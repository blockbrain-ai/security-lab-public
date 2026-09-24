/**
 * Section 11.2 — Probe variant generator.
 *
 * Takes a hypothesis, classifies it into a probe family, and expands
 * it into family-specific probe variants that actually test the theory
 * rather than sending bland generic HTTP requests.
 */

import type { LiveProbeRequest, ExpectedResponse } from '../local-live/contracts.js';
import {
  classifyHypothesis,
  getFamilyDefinition,
  type ProbeFamilyId,
  type ProbeVariant,
  type TargetFamilyCapability,
} from './probe-families.js';

// ---------------------------------------------------------------------------
// Generator input / output
// ---------------------------------------------------------------------------

export interface VariantGenerationRequest {
  findingId: string;
  hypothesis: string;
  /** Base route extracted by the translator. */
  basePath: string;
  /** Base HTTP method. */
  baseMethod: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD';
  /** Available identity IDs from the target's identity ladder. */
  availableIdentities: string[];
  /** Target-declared family capabilities (empty = all defaults). */
  familyCapabilities?: TargetFamilyCapability[];
  /** Base headers already on the probe. */
  baseHeaders?: Record<string, string>;
  /** Base body already on the probe. */
  baseBody?: string;
  /** Max variants to generate. */
  maxVariants?: number;
}

export interface VariantGenerationResult {
  /** The classified family for this hypothesis. */
  family: ProbeFamilyId;
  /** Generated probe variants. */
  probes: LiveProbeRequest[];
  /** Which variant keys were exercised. */
  variantKeysExercised: string[];
}

// ---------------------------------------------------------------------------
// Core generator
// ---------------------------------------------------------------------------

/**
 * Generate family-shaped probe variants for a hypothesis.
 *
 * 1. Classify the hypothesis into a family.
 * 2. Look up the family's default variants.
 * 3. Filter by target capabilities (disabled variants, etc).
 * 4. Expand each variant into a concrete LiveProbeRequest.
 */
export function generateFamilyVariants(request: VariantGenerationRequest): VariantGenerationResult {
  const family = classifyHypothesis(request.hypothesis);
  const definition = getFamilyDefinition(family);

  if (!definition) {
    // Generic family — no special variants to add
    return { family: 'generic', probes: [], variantKeysExercised: [] };
  }

  // Check if the target supports this family
  const capability = resolveCapability(family, request.familyCapabilities);
  const disabledKeys = new Set(capability?.disabledVariants ?? []);

  // Filter variants
  const variants = definition.defaultVariants.filter((v) => !disabledKeys.has(v.key));
  const maxVariants = request.maxVariants ?? 8;
  const selected = variants.slice(0, maxVariants);

  // Expand into probes
  const probes = selected.map((variant) =>
    expandVariant(variant, request, family, capability),
  );

  // Filter identity variants to only available identities
  const filteredProbes = probes.filter((probe) =>
    request.availableIdentities.includes(probe.identityId),
  );

  // For non-identity families, all probes pass through
  const finalProbes = filteredProbes.length > 0 ? filteredProbes : probes.filter((p) => {
    // Keep probes that don't require a specific identity override
    const variant = selected.find((v) => v.key === p.probeVariant);
    return variant?.axis !== 'identity';
  });

  return {
    family,
    probes: finalProbes.slice(0, maxVariants),
    variantKeysExercised: finalProbes.map((p) => p.probeVariant ?? 'unknown'),
  };
}

// ---------------------------------------------------------------------------
// Variant expansion
// ---------------------------------------------------------------------------

function expandVariant(
  variant: ProbeVariant,
  request: VariantGenerationRequest,
  family: ProbeFamilyId,
  capability?: TargetFamilyCapability,
): LiveProbeRequest {
  const method = variant.methodOverride ?? request.baseMethod;
  const path = variant.pathOverride ?? request.basePath;

  // Merge headers: base → family extra → variant
  const headers: Record<string, string> = {
    ...(request.baseHeaders ?? {}),
    ...(capability?.extraHeaders ?? {}),
    ...(variant.headers ?? {}),
  };

  // Body: variant override wins, then falls back to merging into base
  const body = resolveBody(variant, request);

  // Identity: variant override wins, then pick best available
  const identityId = resolveIdentity(variant, request);

  // Expectations depend on family and variant
  const expectations = inferFamilyExpectations(family, variant, method);

  return {
    findingId: request.findingId,
    hypothesis: request.hypothesis,
    probeKind: 'http',
    identityId,
    rationale: `${family} family: ${variant.label}`,
    probeFamily: family,
    probeVariant: variant.key,
    http: {
      method,
      path,
      headers: Object.keys(headers).length > 0 ? headers : undefined,
      body: body || undefined,
    },
    expectedWhenSafe: expectations.safe,
    expectedWhenExploitable: expectations.exploitable,
  };
}

function resolveBody(variant: ProbeVariant, request: VariantGenerationRequest): string | undefined {
  if (variant.bodyOverride) {
    // For SSRF and mutation_guard, merge the variant payload into base body
    if (request.baseBody && (variant.axis === 'destination' || variant.axis === 'body')) {
      try {
        const base = JSON.parse(request.baseBody) as Record<string, unknown>;
        const override = JSON.parse(variant.bodyOverride) as Record<string, unknown>;
        return JSON.stringify({ ...base, ...override });
      } catch {
        return variant.bodyOverride;
      }
    }
    return variant.bodyOverride;
  }
  return request.baseBody;
}

function resolveIdentity(variant: ProbeVariant, request: VariantGenerationRequest): string {
  if (variant.identityOverride) {
    // Map identity variant keys to available identities
    const override = variant.identityOverride;
    // Direct match
    if (request.availableIdentities.includes(override)) {
      return override;
    }
    // Fuzzy match: 'user_a' → 'user_a_low', 'user_a_canary', etc.
    const fuzzy = request.availableIdentities.find((id) => id.startsWith(override));
    if (fuzzy) return fuzzy;
    // Role-based match for admin
    if (override === 'admin') {
      const adminMatch = request.availableIdentities.find((id) =>
        /admin/i.test(id),
      );
      if (adminMatch) return adminMatch;
    }
    // Guest fallback
    if (override === 'guest') {
      const guestMatch = request.availableIdentities.find((id) =>
        /guest|anonymous|anon/i.test(id),
      );
      if (guestMatch) return guestMatch;
    }
    // Fall through to the override even if not in available — the
    // caller filters by availability
    return override;
  }
  return request.availableIdentities[0] ?? 'guest';
}

// ---------------------------------------------------------------------------
// Family-specific expectations
// ---------------------------------------------------------------------------

function inferFamilyExpectations(
  family: ProbeFamilyId,
  variant: ProbeVariant,
  method: string,
): { safe: ExpectedResponse; exploitable: ExpectedResponse } {
  switch (family) {
    case 'header_trust':
      return {
        safe: {
          // Safe: server ignores the injected header
          statusIn: [200, 301, 302, 400, 403],
          bodyNotContains: ['evil.example.com'],
        },
        exploitable: {
          // Exploitable: server reflects or trusts the header
          statusIn: [200, 301, 302],
          bodyContains: ['evil.example.com'],
        },
      };

    case 'identity_differential':
      if (variant.key === 'guest') {
        return {
          safe: { statusIn: [401, 403] },
          exploitable: { statusIn: [200, 201, 204] },
        };
      }
      if (variant.key === 'admin') {
        return {
          safe: { statusIn: [200, 201, 204] },
          exploitable: { statusIn: [200, 201, 204] },
        };
      }
      // Cross-tenant user_b accessing user_a's resources
      return {
        safe: { statusIn: [401, 403, 404] },
        exploitable: { statusIn: [200, 201, 204] },
      };

    case 'ssrf': {
      const isMeta = variant.key === 'metadata_canary';
      return {
        safe: {
          statusIn: [400, 403, 422],
          bodyNotContains: isMeta ? ['ami-id', 'instance-id'] : undefined,
        },
        exploitable: {
          statusIn: [200],
          bodyContains: isMeta ? ['ami-id'] : undefined,
        },
      };
    }

    case 'websocket_origin':
      return {
        safe: {
          statusIn: [400, 403, 426],
        },
        exploitable: {
          statusIn: [101, 200],
        },
      };

    case 'bootstrap_token_flow':
      if (variant.key === 'valid_token') {
        return {
          safe: { statusIn: [200, 201] },
          exploitable: { statusIn: [200, 201] },
        };
      }
      // Expired or tampered tokens should be rejected
      return {
        safe: { statusIn: [400, 401, 403, 404, 410, 422] },
        exploitable: { statusIn: [200, 201] },
      };

    case 'mutation_guard': {
      const isMutation = method !== 'GET' && method !== 'HEAD';
      return {
        safe: {
          statusIn: isMutation ? [400, 403, 422] : [200],
          bodyNotContains: ['admin', 'approved'],
        },
        exploitable: {
          statusIn: [200, 201, 204],
          bodyContains: variant.key === 'inject_role' ? ['admin'] : undefined,
        },
      };
    }

    default:
      return {
        safe: { statusIn: [200, 401, 403, 404] },
        exploitable: { statusIn: [200] },
      };
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function resolveCapability(
  family: ProbeFamilyId,
  capabilities?: TargetFamilyCapability[],
): TargetFamilyCapability | undefined {
  if (!capabilities) return undefined;
  return capabilities.find((c) => c.family === family);
}
