/**
 * Entity resolution — resolves placeholders in probe paths using the
 * entity inventory. Distinguishes critical from optional parameters
 * and emits structured events for both success and failure.
 *
 * Section 11.1: probes with unresolved critical placeholders must not
 * count as meaningful attempts. This module enforces that contract.
 */

import type {
  EntityInventory,
  EntityEntry,
  EntityKind,
} from './entity-inventory.js';
import {
  extractPlaceholders,
  getEntitiesByParameter,
  getEntitiesByKind,
} from './entity-inventory.js';

// ---------------------------------------------------------------------------
// Parameter criticality
// ---------------------------------------------------------------------------

/**
 * Whether a placeholder is critical (must be resolved) or optional
 * (probe can proceed without it, but resolution is preferred).
 *
 * By default all placeholders are critical. Target profiles or probe
 * metadata can mark specific parameters as optional.
 */
export type ParameterCriticality = 'critical' | 'optional';

// ---------------------------------------------------------------------------
// Resolution result
// ---------------------------------------------------------------------------

export interface ResolvedParameter {
  placeholder: string;
  value: string;
  entityId: string;
  kind: EntityKind;
}

export interface UnresolvedParameter {
  placeholder: string;
  criticality: ParameterCriticality;
}

export interface ResolutionResult {
  /** The resolved path with placeholders replaced. */
  resolvedPath: string;
  /** All parameters that were resolved. */
  resolved: ResolvedParameter[];
  /** Parameters that could not be resolved. */
  unresolved: UnresolvedParameter[];
  /** Whether all critical parameters were resolved. */
  allCriticalResolved: boolean;
  /** Whether any parameter was resolved at all. */
  anyResolved: boolean;
}

// ---------------------------------------------------------------------------
// Well-known placeholder → entity kind mapping
// ---------------------------------------------------------------------------

const PLACEHOLDER_KIND_MAP: Record<string, EntityKind> = {
  ':companyId': 'company_id',
  ':tenantId': 'tenant_id',
  ':userId': 'user_id',
  ':inviteToken': 'invite_token',
  ':claimToken': 'claim_token',
  ':onboardingToken': 'onboarding_token',
  ':apiKey': 'api_key',
  ':apiKeyId': 'api_key',
  ':wsCompanyId': 'websocket_company_id',
  ':sessionId': 'session_id',
  ':resourceId': 'resource_id',
  ':id': 'resource_id',
  ':token': 'claim_token',
};

/**
 * Infer the entity kind from a placeholder name. Falls back to
 * `route_param` for unrecognized names.
 */
export function inferEntityKind(placeholder: string): EntityKind {
  return PLACEHOLDER_KIND_MAP[placeholder] ?? 'route_param';
}

// ---------------------------------------------------------------------------
// Resolution options
// ---------------------------------------------------------------------------

export interface ResolutionOptions {
  /** Placeholders to treat as optional (default: all critical). */
  optionalParameters?: string[];
  /** Preferred identity for scoped lookups. */
  identityId?: string;
}

// ---------------------------------------------------------------------------
// Core resolution function
// ---------------------------------------------------------------------------

/**
 * Resolve all placeholders in a probe path using the entity inventory.
 *
 * Resolution strategy per placeholder:
 * 1. Look up by parameter name (exact match on `parameterName`).
 * 2. Look up by inferred entity kind.
 * 3. If both fail, mark as unresolved.
 *
 * Within each lookup, entries matching the preferred identity are
 * prioritized. The first matching entry wins.
 */
export function resolveProbeParameters(
  path: string,
  inventory: EntityInventory,
  options: ResolutionOptions = {},
): ResolutionResult {
  const placeholders = extractPlaceholders(path);
  const optionalSet = new Set(options.optionalParameters ?? []);

  const resolved: ResolvedParameter[] = [];
  const unresolved: UnresolvedParameter[] = [];
  let resolvedPath = path;

  for (const placeholder of placeholders) {
    const entry = findBestMatch(placeholder, inventory, options.identityId);

    if (entry) {
      resolved.push({
        placeholder,
        value: entry.value,
        entityId: entry.id,
        kind: entry.kind,
      });
      resolvedPath = resolvedPath.replace(placeholder, encodeURIComponent(entry.value));
    } else {
      unresolved.push({
        placeholder,
        criticality: optionalSet.has(placeholder) ? 'optional' : 'critical',
      });
    }
  }

  const allCriticalResolved = unresolved.every((u) => u.criticality === 'optional');

  return {
    resolvedPath,
    resolved,
    unresolved,
    allCriticalResolved,
    anyResolved: resolved.length > 0,
  };
}

/**
 * Find the best matching entity entry for a placeholder.
 */
function findBestMatch(
  placeholder: string,
  inventory: EntityInventory,
  preferredIdentityId?: string,
): EntityEntry | undefined {
  // 1. Match by parameter name
  const byParam = getEntitiesByParameter(inventory, placeholder);
  if (byParam.length > 0) {
    return pickPreferred(byParam, preferredIdentityId);
  }

  // 2. Match by inferred kind
  const kind = inferEntityKind(placeholder);
  const byKind = getEntitiesByKind(inventory, kind);
  if (byKind.length > 0) {
    return pickPreferred(byKind, preferredIdentityId);
  }

  return undefined;
}

function pickPreferred(entries: EntityEntry[], preferredIdentityId?: string): EntityEntry {
  if (preferredIdentityId) {
    const preferred = entries.find((e) => e.identityId === preferredIdentityId);
    if (preferred) return preferred;
  }
  return entries[0]!;
}

// ---------------------------------------------------------------------------
// Batch resolution for probe lists
// ---------------------------------------------------------------------------

export interface ProbeResolutionOutcome {
  probeId: string;
  findingId: string;
  originalPath: string;
  result: ResolutionResult;
  /** Whether this probe should count as a meaningful attempt. */
  meaningful: boolean;
}

/**
 * Resolve parameters for a probe, returning the outcome with
 * meaningful-attempt classification.
 */
export function resolveForProbe(
  probeId: string,
  findingId: string,
  path: string,
  inventory: EntityInventory,
  options: ResolutionOptions = {},
): ProbeResolutionOutcome {
  const result = resolveProbeParameters(path, inventory, options);
  return {
    probeId,
    findingId,
    originalPath: path,
    result,
    meaningful: result.allCriticalResolved,
  };
}

// ---------------------------------------------------------------------------
// Runtime discovery helper
// ---------------------------------------------------------------------------

/**
 * Scan an HTTP response body for values that look like entity identifiers.
 * Returns candidate entries to add to the inventory.
 *
 * This is intentionally conservative — it looks for well-known JSON
 * field names in response bodies rather than guessing at random strings.
 */
export interface DiscoveredEntity {
  kind: EntityKind;
  value: string;
  parameterName: string;
  source: string;
}

const DISCOVERY_FIELD_MAP: Record<string, { kind: EntityKind; param: string }> = {
  companyId: { kind: 'company_id', param: ':companyId' },
  company_id: { kind: 'company_id', param: ':companyId' },
  tenantId: { kind: 'tenant_id', param: ':tenantId' },
  tenant_id: { kind: 'tenant_id', param: ':tenantId' },
  userId: { kind: 'user_id', param: ':userId' },
  user_id: { kind: 'user_id', param: ':userId' },
  id: { kind: 'resource_id', param: ':id' },
  inviteToken: { kind: 'invite_token', param: ':inviteToken' },
  invite_token: { kind: 'invite_token', param: ':inviteToken' },
  token: { kind: 'claim_token', param: ':token' },
  apiKey: { kind: 'api_key', param: ':apiKey' },
  api_key: { kind: 'api_key', param: ':apiKey' },
  sessionId: { kind: 'session_id', param: ':sessionId' },
  session_id: { kind: 'session_id', param: ':sessionId' },
};

/**
 * Extract entity candidates from a JSON response body string.
 * Returns an empty array if the body is not valid JSON.
 */
export function discoverEntitiesFromResponse(
  body: string,
  source: string,
): DiscoveredEntity[] {
  const discovered: DiscoveredEntity[] = [];

  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return discovered;
  }

  if (typeof parsed !== 'object' || parsed === null) {
    return discovered;
  }

  walkObject(parsed as Record<string, unknown>, discovered, source);
  return discovered;
}

function walkObject(
  obj: Record<string, unknown>,
  discovered: DiscoveredEntity[],
  source: string,
  depth = 0,
): void {
  if (depth > 5) return; // prevent runaway recursion

  for (const [key, value] of Object.entries(obj)) {
    const mapping = DISCOVERY_FIELD_MAP[key];
    if (mapping && typeof value === 'string' && value.length > 0 && value.length < 256) {
      discovered.push({
        kind: mapping.kind,
        value,
        parameterName: mapping.param,
        source,
      });
    }
    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      walkObject(value as Record<string, unknown>, discovered, source, depth + 1);
    }
    if (Array.isArray(value)) {
      for (const item of value.slice(0, 10)) {
        if (typeof item === 'object' && item !== null) {
          walkObject(item as Record<string, unknown>, discovered, source, depth + 1);
        }
      }
    }
  }
}
