/**
 * Section 11.2 — Probe-family taxonomy.
 *
 * Each family describes the exploit theory a hypothesis is testing and
 * the variant axes that matter for confirming or refuting it.
 * Families are generic — no target-specific knowledge leaks in here.
 */

// ---------------------------------------------------------------------------
// Family identifiers
// ---------------------------------------------------------------------------

/**
 * Closed set of probe families. New families can be added here without
 * touching the rest of the codebase — the variant generator will pick
 * them up via the FAMILY_REGISTRY.
 */
export type ProbeFamilyId =
  | 'header_trust'
  | 'identity_differential'
  | 'ssrf'
  | 'websocket_origin'
  | 'bootstrap_token_flow'
  | 'mutation_guard'
  | 'generic';

// ---------------------------------------------------------------------------
// Variant descriptors
// ---------------------------------------------------------------------------

/** A single variant axis value within a family. */
export interface ProbeVariant {
  /** Machine-readable variant key (e.g. 'x_forwarded_host', 'guest'). */
  key: string;
  /** Human label for reporting. */
  label: string;
  /** What this variant changes on the probe (header injection, identity swap, etc). */
  axis: 'header' | 'identity' | 'destination' | 'upgrade' | 'body' | 'method';
  /** Header overrides this variant applies. */
  headers?: Record<string, string>;
  /** Identity override (replaces the probe's identityId). */
  identityOverride?: string;
  /** Path override or suffix (e.g. SSRF destination). */
  pathOverride?: string;
  /** Body override. */
  bodyOverride?: string;
  /** Method override. */
  methodOverride?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD';
}

// ---------------------------------------------------------------------------
// Family definition
// ---------------------------------------------------------------------------

export interface ProbeFamilyDefinition {
  id: ProbeFamilyId;
  /** Human-readable label. */
  label: string;
  /** Keywords / regex fragments used to classify a hypothesis into this family. */
  hypothesisPatterns: RegExp[];
  /** The default variant set this family produces. */
  defaultVariants: ProbeVariant[];
  /** Probe kind this family targets (most families target 'http'). */
  probeKind: 'http' | 'process' | 'persistence';
}

// ---------------------------------------------------------------------------
// Family registry
// ---------------------------------------------------------------------------

export const FAMILY_REGISTRY: readonly ProbeFamilyDefinition[] = [
  // ---- header_trust ----
  {
    id: 'header_trust',
    label: 'Header Trust',
    hypothesisPatterns: [
      /header[- ]?trust/i,
      /x-forwarded/i,
      /host[- ]?header/i,
      /header[- ]?sourced/i,
      /origin[- ]?header/i,
      /referer[- ]?spoof/i,
      /proxy[- ]?header/i,
      /forwarded[- ]?proto/i,
      /trusted[- ]?proxy/i,
    ],
    defaultVariants: [
      {
        key: 'host_override',
        label: 'Host header override',
        axis: 'header',
        headers: { Host: 'evil.example.com' },
      },
      {
        key: 'x_forwarded_host',
        label: 'X-Forwarded-Host injection',
        axis: 'header',
        headers: { 'X-Forwarded-Host': 'evil.example.com' },
      },
      {
        key: 'x_forwarded_proto',
        label: 'X-Forwarded-Proto downgrade',
        axis: 'header',
        headers: { 'X-Forwarded-Proto': 'http' },
      },
      {
        key: 'origin_spoof',
        label: 'Origin header spoof',
        axis: 'header',
        headers: { Origin: 'https://evil.example.com' },
      },
      {
        key: 'referer_spoof',
        label: 'Referer header spoof',
        axis: 'header',
        headers: { Referer: 'https://evil.example.com/admin' },
      },
    ],
    probeKind: 'http',
  },

  // ---- identity_differential ----
  {
    id: 'identity_differential',
    label: 'Identity Differential',
    hypothesisPatterns: [
      /idor/i,
      /identity[- ]?differential/i,
      /cross[- ]?tenant/i,
      /privilege[- ]?escalation/i,
      /impersonat/i,
      /authorization[- ]?bypass/i,
      /broken[- ]?access[- ]?control/i,
      /tenant[- ]?isolation/i,
      /horizontal[- ]?privilege/i,
      /vertical[- ]?privilege/i,
    ],
    defaultVariants: [
      { key: 'guest', label: 'Guest / anonymous', axis: 'identity', identityOverride: 'guest' },
      { key: 'user_a', label: 'User A (resource owner)', axis: 'identity', identityOverride: 'user_a' },
      { key: 'user_b', label: 'User B (cross-tenant)', axis: 'identity', identityOverride: 'user_b' },
      { key: 'admin', label: 'Admin', axis: 'identity', identityOverride: 'admin' },
    ],
    probeKind: 'http',
  },

  // ---- ssrf ----
  {
    id: 'ssrf',
    label: 'SSRF',
    hypothesisPatterns: [
      /ssrf/i,
      /server[- ]?side[- ]?request/i,
      /url[- ]?fetch/i,
      /open[- ]?redirect.*internal/i,
      /internal[- ]?service[- ]?access/i,
      /metadata[- ]?endpoint/i,
    ],
    defaultVariants: [
      {
        key: 'unreachable',
        label: 'Unreachable external URL',
        axis: 'destination',
        bodyOverride: JSON.stringify({ url: 'https://unreachable.invalid/canary' }),
      },
      {
        key: 'loopback',
        label: 'Loopback (127.0.0.1)',
        axis: 'destination',
        bodyOverride: JSON.stringify({ url: 'http://127.0.0.1/' }),
      },
      {
        key: 'metadata_canary',
        label: 'Cloud metadata canary',
        axis: 'destination',
        bodyOverride: JSON.stringify({ url: 'http://169.254.169.254/latest/meta-data/' }),
      },
      {
        key: 'internal_canary',
        label: 'Internal service canary',
        axis: 'destination',
        bodyOverride: JSON.stringify({ url: 'http://internal.local/health' }),
      },
    ],
    probeKind: 'http',
  },

  // ---- websocket_origin ----
  {
    id: 'websocket_origin',
    label: 'WebSocket Origin',
    hypothesisPatterns: [
      /websocket/i,
      /ws:\/\//i,
      /wss:\/\//i,
      /upgrade.*websocket/i,
      /socket[- ]?hijack/i,
    ],
    defaultVariants: [
      {
        key: 'cookie_upgrade',
        label: 'Cookie-backed upgrade',
        axis: 'upgrade',
        headers: { Upgrade: 'websocket', Connection: 'Upgrade', 'Sec-WebSocket-Version': '13' },
      },
      {
        key: 'origin_variant',
        label: 'Cross-origin upgrade',
        axis: 'upgrade',
        headers: {
          Upgrade: 'websocket',
          Connection: 'Upgrade',
          'Sec-WebSocket-Version': '13',
          Origin: 'https://evil.example.com',
        },
      },
      {
        key: 'cross_company',
        label: 'Cross-company upgrade',
        axis: 'upgrade',
        headers: {
          Upgrade: 'websocket',
          Connection: 'Upgrade',
          'Sec-WebSocket-Version': '13',
          Origin: 'https://competitor.example.com',
        },
        identityOverride: 'user_b',
      },
    ],
    probeKind: 'http',
  },

  // ---- bootstrap_token_flow ----
  {
    id: 'bootstrap_token_flow',
    label: 'Bootstrap Token Flow',
    hypothesisPatterns: [
      /bootstrap[- ]?token/i,
      /invite[- ]?token/i,
      /claim[- ]?token/i,
      /onboarding[- ]?token/i,
      /magic[- ]?link/i,
      /signup[- ]?flow/i,
      /token[- ]?reuse/i,
    ],
    defaultVariants: [
      {
        key: 'valid_token',
        label: 'Valid token from seed data',
        axis: 'body',
      },
      {
        key: 'expired_token',
        label: 'Expired/used token',
        axis: 'body',
        bodyOverride: JSON.stringify({ token: 'expired_canary_token_000' }),
      },
      {
        key: 'tampered_token',
        label: 'Tampered token payload',
        axis: 'body',
        bodyOverride: JSON.stringify({ token: 'tampered_canary_token_AAA' }),
      },
    ],
    probeKind: 'http',
  },

  // ---- mutation_guard ----
  {
    id: 'mutation_guard',
    label: 'Mutation Guard',
    hypothesisPatterns: [
      /mutation[- ]?guard/i,
      /state[- ]?tamper/i,
      /mass[- ]?assign/i,
      /param\w*[- ]?tamper/i,
      /field[- ]?inject/i,
      /unvalidated[- ]?update/i,
      /bulk[- ]?update/i,
      /write[- ]?without[- ]?auth/i,
    ],
    defaultVariants: [
      {
        key: 'inject_role',
        label: 'Inject role field',
        axis: 'body',
        bodyOverride: JSON.stringify({ role: 'admin' }),
      },
      {
        key: 'inject_org',
        label: 'Inject organizationId field',
        axis: 'body',
        bodyOverride: JSON.stringify({ organizationId: 'canary_org_b' }),
      },
      {
        key: 'inject_status',
        label: 'Inject status field',
        axis: 'body',
        bodyOverride: JSON.stringify({ status: 'approved' }),
      },
    ],
    probeKind: 'http',
  },
] as const;

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/**
 * Classify a hypothesis string into a probe family.
 * Returns 'generic' when no family pattern matches.
 */
export function classifyHypothesis(hypothesis: string): ProbeFamilyId {
  for (const family of FAMILY_REGISTRY) {
    for (const pattern of family.hypothesisPatterns) {
      if (pattern.test(hypothesis)) {
        return family.id;
      }
    }
  }
  return 'generic';
}

/**
 * Look up the full family definition by ID. Returns undefined for 'generic'.
 */
export function getFamilyDefinition(familyId: ProbeFamilyId): ProbeFamilyDefinition | undefined {
  if (familyId === 'generic') return undefined;
  return FAMILY_REGISTRY.find((f) => f.id === familyId);
}

// ---------------------------------------------------------------------------
// Target family capabilities
// ---------------------------------------------------------------------------

/**
 * Families a target declares it supports, with optional overrides
 * for canary values or identity mappings.
 */
export interface TargetFamilyCapability {
  family: ProbeFamilyId;
  /** Override default variants with target-specific values. */
  variantOverrides?: Partial<ProbeVariant>[];
  /** Disable specific variant keys for this target. */
  disabledVariants?: string[];
  /** Extra headers the target needs for this family (e.g. tenant header). */
  extraHeaders?: Record<string, string>;
}

/**
 * Resolve families from a target profile's liveProbing config.
 * Targets without explicit config get all families at defaults.
 */
export function resolveTargetFamilies(
  liveProbing?: Record<string, unknown>,
): TargetFamilyCapability[] {
  const raw = liveProbing?.['probeFamilies'];
  if (!Array.isArray(raw)) {
    // Default: all families enabled, no overrides
    return FAMILY_REGISTRY.map((f) => ({ family: f.id }));
  }

  return raw
    .filter((entry): entry is Record<string, unknown> => entry != null && typeof entry === 'object')
    .map((entry) => {
      const family = typeof entry['family'] === 'string' ? entry['family'] as ProbeFamilyId : 'generic';
      const disabledVariants = Array.isArray(entry['disabledVariants'])
        ? entry['disabledVariants'].filter((v): v is string => typeof v === 'string')
        : undefined;
      const extraHeaders = entry['extraHeaders'] != null && typeof entry['extraHeaders'] === 'object'
        ? entry['extraHeaders'] as Record<string, string>
        : undefined;
      return { family, disabledVariants, extraHeaders };
    });
}
