/**
 * Assertion-based classifier (Section 11.3) — replaces naive live
 * verdicting where `200 OK === confirmed`. Considers route kind,
 * content type, body shape, negative controls, and identity
 * differentials before elevating a probe to confirmed.
 *
 * Key design rules:
 * - SPA HTML shells never confirm an API exploit.
 * - Empty JSON collections (`[]`, `{}`) never confirm exfiltration.
 * - Redirects and static assets never confirm anything.
 * - Explicit 401/403 with expected guard messages classify as refuted.
 * - Identity differentials compare same-request across identities.
 */

import type {
  AssertionClassification,
  RouteKind,
  LiveProbeRequest,
} from './contracts.js';
import type { CanaryMatch } from './canary-harness.js';
import { detectRouteKind, type RouteKindInput } from './route-kind.js';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface ClassifierInput {
  /** The original probe request. */
  probe: LiveProbeRequest;
  /** HTTP response status. */
  status: number;
  /** Response headers (lowercased keys). */
  headers: Record<string, string>;
  /** Response body (may be truncated). */
  body: string;
  /** Request path used. */
  path: string;
  /** Canary match result from the existing canary harness. */
  canaryMatched: CanaryMatch | undefined;
  /** Optional: response from the same request under a different identity. */
  identityDifferential?: {
    /** Identity that produced the baseline response. */
    baselineIdentityId: string;
    /** Body of the baseline response. */
    baselineBody: string;
    /** Status of the baseline response. */
    baselineStatus: number;
  };
}

/**
 * Run assertion-based classification on a live probe response.
 * Returns a structured classification with verdict, reason, and
 * whether the attempt counts as meaningful.
 */
export function classifyResponse(input: ClassifierInput): AssertionClassification {
  const routeKindInput: RouteKindInput = {
    path: input.path,
    status: input.status,
    headers: input.headers,
    body: input.body,
  };
  const routeKind = detectRouteKind(routeKindInput);

  // ── Step 1: Route-kind suppression ─────────────────────────────────
  // Certain route kinds can never confirm an API exploit.
  const suppression = checkRouteKindSuppression(routeKind, input);
  if (suppression) return suppression;

  // ── Step 2: Explicit refutation ────────────────────────────────────
  // Strong negative responses (401/403 with guard messages) refute.
  const refutation = checkExplicitRefutation(input, routeKind);
  if (refutation) return refutation;

  // ── Step 3: Empty-collection suppression ───────────────────────────
  // `[]` or `{}` from a JSON API does not confirm exfiltration.
  const emptySuppression = checkEmptyCollection(input, routeKind);
  if (emptySuppression) return emptySuppression;

  // ── Step 4: Identity differential ──────────────────────────────────
  // If we have a baseline from another identity, compare.
  const differential = checkIdentityDifferential(input, routeKind);
  if (differential) return differential;

  // ── Step 5: Canary / shape match ───────────────────────────────────
  // Fall through to canary-based classification with shape awareness.
  return classifyFromCanary(input, routeKind);
}

// ---------------------------------------------------------------------------
// Classification helpers
// ---------------------------------------------------------------------------

function checkRouteKindSuppression(
  routeKind: RouteKind,
  input: ClassifierInput,
): AssertionClassification | null {
  if (routeKind === 'spa_shell') {
    return {
      verdict: 'inconclusive',
      reason: 'spa_fallback',
      explanation: `SPA shell HTML returned for ${input.path} — not a meaningful API response`,
      routeKind,
      isMeaningfulAttempt: false,
    };
  }

  if (routeKind === 'redirect_bootstrap') {
    return {
      verdict: 'inconclusive',
      reason: 'redirect_not_confirmation',
      explanation: `Redirect (${input.status}) is not exploit confirmation`,
      routeKind,
      isMeaningfulAttempt: false,
    };
  }

  if (routeKind === 'asset_static') {
    return {
      verdict: 'inconclusive',
      reason: 'static_asset_not_confirmation',
      explanation: `Static asset response for ${input.path} — not a meaningful API response`,
      routeKind,
      isMeaningfulAttempt: false,
    };
  }

  if (routeKind === 'websocket_upgrade') {
    return {
      verdict: 'inconclusive',
      reason: 'websocket_upgrade_not_confirmation',
      explanation: 'WebSocket upgrade (101) is not exploit confirmation',
      routeKind,
      isMeaningfulAttempt: false,
    };
  }

  return null;
}

const GUARD_MESSAGES = [
  'unauthorized',
  'forbidden',
  'access denied',
  'not allowed',
  'permission denied',
  'authentication required',
  'login required',
  'invalid token',
  'token expired',
  'insufficient permissions',
  'requires authentication',
];

function checkExplicitRefutation(
  input: ClassifierInput,
  routeKind: RouteKind,
): AssertionClassification | null {
  if (input.status !== 401 && input.status !== 403) return null;

  const bodyLower = input.body.toLowerCase();
  const hasGuardMessage = GUARD_MESSAGES.some((msg) => bodyLower.includes(msg));

  if (hasGuardMessage) {
    return {
      verdict: 'refuted',
      reason: 'explicit_refutation',
      explanation: `${input.status} with guard message — access hypothesis refuted`,
      routeKind,
      isMeaningfulAttempt: true,
    };
  }

  // 401/403 without a guard message is still a strong refutation signal
  return {
    verdict: 'refuted',
    reason: 'explicit_refutation',
    explanation: `${input.status} response — access hypothesis refuted`,
    routeKind,
    isMeaningfulAttempt: true,
  };
}

function checkEmptyCollection(
  input: ClassifierInput,
  routeKind: RouteKind,
): AssertionClassification | null {
  if (routeKind !== 'json_api') return null;

  const trimmed = input.body.trim();
  if (trimmed === '[]' || trimmed === '{}' || trimmed === '{"data":[]}' || trimmed === '{"results":[]}') {
    return {
      verdict: 'inconclusive',
      reason: 'empty_authorized_state',
      explanation: 'Empty collection response — does not confirm exfiltration',
      routeKind,
      isMeaningfulAttempt: false,
    };
  }

  // Also catch JSON arrays/objects that are semantically empty
  if (isEmptyJsonResponse(trimmed)) {
    return {
      verdict: 'inconclusive',
      reason: 'empty_authorized_state',
      explanation: 'Empty or near-empty JSON response — does not confirm exfiltration',
      routeKind,
      isMeaningfulAttempt: false,
    };
  }

  return null;
}

function isEmptyJsonResponse(body: string): boolean {
  try {
    const parsed = JSON.parse(body);
    if (Array.isArray(parsed) && parsed.length === 0) return true;
    if (typeof parsed === 'object' && parsed !== null) {
      const values = Object.values(parsed);
      // Object where all array values are empty
      if (values.length > 0 && values.every((v) => Array.isArray(v) && v.length === 0)) return true;
      // Completely empty object
      if (values.length === 0) return true;
    }
  } catch {
    // Not valid JSON — not an empty collection
  }
  return false;
}

function checkIdentityDifferential(
  input: ClassifierInput,
  routeKind: RouteKind,
): AssertionClassification | null {
  if (!input.identityDifferential) return null;

  const { baselineBody, baselineStatus } = input.identityDifferential;

  // If both responses are identical (same status, same body), no differential
  if (input.status === baselineStatus && input.body === baselineBody) {
    return {
      verdict: 'inconclusive',
      reason: 'identity_differential_no_change',
      explanation: 'Response identical across identities — no privilege differential detected',
      routeKind,
      isMeaningfulAttempt: true,
    };
  }

  // If the probe response has data the baseline didn't, that's a shape match
  if (
    input.status >= 200 && input.status < 300
    && (baselineStatus === 401 || baselineStatus === 403 || baselineStatus === 404)
  ) {
    return {
      verdict: 'confirmed',
      reason: 'identity_differential_match',
      explanation: `Identity differential: probe got ${input.status} vs baseline ${baselineStatus} — privilege escalation detected`,
      routeKind,
      isMeaningfulAttempt: true,
    };
  }

  return null;
}

function classifyFromCanary(
  input: ClassifierInput,
  routeKind: RouteKind,
): AssertionClassification {
  if (input.canaryMatched === 'exploitable') {
    // Even with a canary match, apply body-shape validation for JSON APIs
    if (routeKind === 'json_api' && !hasSubstantiveContent(input.body)) {
      return {
        verdict: 'inconclusive',
        reason: 'response_shape_mismatch',
        explanation: 'Canary matched exploitable but response body lacks substantive content',
        routeKind,
        isMeaningfulAttempt: true,
      };
    }

    return {
      verdict: 'confirmed',
      reason: 'response_shape_match',
      explanation: 'Canary matched exploitable pattern with substantive response content',
      routeKind,
      isMeaningfulAttempt: true,
    };
  }

  if (input.canaryMatched === 'safe') {
    return {
      verdict: 'refuted',
      reason: 'canary_match',
      explanation: 'Canary matched safe pattern',
      routeKind,
      isMeaningfulAttempt: true,
    };
  }

  // No canary match — inconclusive
  return {
    verdict: 'inconclusive',
    reason: 'response_shape_mismatch',
    explanation: `No canary or expectation match. Status ${input.status}, route kind ${routeKind}.`,
    routeKind,
    isMeaningfulAttempt: true,
  };
}

/**
 * Check whether a JSON response body has substantive content beyond
 * empty containers or trivial metadata.
 */
function hasSubstantiveContent(body: string): boolean {
  const trimmed = body.trim();
  if (trimmed === '' || trimmed === '[]' || trimmed === '{}') return false;

  try {
    const parsed = JSON.parse(trimmed);
    if (Array.isArray(parsed)) return parsed.length > 0;
    if (typeof parsed === 'object' && parsed !== null) {
      const values = Object.values(parsed);
      if (values.length === 0) return false;
      // Check if all values are empty arrays
      if (values.every((v) => Array.isArray(v) && v.length === 0)) return false;
      return true;
    }
  } catch {
    // Non-JSON with content is substantive
  }
  return trimmed.length > 2;
}
