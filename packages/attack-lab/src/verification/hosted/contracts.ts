/**
 * Hosted verification contracts — types for probing a live staging
 * (or other authorized hosted) environment with explicit operator
 * authorization, audit trail, and auto-stop.
 */

import type { VerificationVerdict } from '../shared/contracts.js';

// ---------------------------------------------------------------------------
// Authentication source — how to obtain credentials for hosted probes
// ---------------------------------------------------------------------------

export type AuthSource =
  | { source: 'anonymous' }
  | { source: 'iap_service_account'; serviceAccountPath: string; audience: string }
  | { source: 'iap_user_token'; tokenCommand: string; refreshIntervalSeconds?: number }
  | { source: 'session_cookie'; cookieName: string; cookieValueEnv: string }
  | { source: 'bearer_token'; tokenEnv: string };

// ---------------------------------------------------------------------------
// Hosted identity — who is making this request
// ---------------------------------------------------------------------------

export interface HostedIdentitySpec {
  id: string;
  description: string;
  authSourceRef: string;
  expectedRole?: string;
  expectedScope?: string;
  forbiddenBoundaries?: string[];
  /** Explicit canary marker — must be true for hosted probing. */
  isCanary?: boolean;
  /** Explicit opt-in for hosted lanes. */
  allowInHosted?: boolean;
}

// ---------------------------------------------------------------------------
// Hosted probe request
// ---------------------------------------------------------------------------

export interface HostedProbeRequest {
  findingId: string;
  hypothesis: string;
  identityId: string;
  http: {
    method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD';
    path: string;
    headers?: Record<string, string>;
    body?: string;
  };
  /** Boundary being tested (e.g., "guest -> protected_route"). */
  boundary?: string;
  /** Whether this probe is allowed to mutate hosted state. */
  mutationAllowed?: boolean;
  /**
   * What "exploited" looks like for this probe. A 2xx response is not by
   * itself evidence (catch-all routes, SPA shells and empty collections all
   * answer 2xx), so a probe without an assertion can only be `inconclusive`.
   */
  expect?: {
    /** Status codes that count as confirmation (default: any 2xx). */
    statusIn?: number[];
    /** Marker that must appear in the body. */
    bodyContains?: string;
    /** Marker that must NOT appear in the body (identity differentials). */
    bodyNotContains?: string;
    /** Minimum body size in bytes (e.g. a dump larger than an empty list). */
    minBodyBytes?: number;
  };
}

// ---------------------------------------------------------------------------
// Hosted execution result
// ---------------------------------------------------------------------------

export interface HostedExecutionResult {
  probeId: string;
  findingId: string;
  identityId: string;
  request: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
  };
  response: {
    status: number;
    headers: Record<string, string>;
    body: string;
    durationMs: number;
  };
  boundary?: string;
  auditEntryRef: string;
  rollbackExecuted: boolean;
  verdict: VerificationVerdict;
  reasoning: string;
}

// ---------------------------------------------------------------------------
// Audit entry — append-only record of every hosted probe
// ---------------------------------------------------------------------------

export interface AuditEntry {
  entryId: string;
  /**
   * `request_started` is appended before the request leaves the process and
   * `request_completed` after the response is read, so a crash mid-request
   * still leaves a record of what was sent.
   */
  phase?: 'request_started' | 'request_completed';
  campaignId: string;
  probeId: string;
  findingId: string;
  identityId: string;
  at: string;
  request: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
  };
  response: {
    status: number;
    headers: Record<string, string>;
    body: string;
    durationMs: number;
  };
  authorizationToken: string;
  notes?: string;
}

// ---------------------------------------------------------------------------
// Authorization gate
// ---------------------------------------------------------------------------

export interface AuthorizationContext {
  campaignId: string;
  hostedTargetId: string;
  baseUrl: string;
  authorizeFlagSet: boolean;
  authorizationToken?: string;
  confirmedAt?: string;
}

// ---------------------------------------------------------------------------
// Auto-stop incident
// ---------------------------------------------------------------------------

export interface AutoStopIncident {
  reason:
    | 'first_5xx'
    | 'waf_block'
    | 'iap_redirect'
    | 'latency_spike'
    | 'daily_budget_exceeded'
    | 'rate_limited'
    | 'kill_switch';
  detail: string;
  at: string;
}

// ---------------------------------------------------------------------------
// Hosted target metadata
// ---------------------------------------------------------------------------

export interface HostedTargetMeta {
  id: string;
  baseUrl: string;
  authSources: Map<string, AuthSource>;
  hostedIdentities: HostedIdentitySpec[];
  ingressChecks: Array<{
    description: string;
    method: 'GET' | 'HEAD';
    path: string;
    expectStatusIn: number[];
  }>;
  rateLimit: {
    requestsPerSecond: number;
    requestsPerCampaign: number;
    requestsPerDay: number;
  };
  cooldownSeconds: number;
}
