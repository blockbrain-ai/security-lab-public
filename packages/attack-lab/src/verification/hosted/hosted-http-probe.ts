/**
 * Hosted HTTP probe — wraps fetch with auth injection, audit trail
 * recording, policy authorization, auto-stop monitoring and rate limiting.
 *
 * Everything that produces a live request to a hosted target goes through this
 * function, so it is also where the policy gate lives: a caller cannot reach
 * the network without an authorizing decision, whatever lane invoked it.
 */

import type {
  HostedExecutionResult,
  HostedProbeRequest,
  HostedTargetMeta,
} from './contracts.js';
import type { AuthManager } from './auth-manager.js';
import type { HostedIdentityMatrix } from './hosted-identity-matrix.js';
import type { AuditTrail } from './audit-trail.js';
import type { AutoStopMonitor } from './auto-stop.js';
import { RateLimiter } from '../local-live/rate-limiter.js';
import { redactBody, redactHeaders } from '../shared/redaction.js';
import { deriveHostedVerdict } from './hosted-verdict.js';
import type { SecurityRuntime } from '../../../../security-runtime/src/runtime.js';
import type { RuntimeTargetContext } from '../../../../security-runtime/src/contracts.js';

// ---------------------------------------------------------------------------
// Hosted probe options
// ---------------------------------------------------------------------------

export interface HostedProbeOptions {
  campaignId: string;
  authorizationToken: string;
  target: HostedTargetMeta;
  authManager: AuthManager;
  identityMatrix: HostedIdentityMatrix;
  auditTrail: AuditTrail;
  autoStop: AutoStopMonitor;
  rateLimiter: RateLimiter;
  fetchFn?: typeof fetch;
  /**
   * Policy runtime. When supplied, every hosted request is authorized here
   * before it is sent, including ingress/pre-flight checks.
   */
  runtime?: SecurityRuntime;
  /** Target context handed to the policy runtime. */
  runtimeTargetContext?: RuntimeTargetContext;
  /** Maximum body bytes retained in evidence (default 8000). */
  maxBodyBytes?: number;
}

// ---------------------------------------------------------------------------
// Execute one hosted probe
// ---------------------------------------------------------------------------

export async function executeHostedProbe(
  probe: HostedProbeRequest,
  options: HostedProbeOptions,
): Promise<HostedExecutionResult> {
  const fetchFn = options.fetchFn ?? fetch;
  const probeId = `hosted-${probe.findingId}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const maxBodyBytes = options.maxBodyBytes ?? 8_000;

  // Policy gate — before anything else, so no caller and no ingress check can
  // bypass the runtime's environment tiers, timeout caps or kill switch.
  if (options.runtime) {
    if (!options.runtimeTargetContext) {
      // The tier is a safety contract; never guess it.
      return rejected(
        probe,
        probeId,
        'not_authorized',
        'hosted probe refused: a policy runtime was supplied without a target context (environment tier unknown)',
      );
    }
    const decision = options.runtime.authorizeProbe('declared', options.runtimeTargetContext, {
      kind: probe.http.body ? 'prompt_injection' : 'http_request',
      timeoutMs: 20_000,
      method: probe.http.method,
      body: probe.http.body,
    });
    if (!decision.allowed) {
      return rejected(probe, probeId, 'not_authorized', `policy blocked: ${decision.reason ?? 'blocked'}`);
    }
  }

  // Pre-flight auto-stop check
  const preIncident = options.autoStop.preflight();
  if (preIncident) {
    return rejected(probe, probeId, 'auto_stopped', `auto-stop pre-flight: ${preIncident.detail}`);
  }

  // Mutation must be opted in
  const isMutation = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(probe.http.method);
  if (isMutation && !probe.mutationAllowed) {
    return rejected(
      probe,
      probeId,
      'not_authorized',
      'Mutation probe attempted without --allow-hosted-mutations',
    );
  }

  // Resolve identity
  const identity = options.identityMatrix.get(probe.identityId);
  if (!identity) {
    return rejected(probe, probeId, 'auth_failed', `Unknown hosted identity "${probe.identityId}"`);
  }
  let credentials;
  try {
    credentials = await options.authManager.resolve(identity.authSourceRef);
  } catch (error) {
    return rejected(
      probe,
      probeId,
      'auth_failed',
      error instanceof Error ? error.message : String(error),
    );
  }
  if (!credentials) {
    return rejected(
      probe,
      probeId,
      'auth_failed',
      `Auth source "${identity.authSourceRef}" returned no credentials`,
    );
  }

  // Acquire rate limiter slot
  try {
    await options.rateLimiter.acquire();
  } catch (error) {
    return rejected(
      probe,
      probeId,
      'rate_limited',
      error instanceof Error ? error.message : String(error),
    );
  }

  const url = new URL(probe.http.path, options.target.baseUrl).toString();
  const headers: Record<string, string> = {
    ...credentials.headers,
    ...probe.http.headers,
  };
  // Redacted copies are what reach disk and the returned result.
  const safeHeaders = redactHeaders(headers);
  const safeRequestBody = probe.http.body === undefined ? undefined : redactBody(probe.http.body, maxBodyBytes).body;
  const start = Date.now();

  // Record the request before it leaves the process: a crash mid-request must
  // still leave evidence of what was sent.
  const startedRef = await options.auditTrail.append({
    phase: 'request_started',
    campaignId: options.campaignId,
    probeId,
    findingId: probe.findingId,
    identityId: probe.identityId,
    at: new Date().toISOString(),
    request: { method: probe.http.method, url, headers: safeHeaders, body: safeRequestBody },
    response: { status: 0, headers: {}, body: '', durationMs: 0 },
    authorizationToken: options.authorizationToken,
    notes: 'request_started',
  });

  try {
    const response = await fetchFn(url, {
      method: probe.http.method,
      headers,
      body: probe.http.body,
      signal: AbortSignal.timeout(20_000),
      redirect: 'manual',
    });

    const responseBody = await response.text();
    const durationMs = Date.now() - start;
    const responseHeaders = Object.fromEntries(response.headers.entries());

    options.rateLimiter.recordResult(response.status, durationMs);
    const incident = options.autoStop.recordResult(response.status, durationMs, responseHeaders);

    const bodyForEvidence = redactBody(responseBody, maxBodyBytes);
    const auditEntryId = await options.auditTrail.append({
      phase: 'request_completed',
      campaignId: options.campaignId,
      probeId,
      findingId: probe.findingId,
      identityId: probe.identityId,
      at: new Date().toISOString(),
      request: { method: probe.http.method, url, headers: safeHeaders, body: safeRequestBody },
      response: {
        status: response.status,
        headers: redactHeaders(responseHeaders),
        body: bodyForEvidence.body,
        durationMs,
      },
      authorizationToken: options.authorizationToken,
      notes: incident
        ? `auto-stop incident: ${incident.reason}`
        : bodyForEvidence.truncated
          ? 'response body truncated in evidence'
          : undefined,
    });

    if (incident) {
      return {
        probeId,
        findingId: probe.findingId,
        identityId: probe.identityId,
        request: { method: probe.http.method, url, headers: safeHeaders, body: safeRequestBody },
        response: {
          status: response.status,
          headers: redactHeaders(responseHeaders),
          body: bodyForEvidence.body,
          durationMs,
        },
        boundary: probe.boundary,
        auditEntryRef: auditEntryId,
        rollbackExecuted: false,
        verdict: 'auto_stopped',
        reasoning: `Auto-stop: ${incident.reason} — ${incident.detail}`,
      };
    }

    const derived = deriveHostedVerdict(probe, {
      status: response.status,
      body: responseBody,
      contentLength: Number(response.headers.get('content-length') ?? Number.NaN),
    });

    return {
      probeId,
      findingId: probe.findingId,
      identityId: probe.identityId,
      request: { method: probe.http.method, url, headers: safeHeaders, body: safeRequestBody },
      response: {
        status: response.status,
        headers: redactHeaders(responseHeaders),
        body: bodyForEvidence.body,
        durationMs,
      },
      boundary: probe.boundary,
      auditEntryRef: auditEntryId,
      rollbackExecuted: false,
      verdict: derived.verdict,
      reasoning: derived.reasoning,
    };
  } catch (error) {
    const durationMs = Date.now() - start;
    const auditEntryId = await options.auditTrail.append({
      phase: 'request_completed',
      campaignId: options.campaignId,
      probeId,
      findingId: probe.findingId,
      identityId: probe.identityId,
      at: new Date().toISOString(),
      request: { method: probe.http.method, url, headers: safeHeaders, body: safeRequestBody },
      response: { status: 0, headers: {}, body: '', durationMs },
      authorizationToken: options.authorizationToken,
      notes: `runtime error after request ${startedRef}: ${error instanceof Error ? error.message : String(error)}`,
    });

    return {
      probeId,
      findingId: probe.findingId,
      identityId: probe.identityId,
      request: { method: probe.http.method, url, headers: safeHeaders, body: safeRequestBody },
      response: { status: 0, headers: {}, body: '', durationMs },
      boundary: probe.boundary,
      auditEntryRef: auditEntryId,
      rollbackExecuted: false,
      verdict: 'runtime_error',
      reasoning: error instanceof Error ? error.message : String(error),
    };
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function rejected(
  probe: HostedProbeRequest,
  probeId: string,
  verdict: HostedExecutionResult['verdict'],
  reasoning: string,
): HostedExecutionResult {
  return {
    probeId,
    findingId: probe.findingId,
    identityId: probe.identityId,
    request: {
      method: probe.http.method,
      url: probe.http.path,
      headers: {},
      body: probe.http.body,
    },
    response: { status: 0, headers: {}, body: '', durationMs: 0 },
    boundary: probe.boundary,
    auditEntryRef: '',
    rollbackExecuted: false,
    verdict,
    reasoning,
  };
}
