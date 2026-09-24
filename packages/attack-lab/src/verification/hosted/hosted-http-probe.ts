/**
 * Hosted HTTP probe — wraps fetch with auth injection, audit trail
 * recording, auto-stop monitoring, and rate limiting. Every probe
 * is logged before it executes and after it returns.
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
  const start = Date.now();

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

    const auditEntryId = await options.auditTrail.append({
      campaignId: options.campaignId,
      probeId,
      findingId: probe.findingId,
      identityId: probe.identityId,
      at: new Date().toISOString(),
      request: { method: probe.http.method, url, headers, body: probe.http.body },
      response: {
        status: response.status,
        headers: responseHeaders,
        body: responseBody.slice(0, 8_000),
        durationMs,
      },
      authorizationToken: options.authorizationToken,
      notes: incident ? `auto-stop incident: ${incident.reason}` : undefined,
    });

    if (incident) {
      return {
        probeId,
        findingId: probe.findingId,
        identityId: probe.identityId,
        request: { method: probe.http.method, url, headers, body: probe.http.body },
        response: {
          status: response.status,
          headers: responseHeaders,
          body: responseBody.slice(0, 4_000),
          durationMs,
        },
        boundary: probe.boundary,
        auditEntryRef: auditEntryId,
        rollbackExecuted: false,
        verdict: 'auto_stopped',
        reasoning: `Auto-stop: ${incident.reason} — ${incident.detail}`,
      };
    }

    // Rough verdict heuristic — confirmed if a forbidden boundary was crossed
    const verdict =
      probe.boundary && response.status >= 200 && response.status < 300
        ? 'confirmed'
        : response.status >= 200 && response.status < 300
          ? 'inconclusive'
          : 'refuted';

    return {
      probeId,
      findingId: probe.findingId,
      identityId: probe.identityId,
      request: { method: probe.http.method, url, headers, body: probe.http.body },
      response: {
        status: response.status,
        headers: responseHeaders,
        body: responseBody.slice(0, 4_000),
        durationMs,
      },
      boundary: probe.boundary,
      auditEntryRef: auditEntryId,
      rollbackExecuted: false,
      verdict,
      reasoning: probe.boundary
        ? `Boundary "${probe.boundary}" → status ${response.status}`
        : `Status ${response.status}`,
    };
  } catch (error) {
    const durationMs = Date.now() - start;
    const auditEntryId = await options.auditTrail.append({
      campaignId: options.campaignId,
      probeId,
      findingId: probe.findingId,
      identityId: probe.identityId,
      at: new Date().toISOString(),
      request: { method: probe.http.method, url, headers, body: probe.http.body },
      response: { status: 0, headers: {}, body: '', durationMs },
      authorizationToken: options.authorizationToken,
      notes: `runtime error: ${error instanceof Error ? error.message : String(error)}`,
    });

    return {
      probeId,
      findingId: probe.findingId,
      identityId: probe.identityId,
      request: { method: probe.http.method, url, headers, body: probe.http.body },
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
