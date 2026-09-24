/**
 * Live replay — orchestrates execution of live probe sequences
 * against a locally-running target with rate limiting, canary
 * matching, and rollback.
 */

import type { LiveProbeRequest, LiveExecutionResult, CanarySpec, ProbeSequenceDefinition, ProbeSequenceResult, IdentityDifferentialConfig, IdentityDifferentialResult } from './contracts.js';
import { matchCanary, type CanaryMatch } from './canary-harness.js';
import { IdentityLadder } from './identity-ladder.js';
import { RateLimiter } from './rate-limiter.js';
import { resolveRequestUrl } from '../shared/url-policy.js';
import { MutationJournal } from './reversible-mutation.js';
import {
  COVERAGE_GAP_EVENT_STAGES,
  ENTITY_INVENTORY_EVENT_STAGES,
  type CoverageGapEventPayload,
  type DryRunProbeEventPayload,
  type ProbeParameterResolutionFailedPayload,
  type ProbeParameterResolutionSucceededPayload,
} from '../../../../evidence-plane/src/events/coverage-gap-events.js';
import type { EntityInventory } from '../probe-intelligence/entity-inventory.js';
import type { SecurityMode } from '../../../../evidence-plane/src/contracts.js';
import {
  hasUnresolvedPlaceholders,
} from '../probe-intelligence/entity-inventory.js';
import { classifyResponse as assertionClassify } from './assertion-classifier.js';
import { executeProbeSequence } from './probe-sequence.js';
import type { SequenceExecutorStats } from './probe-sequence.js';
import { executeIdentityDifferentialProbe, executeIdentityDifferentialSequence } from './identity-differential.js';
import {
  resolveProbeParameters,
  discoverEntitiesFromResponse,
} from '../probe-intelligence/entity-resolution.js';
import { addEntity } from '../probe-intelligence/entity-inventory.js';
import type { SecurityRuntime } from '../../../../security-runtime/src/runtime.js';
import type { RuntimeTargetContext } from '../../../../security-runtime/src/contracts.js';

/**
 * Typed live-replay event emission. Section 3.1 coverage gaps and dry-run
 * probe events go through the closed-enum shapes from evidence-plane so
 * typos in reason codes are caught at compile time.
 */
export type LiveReplayEvent =
  | { stage: typeof COVERAGE_GAP_EVENT_STAGES.COVERAGE_GAP; payload: CoverageGapEventPayload }
  | { stage: typeof COVERAGE_GAP_EVENT_STAGES.DRY_RUN_PROBE; payload: DryRunProbeEventPayload }
  | { stage: typeof ENTITY_INVENTORY_EVENT_STAGES.PROBE_PARAMETER_RESOLUTION_FAILED; payload: ProbeParameterResolutionFailedPayload }
  | { stage: typeof ENTITY_INVENTORY_EVENT_STAGES.PROBE_PARAMETER_RESOLUTION_SUCCEEDED; payload: ProbeParameterResolutionSucceededPayload };

// ---------------------------------------------------------------------------
// Live replay options
// ---------------------------------------------------------------------------

export interface LiveReplayOptions {
  baseUrl: string;
  identityLadder: IdentityLadder;
  rateLimiter: RateLimiter;
  mutationJournal: MutationJournal;
  canaries?: CanarySpec[];
  allowMutations?: boolean;
  /** Force dry-run mode for all mutations regardless of other settings. */
  dryRunMutations?: boolean;
  /** Revert to pre-3.1 hard rejection behavior (strict probes mode). */
  strictProbes?: boolean;
  fetchFn?: typeof fetch;
  /**
   * Optional callback to emit evidence events during probe execution.
   * Reason codes are constrained via {@link LiveReplayEvent} so typos in
   * the closed coverage_gap enum are caught at compile time.
   */
  onEvent?: (stage: LiveReplayEvent['stage'], payload: LiveReplayEvent['payload']) => void;
  /**
   * Section 11.1 — entity inventory for probe parameter resolution.
   * When provided, probes with unresolved critical placeholders are
   * degraded to coverage gaps instead of firing with literal placeholders.
   */
  entityInventory?: EntityInventory;
  /**
   * Policy runtime. When supplied, every HTTP probe executes only after an
   * authorizing decision, so no caller (canaries, worker-requested probes,
   * sequence steps, identity differentials) can reach the network without one.
   */
  runtime?: SecurityRuntime;
  /** Target context handed to the policy runtime. */
  runtimeTargetContext?: RuntimeTargetContext;
  /** Security mode reported to the policy runtime (default `declared`). */
  mode?: SecurityMode;
}

function emitCoverageGap(
  options: LiveReplayOptions,
  payload: CoverageGapEventPayload,
): void {
  options.onEvent?.(COVERAGE_GAP_EVENT_STAGES.COVERAGE_GAP, payload);
}

function emitDryRunProbe(
  options: LiveReplayOptions,
  payload: DryRunProbeEventPayload,
): void {
  options.onEvent?.(COVERAGE_GAP_EVENT_STAGES.DRY_RUN_PROBE, payload);
}

// ---------------------------------------------------------------------------
// Execute a single live probe
// ---------------------------------------------------------------------------

export async function executeLiveProbe(
  probe: LiveProbeRequest,
  options: LiveReplayOptions,
): Promise<LiveExecutionResult> {
  const fetchFn = options.fetchFn ?? fetch;
  const probeId = `live-${probe.findingId}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  let http = sanitizeHttpProbe(probe.http);

  // Policy gate at the choke point — before parameter resolution, rate limiting
  // or any network call.
  if (options.runtime) {
    if (!options.runtimeTargetContext) {
      return {
        probeId,
        findingId: probe.findingId,
        identityId: probe.identityId,
        request: { method: http?.method ?? 'GET', url: http?.path ?? '', headers: {}, body: undefined },
        response: { status: 0, headers: {}, body: '', durationMs: 0 },
        rollbackExecuted: false,
        verdict: 'not_authorized',
        reasoning: 'probe refused: a policy runtime was supplied without a target context (environment tier unknown)',
      };
    }
    const decision = options.runtime.authorizeProbe(options.mode ?? 'declared', options.runtimeTargetContext, {
      kind: http?.body ? 'prompt_injection' : 'http_request',
      timeoutMs: 20_000,
      method: http?.method,
      body: http?.body,
    });
    if (!decision.allowed) {
      const reason = `policy blocked: ${decision.reason ?? 'blocked'}`;
      emitCoverageGap(options, {
        code: 'probe_blocked_by_policy',
        probeId,
        identityId: probe.identityId,
        reason,
        context: { method: http?.method, path: http?.path },
      });
      return {
        probeId,
        findingId: probe.findingId,
        identityId: probe.identityId,
        request: { method: http?.method ?? 'GET', url: http?.path ?? '', headers: {}, body: undefined },
        response: { status: 0, headers: {}, body: '', durationMs: 0 },
        rollbackExecuted: false,
        verdict: 'not_authorized',
        reasoning: reason,
      };
    }
  }

  // Section 11.1 — resolve placeholders from entity inventory
  if (http && options.entityInventory && hasUnresolvedPlaceholders(http.path)) {
    const resolution = resolveProbeParameters(http.path, options.entityInventory, {
      identityId: probe.identityId,
    });

    if (!resolution.allCriticalResolved) {
      const unresolvedNames = resolution.unresolved
        .filter((u) => u.criticality === 'critical')
        .map((u) => u.placeholder);

      // Emit resolution failure event
      options.onEvent?.(ENTITY_INVENTORY_EVENT_STAGES.PROBE_PARAMETER_RESOLUTION_FAILED, {
        probeId,
        originalPath: http.path,
        unresolvedParameters: unresolvedNames,
        hasCriticalUnresolved: true,
      });

      // Emit coverage gap for unresolved parameters
      emitCoverageGap(options, {
        code: 'parameter_unresolved',
        probeId,
        reason: `Critical placeholders unresolved: ${unresolvedNames.join(', ')}`,
        context: { method: http.method, path: http.path, unresolvedParameters: unresolvedNames },
      });

      return {
        probeId,
        findingId: probe.findingId,
        identityId: probe.identityId,
        request: { method: http.method, url: http.path, headers: {}, body: undefined },
        response: { status: 0, headers: {}, body: '', durationMs: 0 },
        rollbackExecuted: false,
        verdict: 'coverage_gap',
        reasoning: `Unresolved critical parameters: ${unresolvedNames.join(', ')} — not counted as meaningful attempt`,
      };
    }

    if (resolution.anyResolved) {
      // Emit resolution success event
      options.onEvent?.(ENTITY_INVENTORY_EVENT_STAGES.PROBE_PARAMETER_RESOLUTION_SUCCEEDED, {
        probeId,
        originalPath: http.path,
        resolvedPath: resolution.resolvedPath,
        resolvedCount: resolution.resolved.length,
      });
      http = { ...http, path: resolution.resolvedPath };
    }
  }

  // Block or degrade mutation probes
  const isMutation = http && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(http.method);
  const shouldDryRun = isMutation && (options.dryRunMutations || !options.allowMutations);
  if (isMutation && !options.allowMutations && options.strictProbes) {
    // Pre-3.1 hard rejection behavior
    return {
      probeId,
      findingId: probe.findingId,
      identityId: probe.identityId,
      request: { method: http?.method ?? 'GET', url: http?.path ?? '', headers: {}, body: undefined },
      response: { status: 0, headers: {}, body: '', durationMs: 0 },
      rollbackExecuted: false,
      verdict: 'not_authorized',
      reasoning: 'Mutation probe attempted without --allow-local-mutations (strict mode)',
    };
  }

  // Build identity headers
  const identityHeaders = options.identityLadder.buildHeaders(probe.identityId);
  if (identityHeaders === null) {
    if (options.strictProbes) {
      // Pre-3.1 hard rejection behavior
      return {
        probeId,
        findingId: probe.findingId,
        identityId: probe.identityId,
        request: { method: http?.method ?? 'GET', url: http?.path ?? '', headers: {}, body: undefined },
        response: { status: 0, headers: {}, body: '', durationMs: 0 },
        rollbackExecuted: false,
        verdict: 'auth_failed',
        reasoning: `Identity "${probe.identityId}" not configured (env vars missing)`,
      };
    }
    // Section 3.1: emit coverage gap event and return coverage_gap verdict
    emitCoverageGap(options, {
      code: 'identity_missing',
      probeId,
      identityId: probe.identityId,
      reason: `Identity "${probe.identityId}" not configured (env vars missing)`,
    });
    return {
      probeId,
      findingId: probe.findingId,
      identityId: probe.identityId,
      request: { method: http?.method ?? 'GET', url: http?.path ?? '', headers: {}, body: undefined },
      response: { status: 0, headers: {}, body: '', durationMs: 0 },
      rollbackExecuted: false,
      verdict: 'coverage_gap',
      reasoning: `Identity "${probe.identityId}" not configured (env vars missing) — recorded as coverage gap`,
    };
  }

  // Section 3.1: dry-run mode for mutations without opt-in
  if (shouldDryRun && http) {
    const url = resolveRequestUrl(http.path, options.baseUrl, { label: 'live probe path' });
    const headers = { ...identityHeaders, ...http.headers };
    // Emit dry-run probe event
    emitDryRunProbe(options, {
      probeId,
      findingId: probe.findingId,
      identityId: probe.identityId,
      method: http.method,
      url,
      headers,
      body: http.body,
      reason: options.dryRunMutations
        ? 'Dry-run forced via --dry-run-mutations'
        : 'Mutation probe without --allow-local-mutations; running in dry-run mode',
    });
    // Emit coverage gap for the mutation
    emitCoverageGap(options, {
      code: 'mutation_rollback_missing',
      probeId,
      identityId: probe.identityId,
      reason: options.dryRunMutations
        ? 'Dry-run forced via --dry-run-mutations'
        : 'Mutation probe without rollback path or --allow-local-mutations',
      context: { method: http.method, url },
    });
    return {
      probeId,
      findingId: probe.findingId,
      identityId: probe.identityId,
      request: { method: http.method, url, headers, body: http.body },
      response: { status: 0, headers: {}, body: '', durationMs: 0 },
      rollbackExecuted: false,
      verdict: 'dry_run_simulated',
      reasoning: options.dryRunMutations
        ? `Dry-run simulation (forced): ${http.method} ${url}`
        : `Dry-run simulation: ${http.method} ${url} — mutation without opt-in`,
    };
  }

  // Acquire rate limiter slot
  try {
    await options.rateLimiter.acquire();
  } catch (error) {
    return {
      probeId,
      findingId: probe.findingId,
      identityId: probe.identityId,
      request: { method: http?.method ?? 'GET', url: http?.path ?? '', headers: {}, body: undefined },
      response: { status: 0, headers: {}, body: '', durationMs: 0 },
      rollbackExecuted: false,
      verdict: 'rate_limited',
      reasoning: error instanceof Error ? error.message : String(error),
    };
  }

  // Execute the HTTP probe
  if (!http) {
    return {
      probeId,
      findingId: probe.findingId,
      identityId: probe.identityId,
      request: { method: 'NONE', url: '', headers: {}, body: undefined },
      response: { status: 0, headers: {}, body: '', durationMs: 0 },
      rollbackExecuted: false,
      verdict: 'not_applicable',
      reasoning: 'Non-HTTP probe kinds not yet supported in live replay',
    };
  }

  const url = resolveRequestUrl(http.path, options.baseUrl, { label: 'live probe path' });
  const headers = { ...identityHeaders, ...http.headers };
  const start = Date.now();

  try {
    const response = await fetchFn(url, {
      method: http.method,
      headers,
      body: http.body,
      signal: AbortSignal.timeout(15_000),
    });

    const responseBody = await response.text();
    const durationMs = Date.now() - start;
    options.rateLimiter.recordResult(response.status, durationMs);

    // Match against canaries
    let canaryMatched: CanaryMatch | undefined;
    if (options.canaries && options.canaries.length > 0) {
      for (const canary of options.canaries) {
        if (canary.path === http.path) {
          canaryMatched = matchCanary(canary, { status: response.status, body: responseBody });
          if (canaryMatched !== 'neither') break;
        }
      }
    }
    if (
      (!canaryMatched || canaryMatched === 'neither')
      && (probe.expectedWhenSafe || probe.expectedWhenExploitable)
    ) {
      canaryMatched = matchCanary(
        {
          id: probeId,
          description: probe.hypothesis,
          method: http.method,
          path: http.path,
          expectedWhenSafe: probe.expectedWhenSafe ?? { statusIn: [401, 403, 404] },
          expectedWhenExploitable: probe.expectedWhenExploitable ?? { status: 200 },
        },
        { status: response.status, body: responseBody },
      );
    }

    // Section 11.3 — assertion-based classification replaces naive verdicting.
    const responseHeaders = Object.fromEntries(response.headers.entries());
    const classification = assertionClassify({
      probe,
      status: response.status,
      headers: responseHeaders,
      body: responseBody,
      path: http.path,
      canaryMatched: canaryMatched ?? undefined,
    });

    const verdict = classification.verdict;

    // Section 11.1 — discover entities from successful responses
    if (options.entityInventory && response.status >= 200 && response.status < 400) {
      const discovered = discoverEntitiesFromResponse(responseBody, `response:${http.path}`);
      for (const entity of discovered) {
        addEntity(options.entityInventory, {
          kind: entity.kind,
          value: entity.value,
          provenance: 'discovered_runtime',
          parameterName: entity.parameterName,
          identityId: probe.identityId,
          discoveredDuring: `live-probe:${probeId}`,
        });
      }
    }

    return {
      probeId,
      findingId: probe.findingId,
      identityId: probe.identityId,
      request: { method: http.method, url, headers, body: http.body },
      response: {
        status: response.status,
        headers: responseHeaders,
        body: responseBody.slice(0, 4000),
        durationMs,
      },
      canaryMatched,
      rollbackExecuted: false,
      verdict,
      reasoning: classification.explanation,
      classification,
    };
  } catch (error) {
    return {
      probeId,
      findingId: probe.findingId,
      identityId: probe.identityId,
      request: { method: http.method, url, headers, body: http.body },
      response: { status: 0, headers: {}, body: '', durationMs: Date.now() - start },
      rollbackExecuted: false,
      verdict: 'runtime_error',
      reasoning: error instanceof Error ? error.message : String(error),
    };
  }
}

// ---------------------------------------------------------------------------
// Execute a batch of live probes
// ---------------------------------------------------------------------------

export async function executeLiveProbeBatch(
  probes: LiveProbeRequest[],
  options: LiveReplayOptions,
): Promise<LiveExecutionResult[]> {
  const results: LiveExecutionResult[] = [];
  for (const probe of probes) {
    if (options.rateLimiter.isStopped()) {
      break;
    }
    const result = await executeLiveProbe(probe, options);
    results.push(result);
  }
  return results;
}

function sanitizeHttpProbe(http: LiveProbeRequest['http']): LiveProbeRequest['http'] {
  if (!http) {
    return http;
  }
  if ((http.method === 'GET' || http.method === 'HEAD') && typeof http.body === 'string') {
    return { ...http, body: undefined };
  }
  return http;
}

// ---------------------------------------------------------------------------
// Section 11.4 — Sequence execution
// ---------------------------------------------------------------------------

/**
 * Execute a multi-step probe sequence. Delegates to the probe-sequence
 * executor while providing the same LiveReplayOptions (rate limiter,
 * identity ladder, mutation journal, etc.).
 */
export async function executeLiveProbeSequence(
  definition: ProbeSequenceDefinition,
  options: LiveReplayOptions,
): Promise<{ result: ProbeSequenceResult; stats: SequenceExecutorStats }> {
  return executeProbeSequence(definition, options);
}

// ---------------------------------------------------------------------------
// Section 11.4 — Identity differential execution
// ---------------------------------------------------------------------------

/**
 * Run a single probe across multiple identities and compare results.
 */
export async function executeLiveIdentityDifferentialProbe(
  baseProbe: LiveProbeRequest,
  config: IdentityDifferentialConfig,
  options: LiveReplayOptions,
): Promise<IdentityDifferentialResult> {
  return executeIdentityDifferentialProbe(baseProbe, config, options);
}

/**
 * Run a sequence across multiple identities and compare results.
 */
export async function executeLiveIdentityDifferentialSequence(
  baseDefinition: ProbeSequenceDefinition,
  config: IdentityDifferentialConfig,
  options: LiveReplayOptions,
): Promise<{ result: IdentityDifferentialResult; sequenceStats: { statePassthroughCount: number; rollbacksExecuted: number } }> {
  return executeIdentityDifferentialSequence(baseDefinition, config, options);
}
