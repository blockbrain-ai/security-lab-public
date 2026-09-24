/**
 * Probe sequence executor (Section 11.4) — runs bounded multi-step
 * probe sequences with output extraction, step-to-step parameter
 * passing, per-step assertions, and sequence-level verdicting.
 *
 * Safety invariants:
 * - Rate limiter checked before every step.
 * - Mutations are subject to the same dry-run / allowMutations policy.
 * - Rollback commands execute after the sequence completes.
 * - Evidence emitted for every step.
 */

import type {
  ProbeSequenceDefinition,
  ProbeSequenceStep,
  ProbeSequenceStepResult,
  ProbeSequenceResult,
  OutputExtractor,
  RollbackCommand,
  LiveProbeRequest,
} from './contracts.js';
import type { LiveReplayOptions } from './live-replay.js';
import { executeLiveProbe } from './live-replay.js';
import type { VerificationVerdict } from '../shared/contracts.js';

// ---------------------------------------------------------------------------
// Output extraction
// ---------------------------------------------------------------------------

/**
 * Extract a named value from a probe response using the given extractor.
 */
export function extractOutput(
  extractor: OutputExtractor,
  responseBody: string,
  responseHeaders: Record<string, string>,
): string | null {
  switch (extractor.kind) {
    case 'jsonPath':
      return extractJsonPath(responseBody, extractor.path);
    case 'regex':
      return extractRegex(responseBody, extractor.pattern);
    case 'header':
      return responseHeaders[extractor.headerName.toLowerCase()] ?? null;
  }
}

function extractJsonPath(body: string, path: string): string | null {
  try {
    let current: unknown = JSON.parse(body);
    for (const segment of path.split('.')) {
      if (current == null || typeof current !== 'object') return null;
      // Support array indexing like "items.0.id"
      const asIndex = Number(segment);
      if (Array.isArray(current) && !Number.isNaN(asIndex)) {
        current = current[asIndex];
      } else {
        current = (current as Record<string, unknown>)[segment];
      }
    }
    if (current == null) return null;
    return typeof current === 'string' ? current : JSON.stringify(current);
  } catch {
    return null;
  }
}

function extractRegex(body: string, pattern: string): string | null {
  try {
    const match = new RegExp(pattern).exec(body);
    if (!match) return null;
    // Prefer named capture group "value", fall back to first capture group
    return match.groups?.['value'] ?? match[1] ?? match[0];
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Step reference resolution
// ---------------------------------------------------------------------------

/**
 * Resolve `{{stepId.outputName}}` placeholders in a string using
 * outputs collected from prior steps.
 */
export function resolveStepReferences(
  template: string,
  collectedOutputs: Map<string, Record<string, string>>,
): { resolved: string; referencesUsed: number } {
  let referencesUsed = 0;
  const resolved = template.replace(/\{\{(\w+)\.(\w+)\}\}/g, (_match, stepId: string, outputName: string) => {
    const stepOutputs = collectedOutputs.get(stepId);
    if (stepOutputs && outputName in stepOutputs) {
      referencesUsed += 1;
      return stepOutputs[outputName];
    }
    return _match; // Leave unresolved if not found
  });
  return { resolved, referencesUsed };
}

/**
 * Apply step-reference resolution to an HTTP spec's path, headers, and body.
 */
function resolveHttpReferences(
  http: ProbeSequenceStep['http'],
  collectedOutputs: Map<string, Record<string, string>>,
): { http: ProbeSequenceStep['http']; referencesUsed: number } {
  let totalRefs = 0;

  const pathResult = resolveStepReferences(http.path, collectedOutputs);
  totalRefs += pathResult.referencesUsed;

  let resolvedHeaders = http.headers;
  if (http.headers) {
    resolvedHeaders = {};
    for (const [key, value] of Object.entries(http.headers)) {
      const headerResult = resolveStepReferences(value, collectedOutputs);
      resolvedHeaders[key] = headerResult.resolved;
      totalRefs += headerResult.referencesUsed;
    }
  }

  let resolvedBody = http.body;
  if (http.body) {
    const bodyResult = resolveStepReferences(http.body, collectedOutputs);
    resolvedBody = bodyResult.resolved;
    totalRefs += bodyResult.referencesUsed;
  }

  return {
    http: {
      method: http.method,
      path: pathResult.resolved,
      headers: resolvedHeaders,
      body: resolvedBody,
    },
    referencesUsed: totalRefs,
  };
}

// ---------------------------------------------------------------------------
// Rollback execution
// ---------------------------------------------------------------------------

async function executeRollback(
  commands: RollbackCommand[],
  options: LiveReplayOptions,
): Promise<{ executed: boolean; result: string }> {
  const fetchFn = options.fetchFn ?? fetch;
  const results: string[] = [];

  for (const cmd of commands) {
    try {
      const url = new URL(cmd.path, options.baseUrl).toString();
      const response = await fetchFn(url, {
        method: cmd.method,
        headers: cmd.headers,
        body: cmd.body,
        signal: AbortSignal.timeout(10_000),
      });
      results.push(`${cmd.method} ${cmd.path} → ${response.status}`);
    } catch (error) {
      results.push(`${cmd.method} ${cmd.path} → ERROR: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  return { executed: true, result: results.join('; ') };
}

// ---------------------------------------------------------------------------
// Sequence-level verdicting
// ---------------------------------------------------------------------------

/**
 * Compute a sequence-level verdict from per-step results.
 *
 * Rules:
 * - If any step has a blocking failure (runtime_error, rate_limited, auth_failed),
 *   the sequence is that verdict.
 * - If the final step confirmed, the sequence is confirmed.
 * - If any step confirmed and no step had a blocking failure, confirmed.
 * - If the final step refuted, the sequence is refuted.
 * - Otherwise inconclusive.
 */
export function computeSequenceVerdict(
  stepResults: ProbeSequenceStepResult[],
): { verdict: VerificationVerdict; reasoning: string } {
  if (stepResults.length === 0) {
    return { verdict: 'inconclusive', reasoning: 'No steps executed' };
  }

  const blockingVerdicts: VerificationVerdict[] = [
    'runtime_error', 'rate_limited', 'auth_failed', 'not_authorized', 'coverage_gap',
  ];

  for (const step of stepResults) {
    if (blockingVerdicts.includes(step.probeResult.verdict)) {
      return {
        verdict: step.probeResult.verdict,
        reasoning: `Step "${step.label}" blocked with ${step.probeResult.verdict}: ${step.probeResult.reasoning}`,
      };
    }
  }

  const finalStep = stepResults[stepResults.length - 1];
  const anyConfirmed = stepResults.some((s) => s.probeResult.verdict === 'confirmed');

  if (finalStep.probeResult.verdict === 'confirmed' || anyConfirmed) {
    const confirmedSteps = stepResults
      .filter((s) => s.probeResult.verdict === 'confirmed')
      .map((s) => s.label);
    return {
      verdict: 'confirmed',
      reasoning: `Sequence confirmed via step(s): ${confirmedSteps.join(', ')}`,
    };
  }

  if (finalStep.probeResult.verdict === 'refuted') {
    return {
      verdict: 'refuted',
      reasoning: `Final step "${finalStep.label}" refuted the hypothesis`,
    };
  }

  return {
    verdict: 'inconclusive',
    reasoning: `Sequence completed but no step produced a definitive verdict`,
  };
}

// ---------------------------------------------------------------------------
// Sequence executor
// ---------------------------------------------------------------------------

export interface SequenceExecutorStats {
  statePassthroughCount: number;
  rollbackExecuted: boolean;
}

/**
 * Execute a multi-step probe sequence with output propagation,
 * per-step evidence, rate limiting, and rollback.
 */
export async function executeProbeSequence(
  definition: ProbeSequenceDefinition,
  options: LiveReplayOptions,
): Promise<{ result: ProbeSequenceResult; stats: SequenceExecutorStats }> {
  const collectedOutputs = new Map<string, Record<string, string>>();
  const stepResults: ProbeSequenceStepResult[] = [];
  let totalDurationMs = 0;
  let statePassthroughCount = 0;

  for (const step of definition.steps) {
    // Check rate limiter before each step
    if (options.rateLimiter.isStopped()) {
      break;
    }

    // Resolve step references in HTTP spec
    const { http: resolvedHttp, referencesUsed } = resolveHttpReferences(
      step.http,
      collectedOutputs,
    );
    statePassthroughCount += referencesUsed;

    // Build a LiveProbeRequest for this step
    const probeRequest: LiveProbeRequest = {
      findingId: definition.findingId,
      hypothesis: `[Sequence ${definition.sequenceId} / Step ${step.stepId}] ${definition.hypothesis}`,
      probeKind: 'http',
      identityId: step.identityId ?? definition.defaultIdentityId,
      probeFamily: definition.probeFamily,
      probeVariant: definition.probeVariant,
      http: resolvedHttp,
      expectedWhenSafe: step.expectedWhenSafe,
      expectedWhenExploitable: step.expectedWhenExploitable,
    };

    // Execute the probe
    const probeResult = await executeLiveProbe(probeRequest, options);
    totalDurationMs += probeResult.response.durationMs;

    // Extract outputs
    const extractedOutputs: Record<string, string> = {};
    if (step.extractOutputs) {
      for (const [name, extractor] of Object.entries(step.extractOutputs)) {
        const value = extractOutput(
          extractor,
          probeResult.response.body,
          probeResult.response.headers,
        );
        if (value !== null) {
          extractedOutputs[name] = value;
        }
      }
    }
    collectedOutputs.set(step.stepId, extractedOutputs);

    stepResults.push({
      stepId: step.stepId,
      label: step.label,
      extractedOutputs,
      probeResult,
    });

    // If a blocking failure occurred, stop the sequence
    const blockingVerdicts: VerificationVerdict[] = [
      'runtime_error', 'rate_limited', 'auth_failed', 'not_authorized',
    ];
    if (blockingVerdicts.includes(probeResult.verdict)) {
      break;
    }
  }

  // Execute rollback if defined
  let rollbackExecuted = false;
  let rollbackResult: string | undefined;
  if (definition.rollback && definition.rollback.length > 0) {
    const rb = await executeRollback(definition.rollback, options);
    rollbackExecuted = rb.executed;
    rollbackResult = rb.result;
  }

  // Compute sequence-level verdict
  const { verdict, reasoning } = computeSequenceVerdict(stepResults);

  return {
    result: {
      sequenceId: definition.sequenceId,
      findingId: definition.findingId,
      hypothesis: definition.hypothesis,
      stepResults,
      verdict,
      reasoning,
      rollbackExecuted,
      rollbackResult,
      totalDurationMs,
    },
    stats: {
      statePassthroughCount,
      rollbackExecuted,
    },
  };
}
