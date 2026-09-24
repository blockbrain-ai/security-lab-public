/**
 * Identity differential executor (Section 11.4) — runs the same probe
 * or sequence across multiple identities and compares results to detect
 * privilege escalation or access-control inconsistencies.
 *
 * Design:
 * - Generic: works with any target, any identity ladder entries.
 * - Bounded: subject to the same rate limiter and mutation policy.
 * - Evidence: emits per-identity results and computed deltas.
 */

import type {
  LiveProbeRequest,
  ProbeSequenceDefinition,
  IdentityDifferentialConfig,
  IdentityDifferentialEntry,
  IdentityDelta,
  IdentityDifferentialResult,
} from './contracts.js';
import type { LiveReplayOptions } from './live-replay.js';
import { executeLiveProbe } from './live-replay.js';
import { executeProbeSequence } from './probe-sequence.js';
import type { VerificationVerdict } from '../shared/contracts.js';

// ---------------------------------------------------------------------------
// Delta computation
// ---------------------------------------------------------------------------

/**
 * Compare two identity results and produce a delta summary.
 */
function computeDelta(
  entryA: IdentityDifferentialEntry,
  entryB: IdentityDifferentialEntry,
): IdentityDelta {
  const statusA = entryA.probeResult?.response.status
    ?? entryA.sequenceResult?.stepResults[entryA.sequenceResult.stepResults.length - 1]?.probeResult.response.status
    ?? 0;
  const statusB = entryB.probeResult?.response.status
    ?? entryB.sequenceResult?.stepResults[entryB.sequenceResult.stepResults.length - 1]?.probeResult.response.status
    ?? 0;

  const bodyA = entryA.probeResult?.response.body
    ?? entryA.sequenceResult?.stepResults[entryA.sequenceResult.stepResults.length - 1]?.probeResult.response.body
    ?? '';
  const bodyB = entryB.probeResult?.response.body
    ?? entryB.sequenceResult?.stepResults[entryB.sequenceResult.stepResults.length - 1]?.probeResult.response.body
    ?? '';

  const verdictA = entryA.probeResult?.verdict ?? entryA.sequenceResult?.verdict ?? 'inconclusive' as VerificationVerdict;
  const verdictB = entryB.probeResult?.verdict ?? entryB.sequenceResult?.verdict ?? 'inconclusive' as VerificationVerdict;

  const statusDelta = statusA !== statusB ? { a: statusA, b: statusB } : null;
  const bodyDiffers = bodyA !== bodyB;

  // Privilege escalation: lower-privilege identity gets access that
  // the higher-privilege baseline was denied, OR a lower-privilege
  // identity sees data identical to a higher-privilege identity when
  // it shouldn't.
  const lowerGotAccess = (
    statusA >= 200 && statusA < 300
    && (statusB === 401 || statusB === 403 || statusB === 404)
  );
  const higherDeniedLowerAllowed = (
    statusB >= 200 && statusB < 300
    && (statusA === 401 || statusA === 403 || statusA === 404)
  );
  const privilegeEscalationDetected = lowerGotAccess || higherDeniedLowerAllowed;

  let explanation: string;
  if (privilegeEscalationDetected) {
    explanation = `Privilege differential: ${entryA.identityId} got ${statusA}, ${entryB.identityId} got ${statusB}`;
  } else if (statusDelta) {
    explanation = `Status differs: ${entryA.identityId}=${statusA} vs ${entryB.identityId}=${statusB}`;
  } else if (bodyDiffers) {
    explanation = `Same status (${statusA}) but response bodies differ`;
  } else {
    explanation = `Identical responses (status ${statusA})`;
  }

  return {
    identityA: entryA.identityId,
    identityB: entryB.identityId,
    statusDelta,
    bodyDiffers,
    verdictA,
    verdictB,
    privilegeEscalationDetected,
    explanation,
  };
}

/**
 * Compute all pairwise deltas from a list of identity entries.
 */
function computeAllDeltas(entries: IdentityDifferentialEntry[]): IdentityDelta[] {
  const deltas: IdentityDelta[] = [];
  for (let i = 0; i < entries.length; i++) {
    for (let j = i + 1; j < entries.length; j++) {
      deltas.push(computeDelta(entries[i], entries[j]));
    }
  }
  return deltas;
}

/**
 * Compute overall differential verdict from deltas.
 */
function computeDifferentialVerdict(
  entries: IdentityDifferentialEntry[],
  deltas: IdentityDelta[],
): { verdict: VerificationVerdict; reasoning: string } {
  if (entries.length === 0) {
    return { verdict: 'inconclusive', reasoning: 'No identity entries to compare' };
  }

  const escalations = deltas.filter((d) => d.privilegeEscalationDetected);
  if (escalations.length > 0) {
    const pairs = escalations.map((d) => `${d.identityA}↔${d.identityB}`).join(', ');
    return {
      verdict: 'confirmed',
      reasoning: `Privilege escalation detected in ${escalations.length} pair(s): ${pairs}`,
    };
  }

  const anyConfirmed = entries.some(
    (e) => (e.probeResult?.verdict ?? e.sequenceResult?.verdict) === 'confirmed',
  );
  if (anyConfirmed) {
    return {
      verdict: 'confirmed',
      reasoning: 'At least one identity produced a confirmed verdict',
    };
  }

  const allRefuted = entries.every(
    (e) => (e.probeResult?.verdict ?? e.sequenceResult?.verdict) === 'refuted',
  );
  if (allRefuted) {
    return { verdict: 'refuted', reasoning: 'All identities refuted the hypothesis' };
  }

  return {
    verdict: 'inconclusive',
    reasoning: 'No privilege escalation detected; mixed or inconclusive results across identities',
  };
}

// ---------------------------------------------------------------------------
// Single-probe differential
// ---------------------------------------------------------------------------

/**
 * Run a single probe across multiple identities and compare.
 */
export async function executeIdentityDifferentialProbe(
  baseProbe: LiveProbeRequest,
  config: IdentityDifferentialConfig,
  options: LiveReplayOptions,
): Promise<IdentityDifferentialResult> {
  const entries: IdentityDifferentialEntry[] = [];

  for (const identityId of config.identityIds) {
    if (options.rateLimiter.isStopped()) break;

    const probe: LiveProbeRequest = { ...baseProbe, identityId };
    const probeResult = await executeLiveProbe(probe, options);
    entries.push({ identityId, probeResult });
  }

  const deltas = computeAllDeltas(entries);
  const { verdict, reasoning } = computeDifferentialVerdict(entries, deltas);

  return {
    findingId: baseProbe.findingId,
    hypothesis: baseProbe.hypothesis,
    entries,
    deltas,
    verdict,
    reasoning,
  };
}

// ---------------------------------------------------------------------------
// Sequence differential
// ---------------------------------------------------------------------------

/**
 * Run a sequence across multiple identities and compare.
 */
export async function executeIdentityDifferentialSequence(
  baseDefinition: ProbeSequenceDefinition,
  config: IdentityDifferentialConfig,
  options: LiveReplayOptions,
): Promise<{ result: IdentityDifferentialResult; sequenceStats: { statePassthroughCount: number; rollbacksExecuted: number } }> {
  const entries: IdentityDifferentialEntry[] = [];
  let totalStatePassthrough = 0;
  let rollbacksExecuted = 0;

  for (const identityId of config.identityIds) {
    if (options.rateLimiter.isStopped()) break;

    // Override the default identity for this run
    const definition: ProbeSequenceDefinition = {
      ...baseDefinition,
      defaultIdentityId: identityId,
      sequenceId: `${baseDefinition.sequenceId}-${identityId}`,
    };

    const { result: sequenceResult, stats } = await executeProbeSequence(definition, options);
    entries.push({ identityId, sequenceResult });
    totalStatePassthrough += stats.statePassthroughCount;
    if (stats.rollbackExecuted) rollbacksExecuted += 1;
  }

  const deltas = computeAllDeltas(entries);
  const { verdict, reasoning } = computeDifferentialVerdict(entries, deltas);

  return {
    result: {
      findingId: baseDefinition.findingId,
      hypothesis: baseDefinition.hypothesis,
      entries,
      deltas,
      verdict,
      reasoning,
    },
    sequenceStats: {
      statePassthroughCount: totalStatePassthrough,
      rollbacksExecuted,
    },
  };
}
