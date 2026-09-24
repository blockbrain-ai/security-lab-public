/**
 * Chain synthesizer — converts attack graph chain candidates into
 * testable chain hypotheses with severity, prerequisites, and
 * boundary crossing metadata.
 */

import type { ChainHypothesis, CampaignMemory, WeakSignal } from './contracts.js';
import type { ChainCandidate } from './attack-graph.js';

export function synthesizeHypotheses(
  memory: CampaignMemory,
  candidates: ChainCandidate[],
  maxNew: number = 5,
): ChainHypothesis[] {
  const newHypotheses: ChainHypothesis[] = [];
  const existingSignalSets = new Set(
    memory.hypotheses.map((h) => h.signalIds.sort().join(',')),
  );

  for (const candidate of candidates) {
    if (newHypotheses.length >= maxNew) break;

    // Deduplicate: don't create hypothesis for the same signal combination
    const key = candidate.signalIds.sort().join(',');
    if (existingSignalSets.has(key)) continue;

    const signals = candidate.signalIds
      .map((id) => memory.signals.find((s) => s.id === id))
      .filter((s): s is WeakSignal => s !== undefined);

    if (signals.length < 2) continue;

    const severity = computeChainSeverity(signals, candidate);
    const description = buildChainDescription(signals, candidate);
    const prerequisites = signals.flatMap((s) => s.suggestedFollowUps).slice(0, 5);

    const hypothesis: ChainHypothesis = {
      id: `ch-${memory.iteration}-${memory.hypotheses.length + newHypotheses.length + 1}`,
      synthesizedAt: new Date().toISOString(),
      iteration: memory.iteration,
      description,
      severity,
      signalIds: candidate.signalIds,
      prerequisites,
      boundaryCrossing: candidate.crossesBoundary
        ? { from: 'external', to: 'internal', mechanism: 'composition chain' }
        : undefined,
      privilegeDelta: undefined,
      status: 'proposed',
      attempts: [],
      finding: undefined,
    };

    newHypotheses.push(hypothesis);
    existingSignalSets.add(key);
  }

  memory.hypotheses.push(...newHypotheses);
  return newHypotheses;
}

function computeChainSeverity(
  signals: WeakSignal[],
  candidate: ChainCandidate,
): 'low' | 'medium' | 'high' | 'critical' {
  // Boundary-crossing chains with high confidence are critical
  if (candidate.crossesBoundary && candidate.totalWeight > 1.5) return 'critical';
  if (candidate.crossesBoundary) return 'high';

  // Multi-signal chains with dormant reactivation are high
  if (candidate.involvesDormant && signals.length >= 3) return 'high';

  // Default based on signal count and confidence
  const avgConfidence = signals.reduce((sum, s) => sum + s.confidence, 0) / signals.length;
  if (avgConfidence > 0.7 && signals.length >= 3) return 'high';
  if (avgConfidence > 0.5) return 'medium';
  return 'low';
}

function buildChainDescription(signals: WeakSignal[], candidate: ChainCandidate): string {
  const signalDescs = signals.map((s, i) => `${i + 1}. ${s.description}`).join('\n');
  const crossing = candidate.crossesBoundary ? ' crossing a trust boundary' : '';
  const dormant = candidate.involvesDormant ? ' (involves reactivated dormant signals)' : '';

  return `Chain hypothesis composing ${signals.length} signals${crossing}${dormant}:\n${signalDescs}`;
}
