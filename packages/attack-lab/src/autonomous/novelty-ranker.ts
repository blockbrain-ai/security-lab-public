/**
 * Novelty ranker — scores hypotheses and probes by how different they
 * are from what has already been tried. Prevents duplicate probing.
 */

import type { CampaignMemory, ChainHypothesis } from './contracts.js';

/**
 * Compute a novelty score for a hypothesis (0 = already tried, 1 = completely new).
 */
export function scoreNovelty(
  memory: CampaignMemory,
  hypothesis: ChainHypothesis,
): number {
  let score = 1.0;

  // Penalize if we've tested similar signal combinations before
  for (const existing of memory.hypotheses) {
    if (existing.id === hypothesis.id) continue;
    const overlap = computeSignalOverlap(hypothesis.signalIds, existing.signalIds);
    if (overlap > 0.8) score *= 0.2; // Very similar: heavy penalty
    else if (overlap > 0.5) score *= 0.5; // Partial overlap: moderate penalty
  }

  // Penalize if many probes have been run against the same surfaces
  const surfaces = new Set(
    hypothesis.signalIds
      .map((id) => memory.signals.find((s) => s.id === id)?.surface)
      .filter(Boolean),
  );

  const totalProbesOnSurfaces = memory.signals
    .filter((s) => surfaces.has(s.surface))
    .length;

  if (totalProbesOnSurfaces > 20) score *= 0.7;
  if (totalProbesOnSurfaces > 50) score *= 0.5;

  // Boost if it involves dormant reactivation (novel by definition)
  const involvesDormant = hypothesis.signalIds.some((id) =>
    memory.dormantSignalIds.includes(id),
  );
  if (involvesDormant) score = Math.min(1, score * 1.5);

  return Math.max(0, Math.min(1, score));
}

/**
 * Check if a probe has already been executed (by fingerprint).
 */
export function isDuplicateProbe(memory: CampaignMemory, fingerprint: string): boolean {
  return memory.probeFingerprints.has(fingerprint);
}

/**
 * Record a probe as executed.
 */
export function recordProbe(memory: CampaignMemory, fingerprint: string): void {
  memory.probeFingerprints.add(fingerprint);
}

/**
 * Rank hypotheses by combined novelty and severity.
 */
export function rankHypotheses(
  memory: CampaignMemory,
  hypotheses: ChainHypothesis[],
): ChainHypothesis[] {
  return [...hypotheses]
    .map((h) => ({
      hypothesis: h,
      novelty: scoreNovelty(memory, h),
      severityWeight: severityToWeight(h.severity),
    }))
    .sort((a, b) => {
      const scoreA = a.novelty * a.severityWeight;
      const scoreB = b.novelty * b.severityWeight;
      return scoreB - scoreA;
    })
    .map((item) => item.hypothesis);
}

function computeSignalOverlap(a: string[], b: string[]): number {
  const setA = new Set(a);
  const setB = new Set(b);
  const intersection = [...setA].filter((x) => setB.has(x)).length;
  const union = new Set([...setA, ...setB]).size;
  return union > 0 ? intersection / union : 0;
}

function severityToWeight(severity: string): number {
  switch (severity) {
    case 'critical': return 4;
    case 'high': return 3;
    case 'medium': return 2;
    case 'low': return 1;
    default: return 1;
  }
}
