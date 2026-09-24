/**
 * Section 11.5 — Lead ranking.
 *
 * Ranks hypotheses from the static investigation stage to identify the
 * highest-value candidates for focused confirmation sessions. Ranking
 * uses generic heuristics (severity, confidence, confirmability, novelty,
 * boundary-crossing potential) and is not hardcoded to any specific target.
 */

import type { ChainHypothesis, WeakSignal } from '../../autonomous/contracts.js';
import type { ProbeFamilyId } from '../probe-intelligence/probe-families.js';
import { classifyHypothesis } from '../probe-intelligence/probe-families.js';

// ---------------------------------------------------------------------------
// Ranking factors
// ---------------------------------------------------------------------------

export interface LeadRankingFactors {
  /** Severity score: critical=4, high=3, medium=2, low=1. */
  severity: number;
  /** Average confidence of composing signals (0-1). */
  confidence: number;
  /** How confirmable the hypothesis is (has concrete probe family, route refs). */
  confirmability: number;
  /** Average novelty of composing signals (0-1). */
  novelty: number;
  /** Whether the hypothesis crosses a trust boundary. */
  boundaryCrossingPotential: number;
}

export interface RankedLead {
  hypothesis: ChainHypothesis;
  factors: LeadRankingFactors;
  score: number;
  probeFamily: ProbeFamilyId;
  rank: number;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export interface LeadRankingConfig {
  /** Maximum number of leads to select for focused confirmation. */
  maxLeads: number;
  /** Minimum composite score to qualify. */
  minScore: number;
  /** Weight multipliers for each factor. */
  weights: {
    severity: number;
    confidence: number;
    confirmability: number;
    novelty: number;
    boundaryCrossing: number;
  };
}

export const DEFAULT_RANKING_CONFIG: LeadRankingConfig = {
  maxLeads: 5,
  minScore: 0.3,
  weights: {
    severity: 0.30,
    confidence: 0.20,
    confirmability: 0.25,
    novelty: 0.10,
    boundaryCrossing: 0.15,
  },
};

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

const SEVERITY_SCORES: Record<string, number> = {
  critical: 1.0,
  high: 0.75,
  medium: 0.5,
  low: 0.25,
};

function scoreSeverity(hypothesis: ChainHypothesis): number {
  return SEVERITY_SCORES[hypothesis.severity] ?? 0.25;
}

function scoreConfidence(
  hypothesis: ChainHypothesis,
  signalIndex: Map<string, WeakSignal>,
): number {
  const signalConfidences = hypothesis.signalIds
    .map((id) => signalIndex.get(id)?.confidence ?? 0)
    .filter((c) => c > 0);
  if (signalConfidences.length === 0) return 0.5;
  return signalConfidences.reduce((a, b) => a + b, 0) / signalConfidences.length;
}

function scoreConfirmability(hypothesis: ChainHypothesis): number {
  let score = 0;
  const family = classifyHypothesis(hypothesis.description);
  // Known probe family boosts confirmability.
  if (family !== 'generic') score += 0.4;
  // Source location refs or related assets increase confirmability.
  if (hypothesis.sourceLocationRefs && hypothesis.sourceLocationRefs.length > 0) score += 0.3;
  if (hypothesis.signalIds.length > 0) score += 0.15;
  // Prior attempts with progress signal confirmability.
  const hasProgress = hypothesis.attempts.some((a) => a.verdict === 'progress' || a.verdict === 'partial');
  if (hasProgress) score += 0.15;
  return Math.min(score, 1.0);
}

function scoreNovelty(
  hypothesis: ChainHypothesis,
  signalIndex: Map<string, WeakSignal>,
): number {
  const novelties = hypothesis.signalIds
    .map((id) => signalIndex.get(id)?.novelty ?? 0)
    .filter((n) => n > 0);
  if (novelties.length === 0) return 0.5;
  return novelties.reduce((a, b) => a + b, 0) / novelties.length;
}

function scoreBoundaryCrossing(hypothesis: ChainHypothesis): number {
  if (hypothesis.boundaryCrossing) return 1.0;
  if (hypothesis.privilegeDelta) return 0.8;
  return 0;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Compute ranking factors for a single hypothesis.
 */
export function computeRankingFactors(
  hypothesis: ChainHypothesis,
  signalIndex: Map<string, WeakSignal>,
): LeadRankingFactors {
  return {
    severity: scoreSeverity(hypothesis),
    confidence: scoreConfidence(hypothesis, signalIndex),
    confirmability: scoreConfirmability(hypothesis),
    novelty: scoreNovelty(hypothesis, signalIndex),
    boundaryCrossingPotential: scoreBoundaryCrossing(hypothesis),
  };
}

/**
 * Compute a composite score from factors and weights.
 */
export function computeCompositeScore(
  factors: LeadRankingFactors,
  weights: LeadRankingConfig['weights'],
): number {
  return (
    factors.severity * weights.severity +
    factors.confidence * weights.confidence +
    factors.confirmability * weights.confirmability +
    factors.novelty * weights.novelty +
    factors.boundaryCrossingPotential * weights.boundaryCrossing
  );
}

/**
 * Rank hypotheses for focused confirmation.
 *
 * Filters to `proposed` or `testing` status, scores each, sorts
 * descending, applies the min-score threshold and max-leads cap.
 */
export function rankLeads(
  hypotheses: readonly ChainHypothesis[],
  signals: readonly WeakSignal[],
  config: LeadRankingConfig = DEFAULT_RANKING_CONFIG,
): RankedLead[] {
  const signalIndex = new Map<string, WeakSignal>();
  for (const s of signals) {
    signalIndex.set(s.id, s);
  }

  const eligible = hypotheses.filter(
    (h) => h.status === 'proposed' || h.status === 'testing' || h.status === 'needs_more_data',
  );

  const scored: RankedLead[] = eligible.map((hypothesis) => {
    const factors = computeRankingFactors(hypothesis, signalIndex);
    const score = computeCompositeScore(factors, config.weights);
    const probeFamily = classifyHypothesis(hypothesis.description);
    return { hypothesis, factors, score, probeFamily, rank: 0 };
  });

  scored.sort((a, b) => b.score - a.score);

  const qualified = scored.filter((r) => r.score >= config.minScore);
  const selected = qualified.slice(0, config.maxLeads);
  for (let i = 0; i < selected.length; i++) {
    selected[i]!.rank = i + 1;
  }

  return selected;
}
