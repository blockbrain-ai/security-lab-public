/**
 * Portfolio benchmark — evaluates model-role assignments across
 * threat corpus fixtures and produces role scorecards.
 */

import type { ModelConfig } from '../providers/contracts.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface BenchmarkConfig {
  /** Models to evaluate for each role. */
  plannerCandidates: ModelConfig[];
  judgeCandidates: ModelConfig[];
  synthesizerCandidates: ModelConfig[];
  /** Fixtures to run. */
  fixtureIds: string[];
  /** Maximum cost per fixture run. */
  maxCostPerFixture: number;
  /** Maximum iterations per fixture. */
  maxIterationsPerFixture: number;
}

export interface BenchmarkResult {
  runAt: string;
  config: BenchmarkConfig;
  roleScorecards: RoleScorecard[];
  recommendedPortfolio: RecommendedPortfolio;
}

export interface RoleScorecard {
  role: 'planner' | 'judge' | 'synthesizer';
  provider: string;
  model: string;
  metrics: RoleMetrics;
}

export interface RoleMetrics {
  signalRecall: number;
  chainConfirmationRate: number;
  dormantReactivationContribution: number;
  precision: number;
  falsePositiveRate: number;
  disagreementYield: number;
  synthesisCalibration: number;
  costPerUsefulSignal: number;
  costPerConfirmedChain: number;
  totalCostUsd: number;
  totalInvocations: number;
}

export interface RecommendedPortfolio {
  planner: ModelConfig;
  judge: ModelConfig;
  synthesizer?: ModelConfig;
  counterPlanner?: ModelConfig;
  reasoning: string;
  backedByData: boolean;
}

// ---------------------------------------------------------------------------
// Benchmark runner (stub — requires real model calls to populate)
// ---------------------------------------------------------------------------

export function createBenchmarkConfig(
  options?: Partial<BenchmarkConfig>,
): BenchmarkConfig {
  return {
    plannerCandidates: options?.plannerCandidates ?? [
      { provider: 'anthropic', model: 'claude-sonnet-4-6' },
      { provider: 'openai', model: 'gpt-4o' },
    ],
    judgeCandidates: options?.judgeCandidates ?? [
      { provider: 'anthropic', model: 'claude-sonnet-4-6' },
      { provider: 'openai', model: 'gpt-4o' },
    ],
    synthesizerCandidates: options?.synthesizerCandidates ?? [
      { provider: 'anthropic', model: 'claude-opus-4-6' },
      { provider: 'anthropic', model: 'claude-sonnet-4-6' },
    ],
    fixtureIds: options?.fixtureIds ?? [
      'authz-drift',
      'prompt-smuggle',
      'composition-chain',
      'thread-pull',
    ],
    maxCostPerFixture: options?.maxCostPerFixture ?? 2.0,
    maxIterationsPerFixture: options?.maxIterationsPerFixture ?? 5,
  };
}

/**
 * Placeholder for benchmark execution. Full implementation requires
 * running real campaigns with different model assignments and scoring
 * the results against corpus ground truth.
 */
export function computeRoleScorecard(
  role: 'planner' | 'judge' | 'synthesizer',
  provider: string,
  model: string,
  metrics: Partial<RoleMetrics>,
): RoleScorecard {
  return {
    role,
    provider,
    model,
    metrics: {
      signalRecall: metrics.signalRecall ?? 0,
      chainConfirmationRate: metrics.chainConfirmationRate ?? 0,
      dormantReactivationContribution: metrics.dormantReactivationContribution ?? 0,
      precision: metrics.precision ?? 0,
      falsePositiveRate: metrics.falsePositiveRate ?? 0,
      disagreementYield: metrics.disagreementYield ?? 0,
      synthesisCalibration: metrics.synthesisCalibration ?? 0,
      costPerUsefulSignal: metrics.costPerUsefulSignal ?? 0,
      costPerConfirmedChain: metrics.costPerConfirmedChain ?? 0,
      totalCostUsd: metrics.totalCostUsd ?? 0,
      totalInvocations: metrics.totalInvocations ?? 0,
    },
  };
}

export function recommendPortfolio(scorecards: RoleScorecard[]): RecommendedPortfolio {
  const bestPlanner = scorecards
    .filter((s) => s.role === 'planner')
    .sort((a, b) => b.metrics.signalRecall - a.metrics.signalRecall)[0];

  const bestJudge = scorecards
    .filter((s) => s.role === 'judge')
    .sort((a, b) => b.metrics.precision - a.metrics.precision)[0];

  const bestSynthesizer = scorecards
    .filter((s) => s.role === 'synthesizer')
    .sort((a, b) => b.metrics.synthesisCalibration - a.metrics.synthesisCalibration)[0];

  return {
    planner: bestPlanner
      ? { provider: bestPlanner.provider as 'anthropic' | 'openai' | 'gemini', model: bestPlanner.model }
      : { provider: 'anthropic', model: 'claude-sonnet-4-6' },
    judge: bestJudge
      ? { provider: bestJudge.provider as 'anthropic' | 'openai' | 'gemini', model: bestJudge.model }
      : { provider: 'anthropic', model: 'claude-sonnet-4-6' },
    synthesizer: bestSynthesizer
      ? { provider: bestSynthesizer.provider as 'anthropic' | 'openai' | 'gemini', model: bestSynthesizer.model }
      : undefined,
    reasoning: scorecards.length > 0
      ? `Selected based on ${scorecards.length} role evaluations across corpus fixtures.`
      : 'No benchmark data available — using defaults.',
    backedByData: scorecards.length > 0,
  };
}
