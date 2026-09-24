/**
 * Corpus scorer — compares investigator run outputs against the threat
 * corpus ground truth to measure signal recall, chain confirmation,
 * precision, dormant reactivation, and cost efficiency.
 */

import type {
  AggregateScore,
  CorpusFixture,
  FixtureScore,
  RunScore,
  ScoreComparison,
  ThreatCorpus,
} from './contracts.js';

// ---------------------------------------------------------------------------
// Investigator output shape (what the scorer reads from run evidence)
// ---------------------------------------------------------------------------

export interface InvestigatorOutput {
  runId: string;
  /** Signals the investigator reported. */
  reportedSignals: ReportedSignal[];
  /** Chains the investigator confirmed. */
  confirmedChains: ConfirmedChain[];
  /** Total probes executed. */
  totalProbes: number;
  /** Unique probe fingerprints (for duplicate detection). */
  uniqueProbeFingerprints: Set<string>;
  /** Total cost in USD. */
  costUsd: number;
  /** Run start timestamp (ISO). */
  startedAt: string;
  /** Per-chain confirmation timestamps (ISO). */
  chainConfirmedAt: Record<string, string>;
  /** Signals that were initially dormant and later reactivated. */
  reactivatedSignalIds: string[];
}

export interface ReportedSignal {
  /** Investigator's signal ID (may or may not match ground truth). */
  id: string;
  /** Which corpus fixture this signal maps to (if matched). */
  fixtureId?: string;
  /** Which ground-truth signal ID this matches (if matched). */
  groundTruthId?: string;
  /** Description from the investigator. */
  description: string;
  /** Surface where the investigator found it. */
  surface: string;
}

export interface ConfirmedChain {
  /** Investigator's chain ID. */
  id: string;
  /** Which corpus fixture this chain maps to (if matched). */
  fixtureId?: string;
  /** Which ground-truth chain ID this matches (if matched). */
  groundTruthId?: string;
  /** Signal IDs composing this chain. */
  signalIds: string[];
  /** Description from the investigator. */
  description: string;
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

export function scoreRun(
  corpus: ThreatCorpus,
  output: InvestigatorOutput,
): RunScore {
  const fixtureScores = corpus.fixtures.map((fixture) =>
    scoreFixture(fixture, output),
  );

  const aggregate = computeAggregate(corpus, fixtureScores, output);

  return {
    runId: output.runId,
    scoredAt: new Date().toISOString(),
    fixtureScores,
    aggregate,
  };
}

function scoreFixture(
  fixture: CorpusFixture,
  output: InvestigatorOutput,
): FixtureScore {
  const allGroundTruthSignalIds = new Set(fixture.signals.map((s) => s.id));
  const allGroundTruthChainIds = new Set(fixture.chains.map((c) => c.id));

  const matchedSignals = output.reportedSignals.filter(
    (rs) => rs.fixtureId === fixture.id && rs.groundTruthId && allGroundTruthSignalIds.has(rs.groundTruthId),
  );
  const matchedChains = output.confirmedChains.filter(
    (cc) => cc.fixtureId === fixture.id && cc.groundTruthId && allGroundTruthChainIds.has(cc.groundTruthId),
  );

  const signalsFound = matchedSignals.map((m) => m.groundTruthId!);
  const signalsMissed = fixture.signals
    .filter((s) => !signalsFound.includes(s.id))
    .map((s) => s.id);

  const chainsConfirmed = matchedChains.map((m) => m.groundTruthId!);
  const chainsMissed = fixture.chains
    .filter((c) => !chainsConfirmed.includes(c.id))
    .map((c) => c.id);

  const falsePositives = output.reportedSignals
    .filter(
      (rs) =>
        rs.fixtureId === fixture.id &&
        (!rs.groundTruthId || !allGroundTruthSignalIds.has(rs.groundTruthId)),
    )
    .map((rs) => rs.id);

  const dormantReactivated = output.reactivatedSignalIds.filter((id) =>
    fixture.signals.some((s) => s.id === id && s.dormantByDesign),
  );

  return {
    fixtureId: fixture.id,
    signalsFound,
    signalsMissed,
    chainsConfirmed,
    chainsMissed,
    falsePositives,
    dormantReactivated,
  };
}

function computeAggregate(
  corpus: ThreatCorpus,
  fixtureScores: FixtureScore[],
  output: InvestigatorOutput,
): AggregateScore {
  const totalSignals = corpus.fixtures.reduce((n, f) => n + f.signals.length, 0);
  const totalChains = corpus.fixtures.reduce((n, f) => n + f.chains.length, 0);
  const totalFound = fixtureScores.reduce((n, fs) => n + fs.signalsFound.length, 0);
  const totalChainsConfirmed = fixtureScores.reduce((n, fs) => n + fs.chainsConfirmed.length, 0);
  const totalFalsePositives = fixtureScores.reduce((n, fs) => n + fs.falsePositives.length, 0);
  const totalReported = output.reportedSignals.length;
  const totalDormantReactivated = fixtureScores.reduce(
    (n, fs) => n + fs.dormantReactivated.length,
    0,
  );
  const duplicateProbeCount = output.totalProbes - output.uniqueProbeFingerprints.size;

  const signalRecall = totalSignals > 0 ? totalFound / totalSignals : 0;
  const chainRecall = totalChains > 0 ? totalChainsConfirmed / totalChains : 0;
  const signalPrecision = totalReported > 0 ? totalFound / totalReported : 0;
  const costPerChain =
    totalChainsConfirmed > 0 ? output.costUsd / totalChainsConfirmed : output.costUsd;

  // Time to first chain
  const startMs = new Date(output.startedAt).getTime();
  const chainTimes = Object.values(output.chainConfirmedAt).map(
    (ts) => (new Date(ts).getTime() - startMs) / 1000,
  );
  const timeToFirstChainSeconds =
    chainTimes.length > 0 ? Math.min(...chainTimes) : -1;

  return {
    signalRecall,
    chainRecall,
    signalPrecision,
    falsePositiveCount: totalFalsePositives,
    duplicateProbeCount,
    costUsd: output.costUsd,
    costPerChain,
    timeToFirstChainSeconds,
    dormantReactivationCount: totalDormantReactivated,
  };
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

export function compareRuns(
  baseline: RunScore,
  candidate: RunScore,
): ScoreComparison {
  const deltas = {
    signalRecall: candidate.aggregate.signalRecall - baseline.aggregate.signalRecall,
    chainRecall: candidate.aggregate.chainRecall - baseline.aggregate.chainRecall,
    signalPrecision:
      candidate.aggregate.signalPrecision - baseline.aggregate.signalPrecision,
    falsePositiveCount:
      baseline.aggregate.falsePositiveCount - candidate.aggregate.falsePositiveCount,
    costPerChain:
      baseline.aggregate.costPerChain - candidate.aggregate.costPerChain,
    timeToFirstChainSeconds:
      baseline.aggregate.timeToFirstChainSeconds -
      candidate.aggregate.timeToFirstChainSeconds,
    dormantReactivationCount:
      candidate.aggregate.dormantReactivationCount -
      baseline.aggregate.dormantReactivationCount,
  };

  // Improved if recall went up without precision collapsing
  const improved =
    deltas.signalRecall >= 0 &&
    deltas.chainRecall >= 0 &&
    deltas.signalPrecision >= -0.1;

  return { baseline, candidate, deltas, improved };
}
