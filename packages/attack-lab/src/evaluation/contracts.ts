/**
 * Threat corpus evaluation contracts.
 *
 * The corpus is a fixed set of adversarial fixtures with known ground-truth
 * signals. The scorer compares investigator runs against that ground truth
 * to measure whether the system is actually improving.
 */

// ---------------------------------------------------------------------------
// Ground truth
// ---------------------------------------------------------------------------

export interface GroundTruthSignal {
  /** Unique signal identifier within the corpus fixture. */
  id: string;
  /** Human-readable description of the weak signal. */
  description: string;
  /** Surface where the signal lives. */
  surface: SignalSurface;
  /** Severity if confirmed as part of a chain. */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Whether this signal requires chaining with others to become a finding. */
  requiresChaining: boolean;
  /**
   * If true, this signal is intentionally non-obvious on first encounter
   * and should only become meaningful after later context changes.
   */
  dormantByDesign: boolean;
  /** IDs of other signals this one chains with to form a finding. */
  chainPartners: string[];
}

export type SignalSurface =
  | 'http'
  | 'shell'
  | 'code'
  | 'dependency'
  | 'config'
  | 'process'
  | 'evidence'
  | 'state'
  | 'prompt'
  | 'browser';

export interface GroundTruthChain {
  /** Unique chain identifier. */
  id: string;
  /** Human-readable description of the full chain finding. */
  description: string;
  /** Severity of the composed chain. */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Ordered signal IDs that compose this chain. */
  signalIds: string[];
  /** Whether confirming this chain requires reopening dormant signals. */
  requiresDormantReactivation: boolean;
}

export interface CorpusFixture {
  /** Fixture directory name (e.g. "authz-drift"). */
  id: string;
  /** Human-readable name. */
  name: string;
  /** Description of what this fixture tests. */
  description: string;
  /** Known weak signals seeded into this fixture. */
  signals: GroundTruthSignal[];
  /** Known chains that compose signals into findings. */
  chains: GroundTruthChain[];
}

export interface ThreatCorpus {
  /** All fixtures in the corpus. */
  fixtures: CorpusFixture[];
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

export interface RunScore {
  /** Investigator run ID being scored. */
  runId: string;
  /** Timestamp of scoring. */
  scoredAt: string;
  /** Per-fixture scores. */
  fixtureScores: FixtureScore[];
  /** Aggregate metrics. */
  aggregate: AggregateScore;
}

export interface FixtureScore {
  fixtureId: string;
  /** Signals the investigator found (matched to ground truth). */
  signalsFound: string[];
  /** Signals the investigator missed. */
  signalsMissed: string[];
  /** Chains the investigator confirmed. */
  chainsConfirmed: string[];
  /** Chains the investigator missed. */
  chainsMissed: string[];
  /** Signals the investigator reported that are not in ground truth. */
  falsePositives: string[];
  /** Dormant signals that were reactivated during the run. */
  dormantReactivated: string[];
}

export interface AggregateScore {
  /** Total weak signals found / total in corpus. */
  signalRecall: number;
  /** Total chains confirmed / total in corpus. */
  chainRecall: number;
  /** Signals found that are real / total signals reported. */
  signalPrecision: number;
  /** False positive count. */
  falsePositiveCount: number;
  /** Duplicate probe count (wasted work). */
  duplicateProbeCount: number;
  /** Total cost in USD for the run. */
  costUsd: number;
  /** Cost per confirmed chain finding. */
  costPerChain: number;
  /** Seconds from run start to first meaningful chain confirmation. */
  timeToFirstChainSeconds: number;
  /** Dormant signals that were later reactivated into chain hypotheses. */
  dormantReactivationCount: number;
}

export interface ScoreComparison {
  /** The baseline run score. */
  baseline: RunScore;
  /** The candidate run score. */
  candidate: RunScore;
  /** Per-metric deltas (positive = improvement). */
  deltas: {
    signalRecall: number;
    chainRecall: number;
    signalPrecision: number;
    falsePositiveCount: number;
    costPerChain: number;
    timeToFirstChainSeconds: number;
    dormantReactivationCount: number;
  };
  /** Overall verdict. */
  improved: boolean;
}
