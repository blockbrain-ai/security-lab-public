/**
 * Autonomous investigation contracts — weak signals, chain hypotheses,
 * attack graph nodes/edges, campaign memory, and stage vocabulary.
 */

// ---------------------------------------------------------------------------
// Stage vocabulary (SL6 — durable stage boundaries)
// ---------------------------------------------------------------------------

export const STAGES = [
  'static',
  'verification_packet_build',
  'focused_lead_confirmation',
  'local_live',
  'test_synthesis',
  'focused_closure',
  'assessment',
  'reporting',
] as const;

export type Stage = (typeof STAGES)[number];

/** Return the stage that follows `current`, or `null` if `current` is the last. */
export function nextStageAfter(current: Stage): Stage | null {
  const idx = STAGES.indexOf(current);
  return idx >= 0 && idx < STAGES.length - 1 ? STAGES[idx + 1]! : null;
}

/** Return the ordered index of a stage (0-based). */
export function stageIndex(stage: Stage): number {
  return STAGES.indexOf(stage);
}

// ---------------------------------------------------------------------------
// Run mode (SL6 — Section 3.2)
// ---------------------------------------------------------------------------

export {
  RUN_MODES,
  DEFAULT_RUN_MODE,
  isRunMode,
  inferModeFromPreset,
  describeRunMode,
  evaluateCoverageAgainstMode,
} from './mode.js';
export type { RunMode, ModeCoverageEvaluation } from './mode.js';

// ---------------------------------------------------------------------------
// Weak signals
// ---------------------------------------------------------------------------

export interface WeakSignal {
  id: string;
  /** When discovered. */
  discoveredAt: string;
  /** Iteration number when discovered. */
  iteration: number;
  /** Human-readable description. */
  description: string;
  /** Surface where the signal was observed. */
  surface: string;
  /** Confidence level 0-1. */
  confidence: number;
  /** Novelty score 0-1 (how different from previously seen signals). */
  novelty: number;
  /** Related files, endpoints, or dependencies. */
  relatedAssets: string[];
  /** What capabilities this signal might enable if chained. */
  potentialCapabilities: string[];
  /** Possible follow-on probes to investigate further. */
  suggestedFollowUps: string[];
  /** Current status. */
  status: SignalStatus;
  /** If dormant, when was it last active. */
  dormantSince?: string;
  /** If reopened, what triggered reactivation. */
  reactivationReason?: string;
  /** IDs of signals this one has been correlated with. */
  correlatedWith: string[];
  /** IDs of unresolved correlation candidates (not yet confirmed or denied). */
  unresolvedCorrelations: string[];
  /** Which probe discovered this signal. */
  sourceProbeId?: string;
}

export type SignalStatus =
  | 'active'
  | 'dormant'
  | 'reopened'
  | 'promoted'   // promoted into a chain hypothesis
  | 'merged'     // merged with another signal
  | 'dismissed'; // determined to be noise

// ---------------------------------------------------------------------------
// Chain hypotheses
// ---------------------------------------------------------------------------

export interface ChainHypothesis {
  id: string;
  /** When synthesized. */
  synthesizedAt: string;
  /** Iteration when synthesized. */
  iteration: number;
  /** Human-readable description of the full chain. */
  description: string;
  /** Severity if confirmed. */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Ordered signal IDs that compose this chain. */
  signalIds: string[];
  /** Prerequisites that must hold for the chain to work. */
  prerequisites: string[];
  /** What trust boundary would be crossed. */
  boundaryCrossing?: BoundaryCrossing;
  /** What privilege delta would result. */
  privilegeDelta?: PrivilegeDelta;
  /** Current status. */
  status: HypothesisStatus;
  /** Probe attempts against this hypothesis. */
  attempts: ChainAttempt[];
  /** If confirmed, the finding record. */
  finding?: ChainFinding;
  /**
   * Section 7.1 — file:line source location refs collected from
   * `SourceCorrelationWorker` results and threaded through probe results.
   */
  sourceLocationRefs?: import('../../../evidence-plane/src/source-location-ref.js').SourceLocationRef[];
}

export type HypothesisStatus =
  | 'proposed'
  | 'testing'
  | 'confirmed'
  | 'refuted'
  | 'dormant'         // parked for later revisitation
  | 'needs_more_data';

export interface ChainAttempt {
  /** When attempted. */
  at: string;
  /** Iteration number. */
  iteration: number;
  /** Probe IDs used in this attempt. */
  probeIds: string[];
  /** What was observed. */
  observation: string;
  /** Judge's verdict on this attempt. */
  verdict: 'progress' | 'dead_end' | 'confirmed' | 'partial';
  /** Reasoning from the judge. */
  reasoning: string;
}

export interface ChainFinding {
  /** When confirmed. */
  confirmedAt: string;
  /** Iteration when confirmed. */
  iteration: number;
  /** Full description of the confirmed chain. */
  description: string;
  /** Severity. */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Steps to reproduce. */
  reproductionSteps: string[];
  /** Recommended remediation. */
  remediationSuggestion: string;
  /** Whether this finding involved reactivating dormant signals. */
  involvedDormantReactivation: boolean;
  /**
   * Section 7.1 — file:line source refs supporting this finding.
   */
  sourceLocationRefs?: import('../../../evidence-plane/src/source-location-ref.js').SourceLocationRef[];
}

// ---------------------------------------------------------------------------
// Trust boundary and privilege
// ---------------------------------------------------------------------------

export interface BoundaryCrossing {
  from: string;
  to: string;
  mechanism: string;
}

export interface PrivilegeDelta {
  before: string;
  after: string;
  escalationType: 'horizontal' | 'vertical' | 'lateral';
}

// ---------------------------------------------------------------------------
// Attack graph
// ---------------------------------------------------------------------------

export interface AttackGraphNode {
  id: string;
  type: 'asset' | 'identity' | 'secret' | 'capability' | 'trust_boundary' | 'weak_signal' | 'dormant_correlation';
  label: string;
  metadata: Record<string, unknown>;
}

export type AttackGraphEdgeType =
  | 'leaks'
  | 'writes_to'
  | 'executes_as'
  | 'persists_via'
  | 'crosses_boundary'
  | 'enables'
  | 'suggests'
  | 'co_occurs_with'
  | 'escalates_to';

export interface AttackGraphEdge {
  from: string;
  to: string;
  type: AttackGraphEdgeType;
  weight: number;
  evidence?: string;
}

export interface AttackGraph {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
}

// ---------------------------------------------------------------------------
// Campaign memory
// ---------------------------------------------------------------------------

export interface CampaignMemory {
  /** Campaign ID. */
  campaignId: string;
  /** Current iteration. */
  iteration: number;
  /** All weak signals discovered so far. */
  signals: WeakSignal[];
  /** All chain hypotheses. */
  hypotheses: ChainHypothesis[];
  /** Confirmed findings. */
  findings: ChainFinding[];
  /** Attack graph. */
  graph: AttackGraph;
  /** Probe fingerprints for duplicate suppression. */
  probeFingerprints: Set<string>;
  /** Total cost so far. */
  totalCostUsd: number;
  /** Total probes executed. */
  totalProbes: number;
  /** Duplicate probes suppressed before execution. */
  duplicateProbesSuppressed: number;
  /** Dormant signal IDs. */
  dormantSignalIds: string[];
  /** Last resurfacing iteration. */
  lastResurfacingIteration: number;
  /** Section 11.1 — entity inventory for probe parameter resolution. */
  entityInventory?: import('../verification/probe-intelligence/entity-inventory.js').EntityInventory;
}

export function createEmptyMemory(campaignId: string): CampaignMemory {
  return {
    campaignId,
    iteration: 0,
    signals: [],
    hypotheses: [],
    findings: [],
    graph: { nodes: [], edges: [] },
    probeFingerprints: new Set(),
    totalCostUsd: 0,
    totalProbes: 0,
    duplicateProbesSuppressed: 0,
    dormantSignalIds: [],
    lastResurfacingIteration: 0,
  };
}
