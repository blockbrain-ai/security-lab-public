// Contracts
export type {
  WeakSignal,
  SignalStatus,
  ChainHypothesis,
  HypothesisStatus,
  ChainAttempt,
  ChainFinding,
  BoundaryCrossing,
  PrivilegeDelta,
  AttackGraphNode,
  AttackGraphEdge,
  AttackGraphEdgeType,
  AttackGraph,
  CampaignMemory,
} from './contracts.js';
export { createEmptyMemory } from './contracts.js';

// Schemas
export type { PlannerOutput, JudgeOutput, PlannerProbeRequest } from './schemas.js';
export { PlannerOutputSchema, JudgeOutputSchema } from './schemas.js';

// State
export type { InvestigationPhase, InvestigationState } from './state.js';
export {
  StateStore,
  createInitialState,
  canResume,
  shouldEscapeDeadEnds,
  isBudgetExhausted,
  isIterationLimitReached,
} from './state.js';

// Weak signal ledger
export {
  addSignal,
  markDormant,
  reactivateSignal,
  promoteSignal,
  dismissSignal,
  addCorrelation,
  getActiveSignals,
  getDormantSignals,
  getSignalsWithUnresolvedCorrelations,
  shouldResurface,
  getCandidatesForResurfacing,
  markResurfacingDone,
} from './weak-signal-ledger.js';

// Attack graph
export { addNode, addEdge, ingestSignal, findChainCandidates, summarizeGraph } from './attack-graph.js';
export type { ChainCandidate } from './attack-graph.js';

// Chain synthesis
export { synthesizeHypotheses } from './chain-synthesizer.js';

// Novelty ranking
export { scoreNovelty, isDuplicateProbe, recordProbe, rankHypotheses } from './novelty-ranker.js';

// Campaign memory
export { saveMemory, loadMemory, memorySnapshot } from './campaign-memory.js';

// Planner and judge
export { plan } from './planner.js';
export { judge } from './judge.js';

// Probe generator
export type { GeneratedProbe, ProbeGenerationResult, RejectedProbe } from './probe-generator.js';
export { translateProbeRequests } from './probe-generator.js';
export { executeGeneratedProbe, buildRuntimeProbeContext, buildRuntimeTargetContext } from './probe-executor.js';
export type { InvestigationTarget } from './target-profile.js';
export { loadInvestigationTarget, loadTargetProfile, summarizeTargetProfile } from './target-profile.js';

// Prompts
export { renderPrompt } from './prompts.js';

// Runner and supporting utilities
export type { InvestigationConfig, InvestigationResult } from './investigation-runner.js';
export { InvestigationRunner } from './investigation-runner.js';
export { generateProposal, formatProposals } from './fix-planner.js';
export { buildRegressionPack, saveRegressionPack, formatRegressionSummary } from './regression-promoter.js';
export { loadTargetOverlay } from './target-overlay.js';
export type { OverlayInline, OverlayTrustBoundary, OverlayVulnerabilityFamily } from './target-profile.js';
