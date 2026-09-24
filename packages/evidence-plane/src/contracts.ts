export type SafetyState = 'blocked' | 'allowed' | 'error';
export type SecurityMode = 'declared' | 'blind';
export type EnvironmentTier =
  | 'fixture'
  | 'sandbox'
  | 'local_live'
  | 'staging'
  | 'hosted_authorized'
  | 'production_shadow';
export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type BlockSource = 'runtime' | 'target' | 'execution';

export interface ProbeObservation {
  kind: string;
  statusCode?: number;
  exitCode?: number | null;
  stdout?: string;
  stderr?: string;
  responseBody?: string;
  durationMs: number;
}

export interface StepVerdict {
  observedSafetyState: SafetyState;
  expectationMet: boolean;
  replayable: boolean;
  residualRisk: string | null;
  blockSource?: BlockSource;
}

export interface StepRecord {
  scenarioId: string;
  scenarioTitle: string;
  stepId: string;
  stepTitle: string;
  targetId: string;
  severity: Severity;
  observation: ProbeObservation;
  verdict: StepVerdict;
  captures: Record<string, string>;
}

export interface ScenarioScores {
  attempt: 'yes' | 'no';
  block: 'full' | 'partial' | 'none';
  outcome: 'contained' | 'unexpected' | 'error';
  stealth: 'low' | 'medium' | 'high' | 'unknown';
}

export interface ScenarioRecord {
  scenarioId: string;
  title: string;
  targetId: string;
  severity: Severity;
  passed: boolean;
  scores: ScenarioScores;
  residualRisk: string | null;
  steps: StepRecord[];
}

export interface OrchestrationSummary {
  planner: string;
  executor: string;
  judge: string;
  reporter: string;
}

export interface RunSummary {
  runId: string;
  runfileId: string;
  runfileName: string;
  mode: SecurityMode;
  startedAt: string;
  completedAt: string;
  scenarioCount: number;
  passed: number;
  failed: number;
  targetEnvironments: EnvironmentTier[];
  orchestration: OrchestrationSummary;
  records: ScenarioRecord[];
}

export interface EventEnvelope {
  index?: number;
  previousHash?: string;
  hash?: string;
  at: string;
  stage: string;
  payload: Record<string, unknown>;
  /** Evidence schema version stamped at write time. */
  schemaVersion?: number;
}

export interface EvidenceManifest {
  runId: string;
  generatedAt: string;
  files: Record<string, string>;
  /**
   * Event count at the moment the manifest was written.
   *
   * Optional so manifests produced before this field existed stay readable.
   * Together with `headHash` it lets a later verification detect truncation
   * or reordering of `events.jsonl` that a plain file hash would miss once
   * further events have been appended.
   */
  eventCount?: number;
  /** Hash-chain head at the moment the manifest was written. */
  headHash?: string;
}

/**
 * Evidence schema version.
 * - v1 → v2 (Section 1.1): integrity events (stage_started, stage_completed,
 *   writer_lock_*, provider_timeout, heartbeat, preflight_*).
 * - v2 → v3 (Section 7.1): SourceLocationRef support in event payloads and
 *   the discriminated EvidenceRef union. Old v1/v2 event files remain
 *   readable; new writes use v3.
 */
export const EVIDENCE_SCHEMA_VERSION = 3;

// Re-export the Section 7.1 evidence-ref types so consumers can import from
// contracts.ts (SL1 contract-first).
export type {
  SourceLocationRef,
  EvidenceRef,
} from './source-location-ref.js';
export {
  parseSourceRef,
  formatSourceRef,
  toWorkspaceRelative,
  migrateStringRef,
  normalizeEvidenceRefs,
} from './source-location-ref.js';

// Chain-verification result contract (SL1) — verified against the rolling
// event hash chain by `EvidenceStore.verifyChain()` and the report CLI.
export type { HashChainVerification as ChainVerification } from './hash-chain.js';
