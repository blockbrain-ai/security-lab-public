/**
 * Section 5.1 — Stage interface contracts.
 *
 * This file defines the `Stage`, `StageContext`, and `StageResult` types used
 * by the investigation stage pipeline. Each of the seven durable investigation
 * stages from Section 1.1 (`static`, `verification_packet_build`, `local_live`,
 * `test_synthesis`, `focused_closure`, `assessment`, `reporting`) implements
 * the `Stage` interface and exposes a single `run(context)` method.
 *
 * As of Section 5.1, the first four stages have been extracted. The remaining
 * three still live inline in `investigation-runner.ts` and are scheduled for
 * extraction in Section 5.2.
 */

import type { ModelAdapter } from '../../providers/contracts.js';
import type { ResponseArchiver } from '../../providers/response-archiver.js';
import type { EvidenceStore } from '../../../../evidence-plane/src/store.js';
import type { SecurityRuntime } from '../../../../security-runtime/src/runtime.js';
import type { CampaignMemory, Stage as StageName } from '../contracts.js';
import type { InvestigationState } from '../state.js';
import type { StateStore } from '../state.js';
import type { RoleSessionStore } from '../role-session-store.js';
import type { InvestigationTarget } from '../target-profile.js';
import type { RunMode } from '../mode.js';
import type { createAccumulator } from '../telemetry.js';
import type { PanelMember } from '../../orchestration/judge-panel.js';
import type { PortfolioProfile } from '../../orchestration/portfolio-profiles.js';
import type {
  CoverageGap,
  InvestigationConfig,
  VerificationLaneSummary,
} from '../investigation-runner.js';
import type { VerificationExperiment } from '../../verification/shared/index.js';
import type { ModelResponse } from '../../providers/contracts.js';

/**
 * Adapter bundle used by the stage context. This matches the adapters held by
 * `InvestigationRunner.config` — the stages receive them via the context so
 * they do not need to touch `runner.config` directly.
 */
export interface AdapterBundle {
  planner: ModelAdapter;
  counterPlanner?: ModelAdapter;
  judge: ModelAdapter;
  tribunal?: ModelAdapter;
  judgePanelMembers?: PanelMember[];
  synthesizer?: ModelAdapter;
  reporter?: ModelAdapter;
  portfolio: PortfolioProfile;
}

/**
 * The context passed to every stage's `run()` method. It bundles all of the
 * long-lived campaign state and shared services a stage needs to do its work.
 * Stages read and write `memory` and `state` directly — the shapes are the
 * same as in the monolithic runner, so behavior is bit-identical across the
 * extraction boundary.
 */
export interface StageContext {
  memory: CampaignMemory;
  state: InvestigationState;
  stateStore: StateStore;
  evidenceStore: EvidenceStore;
  target: InvestigationTarget;
  config: InvestigationConfig;
  adapters: AdapterBundle;
  runtime: SecurityRuntime;
  mode: RunMode;
  roleSessions: RoleSessionStore;
  archiver: ResponseArchiver | null;
  telemetry: ReturnType<typeof createAccumulator>;
  campaignDir: string;
  /**
   * Friend accessor: the stage pipeline is still partially owned by the
   * investigation runner during Section 5.1. Some stages delegate back into
   * the runner's existing private implementations. This is a deliberate
   * seam that Section 5.2 will remove as more logic moves into the stage
   * modules.
   */
  runner: StageRunnerHost;
}

/**
 * Coverage gap entries returned by the runner's preflight coverage check.
 * Exposed to stage modules via the `RunnerFriend` interface so they do not
 * need to reach into the runner for a private shape.
 */
export interface StageCoverageGap {
  message: string;
  severity: 'complete' | 'degraded' | 'incomplete' | 'blocked';
}

/**
 * Request record returned by `buildTestSynthesisRequestsFriend`. This is
 * the minimal contract the test-synthesis stage needs — it mirrors the
 * runner's internal `SynthesisRequest` type but is re-declared here so
 * stage modules do not need to import runner-private types.
 */
export interface TestSynthesisRequest {
  findingId: string;
  suspectFile: string;
  testFramework: string;
  hostileInputPattern: string;
  dangerousBehaviour: string;
  hypothesis: string;
}

/**
 * Section 5.1 — typed friend interface exposing the runner internals that
 * extracted stage modules need to call. Replaces the pre-5.1
 * `runner as unknown as RunnerInternals` cast pattern. Every method here
 * is a *friend* — implemented by `InvestigationRunner` as a public method
 * with a `Friend` suffix — so that the stage modules never widen the
 * runner's encapsulation beyond this surface.
 */
export interface RunnerFriend extends StageRunnerHost {
  /** True if the given verification lane is configured as required. */
  laneRequiredFriend(target: InvestigationTarget, lane: string): boolean;
  /** Whether the runner's `allowDegraded` flag is set. */
  readonly allowDegradedFriend: boolean;
  /** The planner adapter (may be absent or not usable). */
  readonly plannerAdapterFriend: ModelAdapter | undefined;
  /** The counter-planner adapter (may be absent). */
  readonly counterPlannerAdapterFriend: ModelAdapter | undefined;
  /** The synthesizer adapter (may be absent). */
  readonly synthesizerAdapterFriend: ModelAdapter | undefined;
  /** Preflight coverage check for the lane. */
  preflightTargetCoverageFriend(
    target: InvestigationTarget,
    lane: string,
  ): Promise<StageCoverageGap[]>;
  /** Build the list of test-synthesis requests for the target. */
  buildTestSynthesisRequestsFriend(
    repoRoot: string,
    memory: CampaignMemory,
  ): Promise<TestSynthesisRequest[]>;
  /** Resolve the model request timeout for a specific lane. */
  resolveModelRequestTimeoutMsFriend(
    target: InvestigationTarget,
    lane: 'test-synthesis' | 'local-live',
  ): number;
  /** Resolve the per-campaign test-synthesis limit. */
  resolveTestSynthesisLimitFriend(target: InvestigationTarget): number;
  /** Resolve the per-test execution timeout. */
  resolveTestTimeoutMsFriend(target: InvestigationTarget): number;
  /** Record a probe-level coverage gap for reporting. */
  recordProbeCoverageGapFriend(payload: Record<string, unknown>): void;
  /** Get the session key for a model invocation for a role/adapter. */
  getRoleSessionKeyFriend(
    role: string,
    adapter: ModelAdapter,
    discriminator?: string,
  ): string;
  /** Record a model invocation in state/telemetry. */
  recordModelInvocationFriend(
    telemetry: ReturnType<typeof createAccumulator>,
    state: InvestigationState,
    memory: CampaignMemory,
    role: string,
    response: ModelResponse,
    sessionKey: string,
  ): void;
  /** Checkpoint volatile state to the state store. */
  checkpointVolatileStateFriend(
    stateStore: StateStore,
    state: InvestigationState,
  ): Promise<void>;
  /** Append a role session entry. */
  appendRoleEntryFriend(
    appender: (entry: unknown) => Promise<void>,
    entry: unknown,
  ): Promise<void>;
}

/**
 * Minimal "host" interface exposed by `InvestigationRunner` to the stages.
 * Only the methods actually needed by the extracted stages are listed here.
 * Section 5.2 will shrink this surface further as more logic moves.
 */
export interface StageRunnerHost {
  runLocalLiveLaneFriend(
    args: LocalLiveLaneArgs,
    experimentStore: ExperimentStoreHandle,
  ): Promise<VerificationLaneSummary>;
  runTestSynthesisLaneFriend(
    args: TestSynthesisLaneArgs,
    experimentStore: ExperimentStoreHandle,
  ): Promise<VerificationLaneSummary>;
  buildVerificationPacketsFriend(
    memory: CampaignMemory,
    target: InvestigationTarget,
    seenHypothesisIds?: Set<string>,
  ): VerificationPacketSummary[];
}

export interface VerificationPacketSummary {
  id: string;
  hypothesisId: string;
  signalDescriptions: string[];
  relatedAssets: string[];
}

export interface ExperimentStoreHandle {
  record: (experiment: VerificationExperiment) => Promise<void>;
}

export interface LocalLiveLaneArgs {
  target: InvestigationTarget;
  memory: CampaignMemory;
  state: InvestigationState;
  stateStore: StateStore;
  evidenceStore: EvidenceStore;
  campaignDir: string;
  telemetry: ReturnType<typeof createAccumulator>;
  roleSessions: RoleSessionStore;
  archiver: ResponseArchiver | null;
}

export type TestSynthesisLaneArgs = LocalLiveLaneArgs;

/**
 * A stage-emitted structured event that the runner will persist via the
 * evidence store. Spec §2.1 requires this field on `StageResult`. During
 * the Section 5.1 seam, most stages emit directly through
 * `context.evidenceStore.appendEvent()` and leave this array empty, but
 * the contract is in place so future stages (and extracted bodies in 5.2)
 * can accumulate events here and let the pipeline driver flush them.
 */
export interface StageEmittedEvent {
  name: string;
  payload: Record<string, unknown>;
}

/**
 * Per-stage result returned to the pipeline driver in the runner.
 */
export interface StageResult {
  stage: StageName;
  outcome: 'complete' | 'degraded' | 'incomplete' | 'blocked';
  events: StageEmittedEvent[];
  coverageGaps: CoverageGap[];
  metadata: Record<string, unknown>;
}

/**
 * The `Stage` interface — every stage module exposes a class implementing
 * this contract. The runner assembles a pipeline of stage instances and
 * iterates through them.
 */
export interface Stage {
  readonly name: StageName;
  run(context: StageContext): Promise<StageResult>;
}

/** Construct an empty (zero-effect) stage result for a given stage. */
export function emptyStageResult(stage: StageName): StageResult {
  return {
    stage,
    outcome: 'complete',
    events: [],
    coverageGaps: [],
    metadata: {},
  };
}
