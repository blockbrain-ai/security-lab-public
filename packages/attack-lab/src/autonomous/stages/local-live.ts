/**
 * Section 5.1 — LocalLiveStage.
 *
 * Wraps the runner's existing `runLocalLiveLane()` as a `Stage`. In Section
 * 5.1 the stage is a thin seam: it delegates to the runner-owned lane
 * implementation through the `StageRunnerHost` friend interface so that
 * behavior is bit-identical with the pre-5.1 monolith. Section 5.2 will
 * move the lane body into this module.
 *
 * Section 6.2 — the lane body now orchestrates two worker-driven
 * extensions: (a) a `SourceCorrelationWorker` that reads handler files in
 * the target repo whenever a probe returns confirmed/surprising data, and
 * (b) a `MythosExplorationSubLane` that runs an open-ended creative worker
 * inside a time + probe budget and is free to invent probes outside the
 * current hypothesis list. Both are configured through the target
 * profile's `liveProbing.mythos` block and CLI overrides; the orchestrator
 * binding still enforces rate limiting, identity ladder, mutation journal,
 * and probe authorization so SL2 + SL4 hold.
 *
 * Section 8.2 — monitoring stress is now a mode inside this stage rather
 * than a standalone lane. When `monitoringStress` is true, every probe
 * execution is instrumented with the detection hooks from
 * `monitoring-stress-hooks.ts`, and the monitoring stress summary is
 * folded into the local-live lane summary.
 *
 * The stage is named `local_live` (SL6, Section 1.1).
 */

import type { ExperimentStoreHandle, Stage, StageContext, StageResult } from './contracts.js';
import type { VerificationLaneSummary } from '../investigation-runner.js';

export interface LocalLiveStageOptions {
  /** Section 8.2 — enable monitoring stress detection hooks during probe execution. */
  monitoringStress?: boolean;
}

export class LocalLiveStage implements Stage {
  readonly name = 'local_live' as const;

  /** Section 8.2 — when true, detection hooks fire before/after each probe. */
  monitoringStress: boolean;

  constructor(
    private readonly experimentStore: ExperimentStoreHandle,
    options?: LocalLiveStageOptions,
  ) {
    this.monitoringStress = options?.monitoringStress ?? false;
  }

  async run(context: StageContext): Promise<StageResult> {
    const lane = await context.runner.runLocalLiveLaneFriend(
      {
        target: context.target,
        memory: context.memory,
        state: context.state,
        stateStore: context.stateStore,
        evidenceStore: context.evidenceStore,
        campaignDir: context.campaignDir,
        telemetry: context.telemetry,
        roleSessions: context.roleSessions,
        archiver: context.archiver,
      },
      this.experimentStore,
    );

    return {
      stage: 'local_live',
      outcome: mapLaneStatus(lane),
      events: [],
      coverageGaps: [],
      metadata: { lane },
    };
  }
}

/** Map a lane summary's status to a stage outcome enum. */
export function mapLaneStatus(lane: VerificationLaneSummary): StageResult['outcome'] {
  switch (lane.status) {
    case 'complete':
      return 'complete';
    case 'degraded':
      return 'degraded';
    case 'incomplete':
      return 'incomplete';
    case 'blocked':
      return 'blocked';
    default:
      return 'complete';
  }
}
