/**
 * Section 11.5 — FocusedLeadConfirmationStage.
 *
 * Sits between `verification_packet_build` and `local_live` in the pipeline.
 * Ranks the top static leads, writes per-lead briefs, hands those briefs to
 * persistent worker sessions, routes worker-requested probes through the
 * orchestrator, and records structured confirmation outcomes.
 *
 * This stage is additive — the broader autonomous local-live lane still runs
 * after it. Focused confirmation provides a preferred path for the highest-
 * value leads while the autonomous lane covers the remaining surface.
 */

import type { Stage, StageContext, StageResult } from './contracts.js';
import {
  runFocusedConfirmation,
  buildConfirmationSummary,
  mapConfirmationToHypothesisStatus,
  type FocusedConfirmationConfig,
  type WorkerSession,
  type ProbeExecutor,
} from '../../verification/focused-leads/focused-confirmation.js';
import { DEFAULT_RANKING_CONFIG } from '../../verification/focused-leads/lead-ranker.js';

export interface FocusedLeadConfirmationStageOptions {
  /** Whether this stage is enabled. Defaults to false (opt-in). */
  enabled?: boolean;
  /** Maximum leads to rank and confirm. */
  maxLeads?: number;
  /** Maximum probes per session. */
  maxProbesPerSession?: number;
  /** Whether to run an optional counter/reviewer worker. */
  useCounterWorker?: boolean;
  /** Factory for creating worker sessions. */
  workerSessionFactory?: (hypothesisId: string) => WorkerSession;
  /** Probe executor (must go through orchestrator). */
  probeExecutor?: ProbeExecutor;
  /** Dynamic runtime resolver used by the real investigation runner. */
  runtimeFactory?: (
    context: StageContext,
  ) => Promise<FocusedLeadConfirmationRuntime> | FocusedLeadConfirmationRuntime;
}

export interface FocusedLeadConfirmationRuntime {
  enabled: boolean;
  maxLeads: number;
  maxProbesPerSession: number;
  useCounterWorker: boolean;
  workerSessionFactory: (hypothesisId: string) => WorkerSession;
  probeExecutor: ProbeExecutor;
  cleanup?: () => Promise<void>;
  skipReason?: string;
}

/**
 * Default no-op worker session that returns insufficient_evidence.
 * Real implementations are injected by the runner when serious-mode
 * workers are available.
 */
const DEFAULT_WORKER: WorkerSession = async (_brief, _requestProbe, _role) => ({
  status: 'insufficient_evidence' as const,
  reasoning: 'No focused confirmation worker configured for this run mode',
});

const DEFAULT_EXECUTOR: ProbeExecutor = async (_request) => ({
  probeId: 'not-configured',
  verdict: 'not_applicable' as const,
  observation: 'No probe executor configured for focused lead confirmation',
  confidence: 0,
  evidenceRefs: [],
  rollbackExecuted: false,
});

/**
 * The FocusedLeadConfirmationStage — Section 11.5.
 *
 * When enabled, ranks the top static leads, writes briefs, runs worker
 * sessions, and records structured outcomes. When disabled (default),
 * emits a skip event and returns complete.
 */
export class FocusedLeadConfirmationStage implements Stage {
  readonly name = 'focused_lead_confirmation' as const;
  private readonly enabled: boolean;
  private readonly maxLeads: number;
  private readonly maxProbesPerSession: number;
  private readonly useCounterWorker: boolean;
  private readonly workerSessionFactory: (hypothesisId: string) => WorkerSession;
  private readonly probeExecutor: ProbeExecutor;
  private readonly runtimeFactory?: FocusedLeadConfirmationStageOptions['runtimeFactory'];

  constructor(options?: FocusedLeadConfirmationStageOptions) {
    this.enabled = options?.enabled ?? false;
    this.maxLeads = options?.maxLeads ?? 5;
    this.maxProbesPerSession = options?.maxProbesPerSession ?? 10;
    this.useCounterWorker = options?.useCounterWorker ?? false;
    this.workerSessionFactory = options?.workerSessionFactory ?? (() => DEFAULT_WORKER);
    this.probeExecutor = options?.probeExecutor ?? DEFAULT_EXECUTOR;
    this.runtimeFactory = options?.runtimeFactory;
  }

  async run(context: StageContext): Promise<StageResult> {
    const runtime = await this.resolveRuntime(context);
    if (!runtime.enabled) {
      await context.evidenceStore.appendEvent('focused_lead_confirmation_skipped', {
        reason: runtime.skipReason ?? 'Stage not enabled for this run mode',
      });
      return {
        stage: 'focused_lead_confirmation',
        outcome: 'complete',
        events: [{ name: 'focused_lead_confirmation_skipped', payload: { reason: runtime.skipReason ?? 'not_enabled' } }],
        coverageGaps: [],
        metadata: { enabled: false, skipReason: runtime.skipReason ?? 'not_enabled' },
      };
    }

    const config: FocusedConfirmationConfig = {
      ranking: { ...DEFAULT_RANKING_CONFIG, maxLeads: runtime.maxLeads },
      maxProbesPerSession: runtime.maxProbesPerSession,
      useCounterWorker: runtime.useCounterWorker,
      campaignDir: context.campaignDir,
    };

    try {
      const result = await runFocusedConfirmation(
        context.memory,
        runtime.workerSessionFactory,
        runtime.probeExecutor,
        config,
        context.evidenceStore,
      );

      // Update hypothesis statuses in campaign memory.
      for (const session of result.sessions) {
        const hypothesis = context.memory.hypotheses.find(
          (h) => h.id === session.hypothesisId,
        );
        if (hypothesis) {
          hypothesis.status = mapConfirmationToHypothesisStatus(session.status);
        }
      }

      const summary = buildConfirmationSummary(result);

      const outcome = result.sessions.length === 0 ? 'complete'
        : result.confirmed > 0 ? 'complete'
        : result.refuted === result.sessions.length ? 'complete'
        : 'degraded';

      return {
        stage: 'focused_lead_confirmation',
        outcome,
        events: [],
        coverageGaps: [],
        metadata: {
          focusedLeadConfirmation: summary,
        },
      };
    } finally {
      await runtime.cleanup?.();
    }
  }

  private async resolveRuntime(context: StageContext): Promise<FocusedLeadConfirmationRuntime> {
    if (this.runtimeFactory) {
      return await this.runtimeFactory(context);
    }

    return {
      enabled: this.enabled,
      maxLeads: this.maxLeads,
      maxProbesPerSession: this.maxProbesPerSession,
      useCounterWorker: this.useCounterWorker,
      workerSessionFactory: this.workerSessionFactory,
      probeExecutor: this.probeExecutor,
    };
  }
}
