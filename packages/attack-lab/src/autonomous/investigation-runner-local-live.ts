/**
 * Investigation runner — local-live method extraction.
 *
 * Abstract base class containing methods related to the local-live
 * verification lane. Extracted from investigation-runner-internals.ts
 * as Step 2b of the god-object refactor, gated by the fixture-campaign
 * diff harness.
 *
 * Class hierarchy:
 *   InvestigationRunnerLocalLive (this file, local-live methods)
 *     └─ InvestigationRunnerInternals (extends, everything else)
 *         └─ InvestigationRunner (extends, thin coordinator)
 */

import { statSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { z } from 'zod';

import type { InvokeOptions, ModelAdapter, ModelResponse } from '../providers/contracts.js';
import { FOCUSED_CONFIRMATION_WORKER_CONTRACT } from '../providers/worker-contract.js';
import type { EnvironmentTier } from '../../../evidence-plane/src/contracts.js';
import type { InvestigationReportData } from '../../../evidence-plane/src/investigation-report.js';
import { SecurityRuntime } from '../../../security-runtime/src/runtime.js';
import type { CanarySpec, IdentitySpec, LiveProbeRequest, LiveExecutionResult, AdaptiveExplorationConfig } from '../verification/local-live/contracts.js';
import type { LiveReplayOptions } from '../verification/local-live/live-replay.js';
import { IdentityLadder } from '../verification/local-live/identity-ladder.js';
import { RateLimiter } from '../verification/local-live/rate-limiter.js';
import { MutationJournal } from '../verification/local-live/reversible-mutation.js';
import { executeLiveProbeBatch, executeLiveProbe } from '../verification/local-live/live-replay.js';
import { executeProbeSequence } from '../verification/local-live/probe-sequence.js';
import { executeIdentityDifferentialProbe } from '../verification/local-live/identity-differential.js';
import type { SequenceExecutionSummary, ProbeSequenceDefinition } from '../verification/local-live/contracts.js';
import { translateHypothesisToLiveProbes, type TranslationResult } from '../verification/local-live/hypothesis-translator.js';
import { generateNonce, substituteNonce, matchCanary, buildAuthBypassCanary, buildIdorCanary, buildPromptInjectionCanary } from '../verification/local-live/canary-harness.js';
import { executeRuntimeSurfaceProbe } from '../verification/local-live/runtime-surface-runner.js';
import { prepareLocalAuthBootstrap, type LocalAuthBootstrapResult } from '../verification/local-live/auth-bootstrap.js';
import { prepareLocalTargetSession, type LocalTargetSession } from '../verification/local-live/target-lifecycle.js';
import { classifyResponse } from '../verification/local-live/response-surprise.js';
import { generateFollowupProbes } from '../verification/local-live/followup-generator.js';
import { rankRoutesByRelevance } from '../verification/local-live/route-similarity.js';
import { MythosExplorationSubLane, type SubLaneResult, type ProbeHistoryEntry, type HypothesisSnapshot } from '../verification/local-live/mythos-exploration-sublane.js';
import { selectMidRoundTriggers, runMidRoundSynthesis } from '../verification/local-live/mid-round-synthesis.js';
import { addSignal } from './weak-signal-ledger.js';
import { ingestSignal, findChainCandidatesNearSignals } from './attack-graph.js';
import { SourceCorrelationWorker, SourceCorrelationBudget } from '../verification/local-live/source-correlation-worker.js';
import { classifyProbe as classifyProbeForMonitoringStress, scoreResponse as scoreResponseForMonitoringStress, trackLongContextLoss, trackRareAction, classifyWorkerToolCall, accumulateDetection, type MonitoringStressRoundSummary, createEmptyRoundSummary } from '../verification/local-live/monitoring-stress-hooks.js';
import type { CampaignMode } from '../verification/monitoring-stress/index.js';
import type { WorkerToolOrchestrator, SubmittedFinding, SubmittedHypothesis } from '../verification/local-live/worker-tools.js';
import { validateFindingEvidenceRefs } from '../verification/local-live/worker-tools.js';
import type { MythosExplorationConfig } from '../verification/local-live/mythos-exploration-sublane.js';
import { parseSourceRef, toWorkspaceRelative, type SourceLocationRef } from '../../../evidence-plane/src/source-location-ref.js';
import { synthesizeHypotheses } from './chain-synthesizer.js';
import { DEFAULT_RUN_MODE } from './mode.js';
import {
  createEmptyInventory,
  seedEntities,
  type EntityInventory,
} from '../verification/probe-intelligence/entity-inventory.js';
import {
  ENTITY_INVENTORY_EVENT_STAGES,
} from '../../../evidence-plane/src/events/coverage-gap-events.js';
import {
  classifyBrowserHypothesis,
  executeBrowserProbe,
  resolveTargetBrowserFamilies,
  getBrowserFamilyDefinition,
  emptyBrowserExploitFamilySummary,
  accumulateBrowserProbeResult,
  type BrowserProbeRequest,
} from '../verification/browser/browser-probe-families.js';
import type { BrowserLauncher } from '../verification/browser/browser-runner.js';
import type { VerificationExperiment } from '../verification/shared/contracts.js';
import { EvidenceStore } from '../../../evidence-plane/src/store.js';
import type { CampaignMemory, ChainHypothesis } from './contracts.js';
import type { InvestigationState } from './state.js';
import type { InvestigationTarget } from './target-profile.js';
import { loadInvestigationTarget } from './target-profile.js';
import { buildRuntimeTargetContext } from './probe-executor.js';
import type { StateStore } from './state.js';
import type { PortfolioProfile } from '../orchestration/portfolio-profiles.js';
import { shouldUseCounterPlanner, getDefaultProfile } from '../orchestration/portfolio-profiles.js';
import type { ResponseArchiver } from '../providers/response-archiver.js';
import type { RoleSessionStore, RoleTranscriptEntry } from './role-session-store.js';
import { createAccumulator } from './telemetry.js';
import type { RouteSurface } from '../intelligence/contracts.js';
import { withHeartbeat } from './heartbeat.js';
import type { StageContext, StageCoverageGap, ExperimentStoreHandle, VerificationPacketSummary } from './stages/contracts.js';
import type { FocusedLeadConfirmationRuntime } from './stages/focused-lead-confirmation.js';
import {
  type ConfirmationStatus,
  type ProbeExecutor as FocusedLeadProbeExecutor,
  type ProbeExecutionResult as FocusedLeadProbeExecutionResult,
  type WorkerSession as FocusedLeadWorkerSession,
} from '../verification/focused-leads/focused-confirmation.js';
import {
  renderBriefForWorker,
  type LeadBrief,
} from '../verification/focused-leads/lead-brief.js';
import {
  createLaneSummary,
  addLaneCoverageGap,
  countLaneVerdict,
  countLaneVerdictWithClassification,
  usableAdapter,
  normalizeRuntimeSignalSummary,
  coverageGap,
  buildLinuxSidecarCommand,
  shouldContinueLocalLiveRounds,
  shouldUseCounterPlannerForLocalLive,
  countNovelRuntimeSignals,
  severityRank,
  maxExecutionStatus,
  type ExecutionStatus,
  type CoverageGap as CoverageGapType,
  type VerificationLaneSummary,
  type ChildCampaignSummary,
} from './investigation-runner-utils.js';


// Types from internals — import type avoids runtime circular dependency
import type {
  InvestigationConfig,
  VerificationLanesSummary,
  VerificationPacket,
} from './investigation-runner-internals.js';
import { resolveAdaptiveExplorationConfig, resolveMythosExplorationConfig } from './target-profile.js';

const execFileAsync = promisify(execFile);

function sanitizePacketFileSegment(value: string): string {
  return value.replace(/[^a-zA-Z0-9._-]+/g, '_');
}

const FocusedConfirmationStatusSchema = z.enum([
  'confirmed',
  'refuted',
  'narrowed',
  'needs_browser',
  'needs_human_setup',
  'insufficient_evidence',
]);

// Nullable-optional helpers: LLMs routinely emit `"body": null` for GET probes,
// `"headers": null` when no headers are needed, etc. `.optional()` alone rejects
// null. We accept null on ingest and transform it to undefined so downstream
// consumers don't need to change their types. Without this the whole focused-
// confirmation turn fails zod validation on a single null field.
const nullishString = () =>
  z.string().nullish().transform((v) => v ?? undefined);
const nullishInt = () =>
  z.number().int().nullish().transform((v) => v ?? undefined);

const FocusedExpectedResponseSchema = z.object({
  status: nullishInt(),
  statusIn: z.array(z.number().int()).nullish().transform((v) => v ?? undefined),
  bodyContains: z.array(z.string()).nullish().transform((v) => v ?? undefined),
  bodyNotContains: z.array(z.string()).nullish().transform((v) => v ?? undefined),
});

const FocusedHttpProbeSchema = z.object({
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD']),
  path: z.string().min(1),
  headers: z.record(z.string()).nullish().transform((v) => v ?? undefined),
  body: nullishString(),
});

const FocusedProcessProbeSchema = z.object({
  action: z.enum(['env_scan', 'fd_scan', 'proc_self_read', 'credential_search']),
  searchPatterns: z.array(z.string()).nullish().transform((v) => v ?? undefined),
});

const FocusedPersistenceProbeSchema = z.object({
  action: z.enum(['cron_check', 'launchd_check', 'background_process_check', 'startup_check']),
});

const FocusedWorkerProbeSchema = z.object({
  probeKind: z.enum(['http', 'process', 'persistence', 'browser']),
  identityId: z.string().min(1),
  rationale: z.string().min(1),
  probeFamily: nullishString(),
  probeVariant: nullishString(),
  http: FocusedHttpProbeSchema.nullish().transform((v) => v ?? undefined),
  process: FocusedProcessProbeSchema.nullish().transform((v) => v ?? undefined),
  persistence: FocusedPersistenceProbeSchema.nullish().transform((v) => v ?? undefined),
  expectedWhenSafe: FocusedExpectedResponseSchema.nullish().transform((v) => v ?? undefined),
  expectedWhenExploitable: FocusedExpectedResponseSchema.nullish().transform((v) => v ?? undefined),
});

const FocusedWorkerTurnSchema = z.object({
  status: FocusedConfirmationStatusSchema,
  reasoning: z.string().min(1),
  probeRequests: z.array(FocusedWorkerProbeSchema).max(10).default([]),
});

type FocusedWorkerTurn = z.infer<typeof FocusedWorkerTurnSchema>;

function parseFocusedWorkerTurn(content: string): FocusedWorkerTurn {
  const fenced = content.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  const candidate = fenced?.[1] ?? content;
  const parsed = JSON.parse(candidate);
  return FocusedWorkerTurnSchema.parse(parsed);
}

function formatFocusedProbeResults(
  results: FocusedLeadProbeExecutionResult[],
): string {
  if (results.length === 0) {
    return 'No probes have been executed yet.';
  }

  return results
    .map((result, index) => [
      `### Probe ${index + 1}`,
      `- Verdict: ${result.verdict}`,
      `- Observation: ${result.observation}`,
      `- Confidence: ${result.confidence}`,
      `- Evidence refs: ${result.evidenceRefs.join(', ') || 'none'}`,
      `- Rollback executed: ${result.rollbackExecuted ? 'yes' : 'no'}`,
    ].join('\n'))
    .join('\n\n');
}

function summarizeFocusedRequest(
  request: FocusedWorkerTurn['probeRequests'][number],
): string {
  const target = request.http?.path
    ?? request.process?.action
    ?? request.persistence?.action
    ?? request.probeKind;
  return `${request.probeKind}:${target}`;
}

export abstract class InvestigationRunnerLocalLive {

  // ── Abstract properties/methods defined on the subclass ──
  abstract readonly config: InvestigationConfig;
  abstract readonly runtime: SecurityRuntime;
  abstract cachedSurfaceRoutes: RouteSurface[];

  // Methods defined on the subclass that local-live methods call
  abstract laneRequired(target: InvestigationTarget, lane: string): boolean;
  abstract preflightTargetCoverage(target: InvestigationTarget, lane: string): Promise<StageCoverageGap[]>;
  abstract isStrictVerificationEnabled(): boolean;
  abstract getVerificationPolicy(target: InvestigationTarget): Record<string, unknown>;
  abstract resolveVerificationLimit(target: InvestigationTarget, key: string, override: number | undefined, defaultValue: number, max: number): number;
  abstract buildInvokeOptions<T>(state: InvestigationState, target: InvestigationTarget, role: string, adapter: ModelAdapter, discriminator?: string, requestTimeoutMs?: number): Partial<InvokeOptions<T>>;
  abstract recordModelInvocation(telemetry: ReturnType<typeof createAccumulator>, state: InvestigationState, memory: CampaignMemory, kind: string, response: ModelResponse, sessionKey?: string): void;
  abstract checkpointVolatileState(stateStore: StateStore, state: InvestigationState): Promise<void>;
  abstract getRoleSessionKey(role: string, adapter: ModelAdapter, discriminator?: string): string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  abstract appendRoleEntry(appender: (entry: any) => Promise<void>, entry: unknown): Promise<void>;
  abstract recordProbeCoverageGap(payload: Record<string, unknown>): void;
  // buildVerificationPackets is defined in the probe builders section below (not abstract)
  abstract resolveVerificationHypothesisLimit(target: InvestigationTarget): number;
  abstract resolveLocalLiveRounds(target: InvestigationTarget): number;
  abstract resolveModelRequestTimeoutMs(target: InvestigationTarget, lane: 'test-synthesis' | 'local-live'): number;
  abstract resolveRuntimeSignalsPerRound(target: InvestigationTarget): number;
  abstract resolveLiveProbeLimitPerHypothesis(target: InvestigationTarget): number;

  protected getLocalLivePrimaryAdapter(): ModelAdapter | undefined {
    return usableAdapter(this.config.localLivePlannerAdapter ?? this.config.plannerAdapter);
  }

  protected getLocalLiveCounterAdapter(): ModelAdapter | undefined {
    return usableAdapter(this.config.localLiveCounterPlannerAdapter ?? this.config.counterPlannerAdapter);
  }

  // ── Local-live identity / mutation / Linux helpers ──

  public getMissingIdentityRequirements(
    target: InvestigationTarget,
    identityLadder: IdentityLadder,
  ): string[] {
    const requiredIdentities = target.requiredIdentities ?? [];
    return requiredIdentities.filter((identityId) => {
      const identity = identityLadder.get(identityId);
      if (!identity) {
        return true;
      }
      return identityLadder.buildHeaders(identityId) === null;
    });
  }

  public getMidPipelineMissingIdentityRequirements(target: InvestigationTarget): string[] {
    const identities = (target.identities ?? []) as unknown as IdentitySpec[];
    const identityLadder = new IdentityLadder(identities, process.env as Record<string, string>, target.authMechanism?.tenantHeader);
    const authBootstrap = (target.authBootstrap as Record<string, unknown> | undefined) ?? {};
    const canBootstrapBearerIdentities = typeof authBootstrap['type'] === 'string' && authBootstrap['type'].endsWith('_local_jwt');

    return (target.requiredIdentities ?? []).filter((identityId) => {
      const identity = identityLadder.get(identityId);
      if (!identity) {
        return true;
      }
      if (identityLadder.buildHeaders(identityId) !== null) {
        return false;
      }
      return !(canBootstrapBearerIdentities && identity.kind === 'bearer_token' && identity.tokenEnv);
    });
  }

  public shouldAutoEnableLocalMutations(target: InvestigationTarget): boolean {
    if (!this.isStrictVerificationEnabled()) {
      return false;
    }
    const policy = this.getVerificationPolicy(target);
    const autoEnable = policy['autoEnableReversibleMutations'];
    return autoEnable === true
      && this.hasReversibleLocalMutationSupport(target);
  }

  public hasReversibleLocalMutationSupport(target: InvestigationTarget): boolean {
    const rollback = target.rollback as Record<string, unknown> | undefined;
    return Boolean(
      target.canaries?.length
      && target.seedData
      && rollback
      && rollback['strategy']
      && rollback['strategy'] !== 'manual',
    );
  }

  public requiresRollbackForMutations(target: InvestigationTarget): boolean {
    const policy = this.getVerificationPolicy(target);
    const configured = policy['requireRollbackForMutations'];
    return configured == null ? true : configured === true;
  }

  public async checkMidPipelineLiveTargetReachability(target: InvestigationTarget): Promise<boolean | null> {
    if (!target.baseUrl) {
      return false;
    }

    const startup = (target.localStartup as Record<string, unknown> | undefined) ?? {};
    if (Object.keys(startup).length > 0) {
      // Targets with an explicit local startup path are allowed to come up later
      // during the actual lane. The mid-pipeline gate only does direct
      // reachability checks for already-running targets.
      return null;
    }

    try {
      const response = await fetch(new URL('/', target.baseUrl), {
        method: 'GET',
        signal: AbortSignal.timeout(3_000),
      });
      return response.status < 500;
    } catch {
      return false;
    }
  }

  public async checkLinuxRuntimeAvailability(target: InvestigationTarget): Promise<{ available: boolean; reason?: string }> {
    if (process.platform === 'linux') {
      return { available: true };
    }

    if (this.config.linuxRuntime === 'skip') {
      return { available: false, reason: 'linux runtime policy is skip' };
    }
    if (this.config.linuxRuntime === 'fail') {
      return { available: false, reason: 'linux runtime policy is fail on non-Linux hosts' };
    }

    const sidecar = (target.linuxSidecar as Record<string, unknown> | undefined) ?? {};
    if (sidecar['enabled'] !== true) {
      return { available: false, reason: 'linux sidecar is not enabled on the target profile' };
    }
    const composeService = typeof sidecar['composeService'] === 'string' ? sidecar['composeService'] : undefined;
    const composeCwd = typeof sidecar['composeCwd'] === 'string' ? sidecar['composeCwd'] : target.cwd ?? target.repoRoot;
    const composeEnv = this.getLinuxSidecarComposeEnv(target);
    const targetContainer = typeof sidecar['targetContainer'] === 'string' ? sidecar['targetContainer'] : undefined;
    const command = typeof sidecar['command'] === 'string' ? sidecar['command'] : undefined;
    if (!composeService && !targetContainer && !command) {
      return {
        available: false,
        reason: 'linux sidecar requires composeService, targetContainer, or command; image-only configuration cannot inspect target runtime surfaces',
      };
    }

    try {
      await execFileAsync('docker', ['info']);
      const startup = (target.localStartup as Record<string, unknown> | undefined) ?? {};
      if (Object.keys(startup).length > 0) {
        return { available: true };
      }
      if (composeService) {
        const { stdout } = await execFileAsync('docker', ['compose', 'ps', '-q', composeService], {
          cwd: composeCwd,
          env: composeEnv,
        });
        if (!stdout.trim()) {
          return {
            available: false,
            reason: `linux sidecar compose service "${composeService}" is not running`,
          };
        }
      }
      if (targetContainer) {
        const { stdout } = await execFileAsync('docker', ['inspect', '-f', '{{.State.Running}}', targetContainer]);
        if (stdout.trim() !== 'true') {
          return {
            available: false,
            reason: `linux sidecar target container "${targetContainer}" is not running`,
          };
        }
      }
      return { available: true };
    } catch (error) {
      return {
        available: false,
        reason: `docker is unavailable for linux sidecar execution: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  }

  public isLinuxOnlyRuntimeProbe(probe: LiveProbeRequest): boolean {
    return probe.process?.action === 'fd_scan'
      || probe.process?.action === 'proc_self_read'
      || probe.persistence?.action === 'background_process_check';
  }

  public async executeRuntimeProbeWithLinuxFallback(
    liveTarget: InvestigationTarget,
    probe: LiveProbeRequest,
  ): Promise<{
    result: Awaited<ReturnType<typeof executeRuntimeSurfaceProbe>>;
    coverageGap?: CoverageGapType;
  }> {
    if (process.platform === 'linux' || !this.isLinuxOnlyRuntimeProbe(probe)) {
      return {
        result: await executeRuntimeSurfaceProbe(probe, {
          decoyMarkers: Array.isArray((liveTarget.processDecoys as Record<string, unknown> | undefined)?.['envMarkers'])
            ? ((liveTarget.processDecoys as Record<string, unknown>)['envMarkers'] as string[])
            : undefined,
          workingDir: liveTarget.cwd ?? liveTarget.repoRoot,
        }),
      };
    }

    if (this.config.linuxRuntime !== 'container') {
      return {
        result: {
          probeId: `runtime-${probe.findingId}-linux-unavailable`,
          findingId: probe.findingId,
          identityId: probe.identityId,
          request: { method: 'NONE', url: '', headers: {} },
          response: { status: 0, headers: {}, body: '', durationMs: 0 },
          rollbackExecuted: false,
          verdict: 'not_applicable',
          reasoning: 'Linux-only runtime probe skipped on non-Linux host',
        },
        coverageGap: coverageGap(
          'local-live',
          'linux_runtime_unavailable',
          `Linux-only runtime probe ${probe.process?.action ?? probe.persistence?.action ?? probe.findingId} was requested but linux runtime handling is ${this.config.linuxRuntime ?? 'unset'}.`,
          this.isStrictVerificationEnabled() ? 'incomplete' : 'degraded',
        ),
      };
    }

    const sidecar = (liveTarget.linuxSidecar as Record<string, unknown> | undefined) ?? {};
    const composeService = typeof sidecar['composeService'] === 'string' ? sidecar['composeService'] : undefined;
    const composeCwd = typeof sidecar['composeCwd'] === 'string' ? sidecar['composeCwd'] : liveTarget.cwd ?? liveTarget.repoRoot;
    const composeEnv = this.getLinuxSidecarComposeEnv(liveTarget);
    const targetContainer = typeof sidecar['targetContainer'] === 'string' ? sidecar['targetContainer'] : undefined;
    const command = typeof sidecar['command'] === 'string' ? sidecar['command'] : undefined;
    const markers = Array.isArray((liveTarget.processDecoys as Record<string, unknown> | undefined)?.['envMarkers'])
      ? ((liveTarget.processDecoys as Record<string, unknown>)['envMarkers'] as string[])
      : ['SECURITY_LAB_DECOY', 'SECURITY_LAB_CANARY'];

    if (!composeService && !targetContainer && !command) {
      return {
        result: {
          probeId: `runtime-${probe.findingId}-linux-sidecar-misconfigured`,
          findingId: probe.findingId,
          identityId: probe.identityId,
          request: { method: 'NONE', url: '', headers: {} },
          response: { status: 0, headers: {}, body: '', durationMs: 0 },
          rollbackExecuted: false,
          verdict: 'not_applicable',
          reasoning: 'Linux sidecar is configured without targetContainer or command',
        },
        coverageGap: coverageGap(
          'local-live',
          'linux_sidecar_misconfigured',
          'Linux-only runtime probes require linuxSidecar.composeService, linuxSidecar.targetContainer, or linuxSidecar.command.',
          this.isStrictVerificationEnabled() ? 'incomplete' : 'degraded',
        ),
      };
    }

    try {
      let stdout = '';
      let stderr = '';
      const startedAt = Date.now();

      if (command) {
        const [binary, ...args] = command.split(/\s+/).filter(Boolean);
        const response = await execFileAsync(binary, args, {
          env: {
            ...process.env,
            SECURITY_LAB_PROBE: JSON.stringify(probe),
            SECURITY_LAB_MARKERS: JSON.stringify(markers),
            SECURITY_LAB_WORKDIR: liveTarget.cwd ?? liveTarget.repoRoot ?? '',
          },
        });
        stdout = response.stdout;
        stderr = response.stderr;
      } else if (composeService) {
        const shellCommand = buildLinuxSidecarCommand(
          probe,
          markers,
          liveTarget.cwd ?? liveTarget.repoRoot ?? '/workspace',
        );
        const response = await execFileAsync('docker', ['compose', 'exec', '-T', composeService, 'sh', '-lc', shellCommand], {
          cwd: composeCwd,
          env: composeEnv,
        });
        stdout = response.stdout;
        stderr = response.stderr;
      } else if (targetContainer) {
        const shellCommand = buildLinuxSidecarCommand(
          probe,
          markers,
          liveTarget.cwd ?? liveTarget.repoRoot ?? '/workspace',
        );
        const response = await execFileAsync('docker', ['exec', targetContainer, 'sh', '-lc', shellCommand]);
        stdout = response.stdout;
        stderr = response.stderr;
      }

      const combined = `${stdout}\n${stderr}`.trim();
      const matchedMarker = markers.find((marker) => combined.includes(marker));
      return {
        result: {
          probeId: `runtime-${probe.findingId}-${Date.now()}`,
          findingId: probe.findingId,
          identityId: probe.identityId,
          request: { method: probe.process?.action ?? probe.persistence?.action ?? 'runtime', url: '', headers: {} },
          response: {
            status: matchedMarker ? 200 : 404,
            headers: {},
            body: combined.slice(0, 4_000),
            durationMs: Date.now() - startedAt,
          },
          rollbackExecuted: false,
          canaryMatched: matchedMarker ? 'exploitable' : 'safe',
          verdict: matchedMarker ? 'confirmed' : 'refuted',
          reasoning: matchedMarker
            ? `Linux sidecar observed marker "${matchedMarker}" while executing ${probe.process?.action ?? probe.persistence?.action}.`
            : `Linux sidecar did not observe a runtime foothold for ${probe.process?.action ?? probe.persistence?.action}.`,
        },
      };
    } catch (error) {
      return {
        result: {
          probeId: `runtime-${probe.findingId}-linux-sidecar-error`,
          findingId: probe.findingId,
          identityId: probe.identityId,
          request: { method: probe.process?.action ?? probe.persistence?.action ?? 'runtime', url: '', headers: {} },
          response: { status: 0, headers: {}, body: '', durationMs: 0 },
          rollbackExecuted: false,
          verdict: 'runtime_error',
          reasoning: error instanceof Error ? error.message : String(error),
        },
        coverageGap: coverageGap(
          'local-live',
          'linux_sidecar_execution_failed',
          `Linux sidecar execution failed for ${probe.process?.action ?? probe.persistence?.action}: ${error instanceof Error ? error.message : String(error)}`,
          this.isStrictVerificationEnabled() ? 'incomplete' : 'degraded',
        ),
      };
    }
  }

  public getLinuxSidecarComposeEnv(target: InvestigationTarget): NodeJS.ProcessEnv {
    const sidecar = (target.linuxSidecar as Record<string, unknown> | undefined) ?? {};
    const composeProjectName = typeof sidecar['composeProjectName'] === 'string' ? sidecar['composeProjectName'] : undefined;
    if (!composeProjectName) {
      return process.env;
    }
    return {
      ...process.env,
      COMPOSE_PROJECT_NAME: composeProjectName,
    };
  }

  public async buildFocusedLeadConfirmationRuntime(
    context: StageContext,
  ): Promise<FocusedLeadConfirmationRuntime> {
    if (this.config.runMode === 'smoke') {
      return {
        enabled: false,
        maxLeads: 0,
        maxProbesPerSession: 0,
        useCounterWorker: false,
        workerSessionFactory: () => async () => ({
          status: 'insufficient_evidence',
          reasoning: 'Focused confirmation is disabled in smoke mode.',
        }),
        probeExecutor: async () => ({
          probeId: 'focused-confirmation-disabled',
          verdict: 'not_applicable',
          observation: 'Focused confirmation is disabled in smoke mode.',
          confidence: 0,
          evidenceRefs: [],
          rollbackExecuted: false,
        }),
        skipReason: 'focused confirmation only runs on serious modes',
      };
    }

    if (!this.config.liveTargetRef) {
      return {
        enabled: false,
        maxLeads: 0,
        maxProbesPerSession: 0,
        useCounterWorker: false,
        workerSessionFactory: () => async () => ({
          status: 'needs_human_setup',
          reasoning: 'No live target was provided for focused lead confirmation.',
        }),
        probeExecutor: async () => ({
          probeId: 'focused-confirmation-no-live-target',
          verdict: 'coverage_gap',
          observation: 'No live target was provided for focused lead confirmation.',
          confidence: 0,
          evidenceRefs: [],
          rollbackExecuted: false,
        }),
        skipReason: 'no live target configured',
      };
    }

    const liveTarget = await loadInvestigationTarget(
      this.config.liveTargetRef,
      this.config.liveTargetId,
    );
    const verificationPolicy = this.getVerificationPolicy(liveTarget);
    // Default-on: focused lead confirmation runs for every live target unless
    // the target explicitly sets `focusedLeadConfirmationEnabled: false`.
    // A numeric `maxFocusedConfirmationLeads` still tunes the cap; if neither
    // is set, the defaults further down (maxLeads=5, maxProbesPerSession=6)
    // apply. See the recovery plan — the user's intent is that the combined
    // static→live→focused-confirmation flow is the default behaviour, not an
    // opt-in for each new target.
    const focusedConfirmationEnabled =
      verificationPolicy['focusedLeadConfirmationEnabled'] !== false;
    if (!focusedConfirmationEnabled) {
      return {
        enabled: false,
        maxLeads: 0,
        maxProbesPerSession: 0,
        useCounterWorker: false,
        workerSessionFactory: () => async () => ({
          status: 'insufficient_evidence',
          reasoning: 'Focused confirmation is explicitly disabled for this target.',
        }),
        probeExecutor: async () => ({
          probeId: 'focused-confirmation-disabled-by-policy',
          verdict: 'not_applicable',
          observation: 'Focused confirmation is explicitly disabled for this target.',
          confidence: 0,
          evidenceRefs: [],
          rollbackExecuted: false,
        }),
        skipReason: 'focused confirmation is explicitly disabled for this target',
      };
    }
    if (!liveTarget.baseUrl) {
      return {
        enabled: false,
        maxLeads: 0,
        maxProbesPerSession: 0,
        useCounterWorker: false,
        workerSessionFactory: () => async () => ({
          status: 'needs_human_setup',
          reasoning: `Live target ${liveTarget.id} has no baseUrl.`,
        }),
        probeExecutor: async () => ({
          probeId: 'focused-confirmation-no-base-url',
          verdict: 'coverage_gap',
          observation: `Live target ${liveTarget.id} has no baseUrl.`,
          confidence: 0,
          evidenceRefs: [],
          rollbackExecuted: false,
        }),
        skipReason: `live target ${liveTarget.id} has no baseUrl`,
      };
    }

    const primaryAdapter = this.getLocalLivePrimaryAdapter();
    if (!primaryAdapter || primaryAdapter.supportsNativeSessionResume !== true) {
      return {
        enabled: false,
        maxLeads: 0,
        maxProbesPerSession: 0,
        useCounterWorker: false,
        workerSessionFactory: () => async () => ({
          status: 'insufficient_evidence',
          reasoning: 'Focused confirmation requires a session-capable primary local-live adapter.',
        }),
        probeExecutor: async () => ({
          probeId: 'focused-confirmation-no-primary-worker',
          verdict: 'coverage_gap',
          observation: 'Focused confirmation requires a session-capable primary local-live adapter.',
          confidence: 0,
          evidenceRefs: [],
          rollbackExecuted: false,
        }),
        skipReason: 'primary local-live worker does not support native session resume',
      };
    }

    const counterAdapter = this.getLocalLiveCounterAdapter();
    const useCounterWorker = Boolean(
      counterAdapter && counterAdapter.supportsNativeSessionResume === true,
    );

    let localTargetSession: LocalTargetSession | null = null;
    try {
      localTargetSession = await prepareLocalTargetSession(liveTarget, context.campaignDir);
      if (localTargetSession.bootstrap) {
        await context.evidenceStore.writeJsonArtifact('focused-confirmation-local-auth-bootstrap.json', {
          target: liveTarget.id,
          envFilePath: localTargetSession.bootstrap.envFilePath,
          issuedIdentities: localTargetSession.bootstrap.issuedIdentities,
          metadata: localTargetSession.bootstrap.metadata,
        });
      }
      if (localTargetSession.started) {
        await context.evidenceStore.appendEvent('focused_confirmation_local_target_started', {
          target: liveTarget.id,
          composeOverridePath: localTargetSession.composeOverridePath ?? null,
        });
      }
    } catch (error) {
      return {
        enabled: false,
        maxLeads: 0,
        maxProbesPerSession: 0,
        useCounterWorker: false,
        workerSessionFactory: () => async () => ({
          status: 'needs_human_setup',
          reasoning: `Local target bootstrap failed: ${error instanceof Error ? error.message : String(error)}`,
        }),
        probeExecutor: async () => ({
          probeId: 'focused-confirmation-bootstrap-failed',
          verdict: 'coverage_gap',
          observation: `Local target bootstrap failed: ${error instanceof Error ? error.message : String(error)}`,
          confidence: 0,
          evidenceRefs: [],
          rollbackExecuted: false,
        }),
        skipReason: `local target bootstrap failed: ${error instanceof Error ? error.message : String(error)}`,
      };
    }

    const identities = (liveTarget.identities ?? []) as unknown as IdentitySpec[];
    const canaries = (liveTarget.canaries ?? []) as unknown as CanarySpec[];
    const runtimeIdentityEnv = {
      ...process.env,
      ...(localTargetSession?.bootstrap?.identityEnv ?? {}),
    };
    const identityLadder = new IdentityLadder(
      identities,
      runtimeIdentityEnv,
      liveTarget.authMechanism?.tenantHeader,
    );
    const liveLimit = (liveTarget.liveProbing as Record<string, unknown> | undefined)?.['rateLimit'] as Record<string, unknown> | undefined;
    const rateLimiter = new RateLimiter({
      requestsPerSecond: Number(liveLimit?.['requestsPerSecond'] ?? 10),
      maxRequestsPerCampaign: Number(liveLimit?.['requestsPerCampaign'] ?? 1000),
      autoStopOn5xxStreak: Number(((liveTarget.liveProbing as Record<string, unknown> | undefined)?.['autoStop'] as Record<string, unknown> | undefined)?.['consecutive5xx'] ?? 5),
      autoStopOnLatencyDoubling: true,
    });
    const mutationJournal = new MutationJournal();
    const allowMutations = Boolean(
      this.config.allowLocalMutations || this.shouldAutoEnableLocalMutations(liveTarget),
    );

    const entityInventory: EntityInventory = context.memory.entityInventory ?? createEmptyInventory();
    context.memory.entityInventory = entityInventory;

    {
      const SeedDataSchema = z.object({
        tenants: z.array(z.object({ id: z.string(), metadata: z.record(z.unknown()).optional() })).optional(),
        records: z.array(z.object({ id: z.string(), tenantId: z.string(), type: z.string().optional(), metadata: z.record(z.unknown()).optional() })).optional(),
      });
      const parsed = liveTarget.seedData ? SeedDataSchema.safeParse(liveTarget.seedData) : null;
      const sd = parsed?.success ? parsed.data : undefined;
      if (sd) {
        const seeded: Parameters<typeof seedEntities>[1] = [];
        for (const tenant of sd.tenants ?? []) {
          seeded.push({
            kind: 'tenant_id',
            value: tenant.id,
            provenance: 'seeded',
            parameterName: ':tenantId',
            discoveredDuring: 'target_profile',
            metadata: tenant.metadata,
          });
        }
        for (const record of sd.records ?? []) {
          seeded.push({
            kind: 'resource_id',
            value: record.id,
            provenance: 'seeded',
            parameterName: ':id',
            discoveredDuring: 'target_profile',
            metadata: { tenantId: record.tenantId, type: record.type, ...record.metadata },
          });
        }
        if (seeded.length > 0) {
          seedEntities(entityInventory, seeded);
        }
      }
    }

    if (localTargetSession?.bootstrap) {
      const bsMeta = localTargetSession.bootstrap.metadata as Record<string, unknown> | undefined;
      if (bsMeta) {
        const bootstrapped: Parameters<typeof seedEntities>[1] = [];
        for (const [key, value] of Object.entries(bsMeta)) {
          if (typeof value === 'string' && value.length > 0) {
            const kind = key.toLowerCase().includes('company') ? 'company_id' : 'user_id';
            const paramName = key.toLowerCase().includes('company') ? ':companyId' : ':userId';
            bootstrapped.push({
              kind,
              value,
              provenance: 'minted',
              parameterName: paramName,
              identityId: localTargetSession.bootstrap.issuedIdentities[0] ?? 'bootstrap',
              discoveredDuring: 'auth_bootstrap',
            });
          }
        }
        if (bootstrapped.length > 0) {
          seedEntities(entityInventory, bootstrapped);
        }
      }
    }

    const maxLeads =
      typeof verificationPolicy['maxFocusedConfirmationLeads'] === 'number'
        ? Math.max(1, Math.min(20, Number(verificationPolicy['maxFocusedConfirmationLeads'])))
        : Math.min(5, this.resolveVerificationHypothesisLimit(liveTarget));
    const maxProbesPerSession =
      typeof verificationPolicy['maxFocusedConfirmationProbesPerSession'] === 'number'
        ? Math.max(1, Math.min(20, Number(verificationPolicy['maxFocusedConfirmationProbesPerSession'])))
        : 6;

    return {
      enabled: true,
      maxLeads,
      maxProbesPerSession,
      useCounterWorker,
      workerSessionFactory: (hypothesisId: string) =>
        this.buildFocusedLeadWorkerSession({
          context,
          liveTarget,
          hypothesisId,
          primaryAdapter,
          counterAdapter: useCounterWorker ? counterAdapter : undefined,
          requestTimeoutMs: this.resolveModelRequestTimeoutMs(liveTarget, 'local-live'),
        }),
      probeExecutor: this.buildFocusedLeadProbeExecutor({
        context,
        liveTarget,
        identityLadder,
        rateLimiter,
        mutationJournal,
        allowMutations,
        canaries,
        entityInventory,
      }),
      cleanup: async () => {
        await localTargetSession?.stop();
      },
    };
  }

  private buildFocusedLeadWorkerSession(args: {
    context: StageContext;
    liveTarget: InvestigationTarget;
    hypothesisId: string;
    primaryAdapter: ModelAdapter;
    counterAdapter?: ModelAdapter;
    requestTimeoutMs: number;
  }): FocusedLeadWorkerSession {
    return async (
      brief: LeadBrief,
      requestProbe,
      role,
    ) => {
      const adapter = role === 'counter'
        ? args.counterAdapter ?? args.primaryAdapter
        : args.primaryAdapter;
      const roleName = role === 'counter' ? 'local_live_counter' : 'local_live_primary';
      const roleLabel = role === 'counter' ? 'counter_planner' : 'planner';
      const appender = role === 'counter'
        ? args.context.roleSessions.appendCounterPlannerEntry.bind(args.context.roleSessions)
        : args.context.roleSessions.appendPlannerEntry.bind(args.context.roleSessions);
      const inspectFirst = this.resolveFocusedLeadInspectPaths(args.liveTarget, brief);
      const observedResults: FocusedLeadProbeExecutionResult[] = [];
      let latestStatus: ConfirmationStatus = 'insufficient_evidence';
      let latestReasoning = 'Focused confirmation did not gather enough evidence.';

      for (let turn = 1; turn <= 3; turn += 1) {
        const scopeId = `${brief.hypothesisId}-${role}-turn-${turn}`;
        const manifest = await args.context.roleSessions.writeBriefManifest({
          role: `focused-${role}`,
          scopeId,
          iteration: args.context.state.iteration + 1,
          whatToDecide: turn === 1
            ? 'Read the lead brief and the referenced source files. Request the precise probes needed to confirm or refute the lead. If the lead already collapses under source inspection alone, return refuted or narrowed without requesting probes.'
            : 'Read the prior probe results and decide whether you need more evidence. Request follow-up probes only when they materially reduce uncertainty; otherwise conclude with a bounded status.',
          outputSchemaReminder:
            'Return ONLY valid JSON with keys: status, reasoning, probeRequests[]. ' +
            'Each probe request must include probeKind, identityId, rationale, and the relevant http/process/persistence block when applicable.',
          evidence: [
            { name: 'lead-brief.md', content: renderBriefForWorker(brief) },
            { name: 'lead-brief.json', content: JSON.stringify(brief, null, 2) },
            { name: 'probe-results.md', content: formatFocusedProbeResults(observedResults) },
          ],
          inspectFirst,
        });

        const evidencePointers = manifest.evidencePaths;
        const prompt = [
          `You are the Security Lab focused confirmation worker.`,
          `Role: ${role}. Hypothesis: ${brief.hypothesisId}. Turn: ${turn}.`,
          '',
          `Read your brief first: ${manifest.briefPath}`,
          '',
          'Then read every evidence pointer listed in the brief and inspect the suggested source files directly.',
          '',
          'Return JSON only. Do not execute live probes yourself; request them through probeRequests.',
        ].join('\n');

        const invocation = await withHeartbeat(
          adapter.invoke({
            ...this.buildInvokeOptions<FocusedWorkerTurn>(
              args.context.state,
              args.liveTarget,
              roleName,
              adapter,
              brief.hypothesisId,
              args.requestTimeoutMs,
            ),
            systemPrompt: FOCUSED_CONFIRMATION_WORKER_CONTRACT,
            prompt,
            temperature: 0,
            maxTokens: 8192,
            briefMode: {
              briefPath: manifest.briefPath,
              artifactsDir: args.context.campaignDir,
              scopeId,
              evidencePointers,
            },
          }),
          {
            stage: 'focused_lead_confirmation',
            role: roleName,
            intervalMs: this.config.heartbeatIntervalMs,
            expectedTimeoutMs: args.requestTimeoutMs,
            emit: async (stage, payload) => {
              await args.context.evidenceStore.appendEvent(stage, payload);
            },
          },
        );

        const parsed = parseFocusedWorkerTurn(invocation.content);
        latestStatus = parsed.status;
        latestReasoning = parsed.reasoning;

        const sessionKey = this.getRoleSessionKey(roleName, adapter, brief.hypothesisId);
        this.recordModelInvocation(
          args.context.telemetry,
          args.context.state,
          args.context.memory,
          role === 'counter' ? 'counter_plan' : 'plan',
          invocation,
          sessionKey,
        );
        await this.checkpointVolatileState(args.context.stateStore, args.context.state);

        if (args.context.archiver) {
          await args.context.archiver.archive(
            role === 'counter' ? 'counter_planner' : 'planner',
            FOCUSED_CONFIRMATION_WORKER_CONTRACT,
            prompt,
            invocation,
            invocation.structured != null,
          );
        }

        await this.appendRoleEntry(appender, {
          role: roleName,
          iteration: args.context.state.iteration + 1,
          provider: invocation.provider,
          model: invocation.model,
          summary: `${brief.hypothesisId} turn ${turn}: ${latestStatus}; ${parsed.probeRequests.map(summarizeFocusedRequest).join(', ')}`.slice(0, 400),
          evidenceRefs: [brief.hypothesisId, ...brief.decisiveSignals.map((signal) => signal.id)].slice(0, 20),
          response: invocation,
        });

        if (parsed.probeRequests.length === 0) {
          return { status: latestStatus, reasoning: latestReasoning };
        }

        for (const probeRequest of parsed.probeRequests) {
          const result = await requestProbe({
            hypothesisId: brief.hypothesisId,
            rationale: probeRequest.rationale,
            probe: {
              findingId: brief.hypothesisId,
              hypothesis: brief.hypothesis,
              probeKind: probeRequest.probeKind,
              identityId: probeRequest.identityId,
              rationale: probeRequest.rationale,
              probeFamily: probeRequest.probeFamily ?? brief.suggestedProbeFamily,
              probeVariant: probeRequest.probeVariant,
              http: probeRequest.http,
              process: probeRequest.process,
              persistence: probeRequest.persistence,
              expectedWhenSafe: probeRequest.expectedWhenSafe,
              expectedWhenExploitable: probeRequest.expectedWhenExploitable,
            },
            isFollowUp: turn > 1,
          });
          observedResults.push(result);
        }
      }

      return { status: latestStatus, reasoning: latestReasoning };
    };
  }

  private buildFocusedLeadProbeExecutor(args: {
    context: StageContext;
    liveTarget: InvestigationTarget;
    identityLadder: IdentityLadder;
    rateLimiter: RateLimiter;
    mutationJournal: MutationJournal;
    allowMutations: boolean;
    canaries: CanarySpec[];
    entityInventory: EntityInventory;
  }): FocusedLeadProbeExecutor {
    return async (request): Promise<FocusedLeadProbeExecutionResult> => {
      const probe = request.probe;
      if (probe.probeKind === 'browser') {
        return {
          probeId: `focused-${request.hypothesisId}-browser`,
          verdict: 'not_applicable',
          observation: 'Browser confirmation is not routed through focused lead confirmation; return needs_browser for this lead.',
          confidence: 0,
          evidenceRefs: [],
          rollbackExecuted: false,
        };
      }

      if (probe.probeKind === 'process' || probe.probeKind === 'persistence') {
        const runtime = await this.executeRuntimeProbeWithLinuxFallback(args.liveTarget, probe);
        if (runtime.coverageGap) {
          this.recordProbeCoverageGap({
            lane: runtime.coverageGap.lane,
            code: runtime.coverageGap.code,
            message: runtime.coverageGap.message,
            severity: runtime.coverageGap.severity,
            findingId: request.hypothesisId,
            identityId: probe.identityId,
          });
          await args.context.evidenceStore.appendEvent(
            'focused_confirmation_coverage_gap',
            runtime.coverageGap as unknown as Record<string, unknown>,
          );
        }
        const result = runtime.result;
        return {
          probeId: result.probeId,
          verdict: result.verdict,
          observation: result.reasoning,
          confidence: result.verdict === 'confirmed' || result.verdict === 'refuted' ? 0.85 : 0.5,
          evidenceRefs: [result.probeId],
          rollbackExecuted: result.rollbackExecuted,
        };
      }

      const result = await executeLiveProbe(probe, {
        baseUrl: args.liveTarget.baseUrl!,
        identityLadder: args.identityLadder,
        rateLimiter: args.rateLimiter,
        mutationJournal: args.mutationJournal,
        canaries: args.canaries,
        allowMutations: args.allowMutations,
        dryRunMutations: this.config.dryRunMutations,
        // Policy gate also lives inside executeLiveProbe; passing it here keeps
        // the lanes in step if a future caller forgets.
        runtime: this.runtime,
        runtimeTargetContext: buildRuntimeTargetContext(args.liveTarget),
        mode: this.config.mode,

        strictProbes: this.config.strictProbes,
        entityInventory: args.entityInventory,
        onEvent: async (stage, payload) => {
          if (stage === 'coverage_gap') {
            this.recordProbeCoverageGap(payload as unknown as Record<string, unknown>);
          }
          await args.context.evidenceStore.appendEvent(
            stage,
            payload as unknown as Record<string, unknown>,
          );
        },
      });

      return {
        probeId: result.probeId,
        verdict: result.verdict,
        observation: `${result.request.method} ${result.request.url} -> ${result.response.status}; ${result.reasoning}`,
        confidence: result.verdict === 'confirmed' || result.verdict === 'refuted' ? 0.85 : 0.5,
        evidenceRefs: [result.probeId],
        rollbackExecuted: result.rollbackExecuted,
      };
    };
  }

  private resolveFocusedLeadInspectPaths(
    liveTarget: InvestigationTarget,
    brief: LeadBrief,
  ): string[] {
    const repoRoot = liveTarget.repoRoot ?? liveTarget.cwd;
    if (!repoRoot) return [];

    const resolved = new Set<string>();
    const maybeAdd = (relativePath: string | undefined): void => {
      if (!relativePath) return;
      const candidate = resolve(repoRoot, relativePath);
      try {
        if (candidate && statSync(candidate).isFile()) {
          resolved.add(candidate);
        }
      } catch {
        // ignore non-file references like routes/endpoints
      }
    };

    for (const ref of brief.sourceRefs) {
      maybeAdd(ref.path);
    }
    for (const asset of brief.relatedAssets) {
      maybeAdd(asset);
    }
    return [...resolved].slice(0, 12);
  }

  // Section 5.1: runTestSynthesisLane body was moved to
  // `stages/test-synthesis.ts` (exported as `runTestSynthesisLaneImpl`).
  // This runner method is retained as a thin delegate so that the rest of
  // the runner can still call it at the same call site.

  // ── runLocalLiveLane ──

  public async runLocalLiveLane(
    args: {
      target: InvestigationTarget;
      memory: CampaignMemory;
      state: InvestigationState;
      stateStore: StateStore;
      evidenceStore: EvidenceStore;
      campaignDir: string;
      telemetry: ReturnType<typeof createAccumulator>;
      roleSessions: RoleSessionStore;
      archiver: ResponseArchiver | null;
    },
    experimentStore: { record: (experiment: VerificationExperiment) => Promise<void> },
  ): Promise<NonNullable<VerificationLanesSummary['localLive']>> {
    const startedAt = Date.now();
    const summary = createLaneSummary(this.laneRequired(args.target, 'local-live'));
    const portfolio = this.config.portfolioProfile ?? getDefaultProfile();
    if (!this.config.liveTargetRef) {
      summary.skipped += 1;
      if (summary.required) {
        addLaneCoverageGap(summary, 'Local-live verification was required but no --live-target was provided.', 'incomplete');
      }
      summary.durationMs = Date.now() - startedAt;
      await args.evidenceStore.appendEvent('verification_local_live_skipped', {
        reason: 'no --live-target provided',
        required: summary.required,
      });
      return summary;
    }

    const liveTarget = await loadInvestigationTarget(this.config.liveTargetRef, this.config.liveTargetId);
    if (!liveTarget.baseUrl) {
      addLaneCoverageGap(summary, `Live target ${liveTarget.id} has no baseUrl.`, summary.required ? 'incomplete' : 'degraded');
      summary.durationMs = Date.now() - startedAt;
      await args.evidenceStore.appendEvent('verification_local_live_skipped', {
        reason: 'live target has no baseUrl',
        target: liveTarget.id,
      });
      return summary;
    }

    for (const gap of await this.preflightTargetCoverage(liveTarget, 'local-live')) {
      addLaneCoverageGap(summary, gap.message, gap.severity);
    }

    let localTargetSession: Awaited<ReturnType<typeof prepareLocalTargetSession>> | null = null;
    try {
      localTargetSession = await prepareLocalTargetSession(liveTarget, args.campaignDir);
      if (localTargetSession.bootstrap) {
        await args.evidenceStore.writeJsonArtifact('local-auth-bootstrap.json', {
          target: liveTarget.id,
          envFilePath: localTargetSession.bootstrap.envFilePath,
          issuedIdentities: localTargetSession.bootstrap.issuedIdentities,
          metadata: localTargetSession.bootstrap.metadata,
        });
        await args.evidenceStore.appendEvent('local_auth_bootstrap_prepared', {
          target: liveTarget.id,
          issuedIdentities: localTargetSession.bootstrap.issuedIdentities,
          envFilePath: localTargetSession.bootstrap.envFilePath ?? null,
        });
      }
      if (localTargetSession.started) {
        await args.evidenceStore.appendEvent('local_target_started', {
          target: liveTarget.id,
          composeOverridePath: localTargetSession.composeOverridePath ?? null,
        });
        if (localTargetSession.warnings?.length) {
          await args.evidenceStore.appendEvent('local_target_started_with_warnings', {
            target: liveTarget.id,
            warnings: localTargetSession.warnings,
          });
        }
      }
    } catch (error) {
      addLaneCoverageGap(
        summary,
        `Local-live target bootstrap/startup failed for ${liveTarget.id}: ${error instanceof Error ? error.message : String(error)}`,
        summary.required ? 'incomplete' : 'degraded',
      );
      summary.durationMs = Date.now() - startedAt;
      await args.evidenceStore.appendEvent('verification_local_live_incomplete', {
        target: liveTarget.id,
        coverageGaps: summary.coverageGaps,
      });
      return summary;
    }

    const identities = (liveTarget.identities ?? []) as unknown as IdentitySpec[];
    const canaries = (liveTarget.canaries ?? []) as unknown as CanarySpec[];
    const runtimeIdentityEnv = {
      ...process.env,
      ...(localTargetSession?.bootstrap?.identityEnv ?? {}),
    };
    const identityLadder = new IdentityLadder(identities, runtimeIdentityEnv, liveTarget.authMechanism?.tenantHeader);
    const missingIdentities = this.getMissingIdentityRequirements(liveTarget, identityLadder);
    if (missingIdentities.length > 0) {
      addLaneCoverageGap(
        summary,
        `Missing required local-live identities: ${missingIdentities.join(', ')}.`,
        summary.required ? 'incomplete' : 'degraded',
      );
    }

    const liveLimit = (liveTarget.liveProbing as Record<string, unknown> | undefined)?.['rateLimit'] as Record<string, unknown> | undefined;
    const rateLimiter = new RateLimiter({
      requestsPerSecond: Number(liveLimit?.['requestsPerSecond'] ?? 10),
      maxRequestsPerCampaign: Number(liveLimit?.['requestsPerCampaign'] ?? 1000),
      autoStopOn5xxStreak: Number(((liveTarget.liveProbing as Record<string, unknown> | undefined)?.['autoStop'] as Record<string, unknown> | undefined)?.['consecutive5xx'] ?? 5),
      autoStopOnLatencyDoubling: true,
    });
    const mutationJournal = new MutationJournal();
    const allowMutations = Boolean(this.config.allowLocalMutations || this.shouldAutoEnableLocalMutations(liveTarget));
    if (!this.getLocalLivePrimaryAdapter()) {
      addLaneCoverageGap(
        summary,
        'Model-backed live probe translation is unavailable; falling back to deterministic verification probe generation from stored hypotheses.',
        'degraded',
      );
    }

    const runtimeProbes = this.buildRuntimeSurfaceProbes(liveTarget);
    const linuxOnlyRequested = runtimeProbes.some((probe) => this.isLinuxOnlyRuntimeProbe(probe));
    if (linuxOnlyRequested) {
      const linuxRuntime = await this.checkLinuxRuntimeAvailability(liveTarget);
      if (!linuxRuntime.available) {
        addLaneCoverageGap(
          summary,
          `Linux-only runtime probes could not run: ${linuxRuntime.reason ?? 'linux execution unavailable'}.`,
          summary.required ? 'incomplete' : 'degraded',
        );
      }
    }

    if (summary.status === 'incomplete' && summary.required && !this.config.allowDegraded) {
      summary.durationMs = Date.now() - startedAt;
      await args.evidenceStore.appendEvent('verification_local_live_incomplete', {
        target: liveTarget.id,
        coverageGaps: summary.coverageGaps,
      });
      await localTargetSession?.stop();
      return summary;
    }

    // Section 6.1 — response-driven adaptive exploration configuration.
    const targetAdaptiveConfig = resolveAdaptiveExplorationConfig(liveTarget);
    const adaptiveEnabled =
      targetAdaptiveConfig.enabled && !this.config.disableAdaptiveExploration;

    // Section 6.2 — Mythos creativity sub-lane configuration. Falls back to
    // the target-profile config, then applies CLI overrides. In serious run
    // modes without an explicit target setting we default-enable Mythos so
    // the creativity lane fires on the serious path.
    const mythosConfig = this.resolveMythosConfigForCampaign(liveTarget);
    const mythosRunBudget = { invocationsLeft: mythosConfig.invocationsPerCampaign };
    const sourceCorrelationBudget = new SourceCorrelationBudget(mythosConfig.sourceCorrelationMax);
    const sourceCorrelationWorker = new SourceCorrelationWorker(
      mythosConfig.sourceCorrelationEnabled ? this.getLocalLivePrimaryAdapter() : undefined,
      sourceCorrelationBudget,
    );
    const probeHistory: ProbeHistoryEntry[] = [];
    const mythosTally = {
      enabled: mythosConfig.enabled,
      invocations: 0,
      probesExecuted: 0,
      hypothesesProposed: 0,
      findingsProposed: 0,
      findingsRejected: 0,
      nonHypothesisProbes: 0,
      budgetExhausted: null as 'probe_budget_exhausted' | 'time_budget_exhausted' | null,
      sourceCorrelations: 0,
      sourceRefsCollected: 0,
    };
    summary.mythos = mythosTally;

    // Section 8.2 — monitoring stress round summary, accumulated across
    // all probes in the local-live lane when monitoring stress mode is on.
    const monitoringStressEnabled = Boolean(this.config.monitoringStress);
    const monitoringStressRoundSummary = monitoringStressEnabled
      ? createEmptyRoundSummary()
      : null;

    await args.evidenceStore.appendEvent('mythos_config', {
      enabled: mythosConfig.enabled,
      timeBudgetMs: mythosConfig.timeBudgetMs,
      probeBudget: mythosConfig.probeBudget,
      invocationsPerCampaign: mythosConfig.invocationsPerCampaign,
      sourceCorrelationEnabled: mythosConfig.sourceCorrelationEnabled,
      sourceCorrelationMax: mythosConfig.sourceCorrelationMax,
    });
    summary.adaptiveProbes = {
      hypothesis: { attempted: 0, confirmed: 0, refuted: 0, inconclusive: 0 },
      adaptive: { attempted: 0, confirmed: 0, refuted: 0, inconclusive: 0 },
      canary: { attempted: 0, matchedSafe: 0, matchedExploitable: 0 },
      surprisesDetected: 0,
      followupsGenerated: 0,
      midRoundHypothesesSynthesized: 0,
    };
    await args.evidenceStore.appendEvent('verification_local_live_adaptive_config', {
      enabled: adaptiveEnabled,
      maxFollowupsPerSurprise: targetAdaptiveConfig.maxFollowupsPerSurprise,
      maxMidRoundHypotheses: targetAdaptiveConfig.maxMidRoundHypotheses,
      disabledByFlag: Boolean(this.config.disableAdaptiveExploration),
    });

    const tallyResultsByOrigin = (
      results: Array<Awaited<ReturnType<typeof executeLiveProbeBatch>>[number]>,
    ): void => {
      const tally = summary.adaptiveProbes!;
      for (const result of results) {
        const origin = result.origin ?? 'hypothesis';
        if (origin === 'canary') {
          tally.canary.attempted += 1;
          if (result.canaryMatched === 'safe') tally.canary.matchedSafe += 1;
          if (result.canaryMatched === 'exploitable') tally.canary.matchedExploitable += 1;
          continue;
        }
        // Mythos-origin probes are tallied through `mythosTally` rather
        // than the adaptive bucket — skip them here so the adaptive
        // histogram only reflects the adaptive exploration sub-system.
        if (origin === 'mythos') continue;
        const bucket = origin === 'adaptive' ? tally.adaptive : tally.hypothesis;
        bucket.attempted += 1;
        if (result.verdict === 'confirmed') bucket.confirmed += 1;
        else if (result.verdict === 'refuted') bucket.refuted += 1;
        else if (result.verdict === 'inconclusive') bucket.inconclusive += 1;
      }
    };

    // Section 11.1 — Initialize entity inventory from campaign memory or create new.
    const entityInventory: EntityInventory = args.memory.entityInventory ?? createEmptyInventory();
    args.memory.entityInventory = entityInventory;

    // Section 11.1 — seed from target profile seed data (tenants, records).
    // Validated with Zod at this trust boundary per SL1.
    {
      const SeedDataSchema = z.object({
        tenants: z.array(z.object({ id: z.string(), metadata: z.record(z.unknown()).optional() })).optional(),
        records: z.array(z.object({ id: z.string(), tenantId: z.string(), type: z.string().optional(), metadata: z.record(z.unknown()).optional() })).optional(),
      });
      const parsed = liveTarget.seedData ? SeedDataSchema.safeParse(liveTarget.seedData) : null;
      const sd = parsed?.success ? parsed.data : undefined;
      if (sd) {
        const seeded: Parameters<typeof seedEntities>[1] = [];
        for (const tenant of sd.tenants ?? []) {
          seeded.push({
            kind: 'tenant_id',
            value: tenant.id,
            provenance: 'seeded',
            parameterName: ':tenantId',
            discoveredDuring: 'target_profile',
            metadata: tenant.metadata,
          });
        }
        for (const record of sd.records ?? []) {
          seeded.push({
            kind: 'resource_id',
            value: record.id,
            provenance: 'seeded',
            parameterName: ':id',
            discoveredDuring: 'target_profile',
            metadata: { tenantId: record.tenantId, type: record.type, ...record.metadata },
          });
        }
        if (seeded.length > 0) {
          seedEntities(entityInventory, seeded);
          await args.evidenceStore.appendEvent(ENTITY_INVENTORY_EVENT_STAGES.ENTITY_INVENTORY_SEEDED, {
            count: seeded.length,
            kinds: [...new Set(seeded.map((e) => e.kind))],
            source: 'target_profile',
          });
        }
      }
    }

    // Section 11.1 — seed from auth bootstrap results (issued identities → user/company IDs).
    if (localTargetSession?.bootstrap) {
      const bsMeta = localTargetSession.bootstrap.metadata as Record<string, unknown> | undefined;
      if (bsMeta) {
        const bootstrapped: Parameters<typeof seedEntities>[1] = [];
        for (const [key, value] of Object.entries(bsMeta)) {
          if (typeof value === 'string' && value.length > 0) {
            const kind = key.toLowerCase().includes('company') ? 'company_id' : 'user_id';
            const paramName = key.toLowerCase().includes('company') ? ':companyId' : ':userId';
            bootstrapped.push({
              kind,
              value,
              provenance: 'minted',
              parameterName: paramName,
              identityId: localTargetSession.bootstrap.issuedIdentities[0] ?? 'bootstrap',
              discoveredDuring: 'auth_bootstrap',
            });
          }
        }
        if (bootstrapped.length > 0) {
          seedEntities(entityInventory, bootstrapped);
          await args.evidenceStore.appendEvent(ENTITY_INVENTORY_EVENT_STAGES.ENTITY_INVENTORY_SEEDED, {
            count: bootstrapped.length,
            kinds: [...new Set(bootstrapped.map((e) => e.kind))],
            source: 'auth_bootstrap',
          });
        }
      }
    }

    const canaryProbes = this.buildLocalCanaryProbes(canaries, identities);
    const packetQueue = this.buildVerificationPackets(args.memory, liveTarget);
    const seenPacketHypothesisIds = new Set(packetQueue.map((packet) => packet.hypothesis.id));
    await args.evidenceStore.writeJsonArtifact('verification-local-live-packets.json', packetQueue.map((packet) => ({
      id: packet.id,
      hypothesisId: packet.hypothesis.id,
      severity: packet.hypothesis.severity,
      signalIds: packet.hypothesis.signalIds,
      relatedAssets: packet.relatedAssets,
    })));

    // Section 11.3 — classification reason tracking for the report.
    const classificationReasonCounts: Record<string, number> = {};
    const classificationRouteKindCounts: Record<string, number> = {};
    let classificationTotalClassified = 0;
    let classificationSuppressedCount = 0;

    // Section 11.4 — sequence and identity-differential tracking.
    const sequenceSummary: SequenceExecutionSummary = {
      sequencesExecuted: 0,
      totalStepsExecuted: 0,
      sequencesConfirmed: 0,
      sequencesRefuted: 0,
      sequencesInconclusive: 0,
      differentialsExecuted: 0,
      differentialsWithEscalation: 0,
      statePassthroughCount: 0,
      rollbacksExecuted: 0,
    };

    const recordResults = async (
      results: Array<Awaited<ReturnType<typeof executeLiveProbeBatch>>[number]>,
      packet: VerificationPacket | null,
      round: number,
    ): Promise<{ summaries: string[]; signalIds: string[] }> => {
      for (const result of results) {
        summary.attempted += 1;
        // Section 11.3 — use classification-aware meaningful attempt accounting
        const isMeaningful = result.classification?.isMeaningfulAttempt;
        countLaneVerdictWithClassification(summary, result.verdict, isMeaningful);
        // Track classification reasons for the report
        if (result.classification) {
          classificationTotalClassified += 1;
          const reason = result.classification.reason;
          classificationReasonCounts[reason] = (classificationReasonCounts[reason] ?? 0) + 1;
          const rk = result.classification.routeKind;
          classificationRouteKindCounts[rk] = (classificationRouteKindCounts[rk] ?? 0) + 1;
          if (!result.classification.isMeaningfulAttempt) {
            classificationSuppressedCount += 1;
          }
        }
        await experimentStore.record({
          experimentId: `exp-local_live-${result.probeId}`,
          findingId: result.findingId,
          route: 'local_live',
          at: new Date().toISOString(),
          hypothesis: packet?.hypothesis.description ?? result.findingId,
          identityContext: result.identityId,
          prerequisites: [liveTarget.id],
          intervention: `${result.request.method} ${result.request.url}`,
          expectedSafeOutcome: 'Canary matches safe path or no runtime foothold is found',
          expectedExploitableOutcome: 'Canary matches exploitable path or runtime foothold is confirmed',
          rollbackPlan: mutationJournal.getPendingRollbacks().length > 0 ? 'mutation journal rollback' : undefined,
          rollbackExecuted: false,
          actualObservation: result.reasoning,
          verdict: result.verdict,
          confidence: result.verdict === 'confirmed' || result.verdict === 'refuted' ? 0.8 : 0.5,
          evidenceRefs: [result.probeId],
        });
      }
      const runtimeSignals: { summaries: string[]; signalIds: string[] } = packet
        ? this.collectRuntimeSignalsFromLiveResults(args.memory, liveTarget, packet, results)
        : { summaries: [], signalIds: [] };
      await args.evidenceStore.appendEvent('verification_local_live_round', {
        packetId: packet?.id ?? 'canaries',
        hypothesisId: packet?.hypothesis.id ?? null,
        round,
        resultCount: results.length,
        runtimeSignals: runtimeSignals.summaries,
      });
      return runtimeSignals;
    };

    const liveReplayEventHandler: NonNullable<LiveReplayOptions['onEvent']> = (stage, payload) => {
      void args.evidenceStore
        .appendEvent(stage, payload as unknown as Record<string, unknown>)
        .catch((error: unknown) => {
          // Never let a dropped evidence write become an unhandled rejection that
          // kills the process mid-campaign without a failure record.
          process.stderr.write(
            `[security-lab] failed to record event "${stage}": ${error instanceof Error ? error.message : String(error)}\n`,
          );
        });
      if (stage === 'coverage_gap') {
        this.recordProbeCoverageGap(payload as unknown as Record<string, unknown>);
      }
    };

    // Section 12.2 — browser exploit family accumulator. Declared here
    // so it's available after the try/finally for summary attachment.
    const browserExploitSummary = emptyBrowserExploitFamilySummary();

    try {
      if (canaryProbes.length > 0) {
        const canaryResults = await executeLiveProbeBatch(canaryProbes, {
          baseUrl: liveTarget.baseUrl,
          identityLadder,
          rateLimiter,
          mutationJournal,
          canaries,
          allowMutations,
          dryRunMutations: this.config.dryRunMutations,
          strictProbes: this.config.strictProbes,
          onEvent: liveReplayEventHandler,
          entityInventory,
          // Canary probes are live requests: they pass the same policy gate.
          runtime: this.runtime,
          runtimeTargetContext: buildRuntimeTargetContext(liveTarget),
          mode: this.config.mode,
        });
        for (const cr of canaryResults) { cr.origin = 'canary'; }
        tallyResultsByOrigin(canaryResults);
        await recordResults(canaryResults, null, 0);
      }

      if (runtimeProbes.length > 0) {
        const runtimeResults = [];
        for (const probe of runtimeProbes) {
          const probeKind = probe.probeKind === 'process' ? 'process_check' : 'persistence_check';
          const decision = this.runtime.authorizeProbe(this.config.mode, {
            id: liveTarget.id,
            kind: 'hybrid',
            environment: liveTarget.environment,
            cwd: liveTarget.cwd,
          }, {
            kind: probeKind,
            timeoutMs: 10_000,
          });
          if (!decision.allowed) {
            summary.blocked += 1;
            await args.evidenceStore.appendEvent('verification_local_live_blocked', {
              findingId: probe.findingId,
              reason: decision.reason,
              probeKind,
            });
            continue;
          }
          const runtimeExecution = await this.executeRuntimeProbeWithLinuxFallback(liveTarget, probe);
          if (runtimeExecution.coverageGap) {
            addLaneCoverageGap(summary, runtimeExecution.coverageGap.message, runtimeExecution.coverageGap.severity);
          }
          runtimeResults.push(runtimeExecution.result);
        }
        await recordResults(runtimeResults, null, 0);
      }

      // Section 12.2 — browser-native exploit verification families.
      // When the target declares browser capability, classify hypotheses
      // into browser families and dispatch browser probes before the
      // model-backed HTTP round loop. Browser probes run independently
      // because they need a full Playwright session, not HTTP replay.
      if (liveTarget.browser?.enabled && liveTarget.baseUrl) {
        const browserFamilies = resolveTargetBrowserFamilies(
          true,
          (liveTarget.liveProbing as Record<string, unknown> | undefined)?.['browserFamilies'] as unknown[] | undefined,
        );
        const browserFamilyIds = new Set(browserFamilies.map((f) => f.family));
        const disabledVariantsByFamily = new Map(
          browserFamilies
            .filter((f) => f.disabledVariants)
            .map((f) => [f.family, new Set(f.disabledVariants)]),
        );

        const browserProbeRequests: BrowserProbeRequest[] = [];
        for (const packet of packetQueue) {
          const browserFamilyId = classifyBrowserHypothesis(packet.hypothesis.description);
          if (!browserFamilyId || !browserFamilyIds.has(browserFamilyId)) continue;

          const familyDef = getBrowserFamilyDefinition(browserFamilyId);
          if (!familyDef) continue;

          const disabled = disabledVariantsByFamily.get(browserFamilyId);
          const familyCapability = browserFamilies.find((f) => f.family === browserFamilyId);

          for (const variant of familyDef.defaultVariants) {
            if (disabled?.has(variant.key)) continue;

            browserProbeRequests.push({
              findingId: packet.hypothesis.id,
              hypothesis: packet.hypothesis.description,
              family: browserFamilyId,
              variant: variant.key,
              targetBaseUrl: liveTarget.baseUrl,
              targetPath: packet.relatedAssets?.[0] ?? '/',
              sessionCookieName: familyCapability?.sessionCookieName,
              websocketPath: familyCapability?.websocketPath,
              xssDomSelector: familyCapability?.xssDomSelector,
            });
          }
        }

        if (browserProbeRequests.length > 0) {
          await args.evidenceStore.appendEvent('browser_exploit_families_started', {
            target: liveTarget.id,
            probeCount: browserProbeRequests.length,
            families: [...new Set(browserProbeRequests.map((r) => r.family))],
          });

          // Use a stub launcher — real Playwright launcher is injected at
          // the investigation-runner level. When no launcher is available,
          // the probes degrade to runtime_error with an honest message.
          const browserLauncher: BrowserLauncher = (this as unknown as { browserLauncher?: BrowserLauncher }).browserLauncher
            ?? (async () => { throw new Error('No browser launcher configured — install Playwright to enable browser probes'); });

          for (const request of browserProbeRequests) {
            const result = await executeBrowserProbe(
              request,
              browserLauncher,
              args.campaignDir,
              // Browser probes are live requests; they pass the policy gate too.
              {
                runtime: this.runtime,
                runtimeTargetContext: buildRuntimeTargetContext(liveTarget),
                mode: this.config.mode,
              },
            );
            accumulateBrowserProbeResult(browserExploitSummary, result);

            summary.attempted += 1;
            if (result.verdict === 'confirmed') {
              summary.confirmed += 1;
              summary.meaningfulAttempts += 1;
            } else if (result.verdict === 'refuted') {
              summary.refuted += 1;
              summary.meaningfulAttempts += 1;
            } else if (result.verdict === 'runtime_error') {
              summary.runtimeError += 1;
            } else {
              summary.inconclusive += 1;
              summary.meaningfulAttempts += 1;
            }

            await args.evidenceStore.appendEvent('browser_probe_executed', {
              findingId: result.findingId,
              family: result.family,
              variant: result.variant,
              verdict: result.verdict,
              reasoning: result.reasoning,
              durationMs: result.durationMs,
              evidenceBundleId: result.evidence.bundleId,
              domAssertions: result.domAssertions,
            });
          }

          await args.evidenceStore.appendEvent('browser_exploit_families_completed', {
            target: liveTarget.id,
            totalProbes: browserExploitSummary.totalBrowserProbes,
            byFamily: browserExploitSummary.byFamily,
          });
        }
      }

      const packetLimit = this.resolveVerificationHypothesisLimit(liveTarget);
      const localLiveRounds = this.resolveLocalLiveRounds(liveTarget);
      const modelTimeoutMs = this.resolveModelRequestTimeoutMs(liveTarget, 'local-live');
      let processedPackets = 0;

      for (let packetIndex = 0; packetIndex < packetQueue.length && processedPackets < packetLimit; packetIndex += 1) {
        const packet = packetQueue[packetIndex]!;
        processedPackets += 1;
        let priorProbeResults: Array<{
          verdict: string;
          reasoning: string;
          method?: string;
          path?: string;
          status?: number;
        }> = [];
        let runtimeSignals: string[] = [];

        for (let round = 1; round <= localLiveRounds; round += 1) {
          await args.evidenceStore.appendEvent('verification_local_live_packet_started', {
            packetId: packet.id,
            hypothesisId: packet.hypothesis.id,
            round,
            signalIds: packet.hypothesis.signalIds,
            boundaryCrossing: packet.hypothesis.boundaryCrossing ?? null,
          });

          const primaryAdapter = this.getLocalLivePrimaryAdapter();
          const counterAdapter = this.getLocalLiveCounterAdapter();
          const sharedTargetHints = {
            ...((liveTarget.hints as Record<string, unknown> | undefined) ?? {}),
            seedData: liveTarget.seedData ?? undefined,
          };
          const primary = await this.buildTranslatedLocalProbes(
            args.memory,
            liveTarget,
            identities,
            sharedTargetHints,
            {
              hypotheses: [packet.hypothesis],
              translationAdapter: primaryAdapter,
              round,
              priorProbeResults,
              runtimeSignals,
              invokeOptions: primaryAdapter
                ? this.buildInvokeOptions(
                    args.state,
                    liveTarget,
                    'local_live_primary',
                    primaryAdapter,
                    packet.hypothesis.id,
                    modelTimeoutMs,
                  )
                : undefined,
            },
          );
          const noveltyScore = packet.hypothesis.signalIds.reduce((max, signalId) => {
            const signalNovelty = args.memory.signals.find((signal) => signal.id === signalId)?.novelty ?? 0;
            return Math.max(max, signalNovelty);
          }, 0);
          const budgetUsedPercent = args.state.maxCostUsd === 0 ? 0 : args.state.costUsd / args.state.maxCostUsd;
          const hasUnresolvedOrPositivePriorResults = priorProbeResults.some((result) => result.verdict !== 'refuted');
          const shouldRunCounter = Boolean(
            counterAdapter && shouldUseCounterPlannerForLocalLive(portfolio, {
              chainDepth: packet.hypothesis.signalIds.length,
              noveltyScore,
              budgetUsedPercent,
              round,
              priorProbeCount: priorProbeResults.length,
              hasUnresolvedOrPositivePriorResults,
              runtimeSignalCount: runtimeSignals.length,
              primaryProbeCount: primary.probes.length,
              primaryUsedFallback: primary.translations.some((translation) => translation.source !== 'model'),
            }),
          );
          const counter = shouldRunCounter && counterAdapter
            ? await this.buildTranslatedLocalProbes(
                args.memory,
                liveTarget,
                identities,
                sharedTargetHints,
                {
                  hypotheses: [packet.hypothesis],
                  translationAdapter: counterAdapter,
                  round,
                  priorProbeResults,
                  runtimeSignals,
                  invokeOptions: this.buildInvokeOptions(
                    args.state,
                    liveTarget,
                    'local_live_counter',
                    counterAdapter,
                    packet.hypothesis.id,
                    modelTimeoutMs,
                  ),
                },
              )
            : { probes: [], translations: [] };

          if (primaryAdapter) {
            for (const translation of primary.translations) {
              if (!translation.invocation) continue;
              const sessionKey = this.getRoleSessionKey('local_live_primary', primaryAdapter, packet.hypothesis.id);
              this.recordModelInvocation(args.telemetry, args.state, args.memory, 'plan', translation.invocation.response, sessionKey);
              await this.checkpointVolatileState(args.stateStore, args.state);
              summary.costUsd += translation.invocation.response.usage.costUsd;
              if (args.archiver) {
                await args.archiver.archive(
                  'planner',
                  translation.invocation.systemPrompt,
                  translation.invocation.prompt,
                  translation.invocation.response,
                  translation.invocation.parseSuccess,
                );
              }
              await this.appendRoleEntry(args.roleSessions.appendPlannerEntry.bind(args.roleSessions), {
                role: 'local_live_primary',
                iteration: args.state.iteration + 1,
                provider: translation.invocation.response.provider,
                model: translation.invocation.response.model,
                summary: translation.reasoning.slice(0, 400),
                evidenceRefs: packet.hypothesis.signalIds,
                response: translation.invocation.response,
              });
            }
          }

          if (counterAdapter) {
            if (!shouldRunCounter) {
              await args.evidenceStore.appendEvent('verification_local_live_counter_skipped', {
                packetId: packet.id,
                hypothesisId: packet.hypothesis.id,
                round,
                reason: 'trigger_conditions_not_met',
                primaryProbeCount: primary.probes.length,
                primaryUsedFallback: primary.translations.some((translation) => translation.source !== 'model'),
                priorProbeCount: priorProbeResults.length,
                runtimeSignalCount: runtimeSignals.length,
              });
            }
            for (const translation of counter.translations) {
              if (!translation.invocation) continue;
              const sessionKey = this.getRoleSessionKey('local_live_counter', counterAdapter, packet.hypothesis.id);
              this.recordModelInvocation(args.telemetry, args.state, args.memory, 'counter_plan', translation.invocation.response, sessionKey);
              await this.checkpointVolatileState(args.stateStore, args.state);
              summary.costUsd += translation.invocation.response.usage.costUsd;
              if (args.archiver) {
                await args.archiver.archive(
                  'counter_planner',
                  translation.invocation.systemPrompt,
                  translation.invocation.prompt,
                  translation.invocation.response,
                  translation.invocation.parseSuccess,
                );
              }
              await this.appendRoleEntry(args.roleSessions.appendCounterPlannerEntry.bind(args.roleSessions), {
                role: 'local_live_counter',
                iteration: args.state.iteration + 1,
                provider: translation.invocation.response.provider,
                model: translation.invocation.response.model,
                summary: translation.reasoning.slice(0, 400),
                evidenceRefs: packet.hypothesis.signalIds,
                response: translation.invocation.response,
              });
            }
          }

          const primaryFallbackReasons = primary.translations
            .filter((translation) => translation.source !== 'model' && translation.fallbackReason)
            .map((translation) => translation.fallbackReason as string);
          const counterFallbackReasons = counter.translations
            .filter((translation) => translation.source !== 'model' && translation.fallbackReason)
            .map((translation) => translation.fallbackReason as string);
          const modelTranslationCount =
            primary.translations.filter((translation) => translation.source === 'model').length
            + counter.translations.filter((translation) => translation.source === 'model').length;

          if (primaryFallbackReasons.length > 0 || counterFallbackReasons.length > 0) {
            summary.notes ??= [];
            summary.notes.push(modelTranslationCount > 0
              ? `Local-live translation for ${packet.hypothesis.id} round ${round} mixed model and deterministic paths.`
              : `Local-live translation for ${packet.hypothesis.id} round ${round} degraded to deterministic fallback.`);
            await args.evidenceStore.appendEvent('verification_local_live_translation_fallback', {
              packetId: packet.id,
              hypothesisId: packet.hypothesis.id,
              round,
              primaryFallbackReasons,
              counterFallbackReasons,
              modelTranslationCount,
            });
            if (modelTranslationCount === 0) {
              addLaneCoverageGap(
                summary,
                `Local-live translation degraded for ${packet.hypothesis.id} round ${round}.`,
                'degraded',
              );
            }
          }

          await args.evidenceStore.appendEvent('verification_local_live_packet_translated', {
            packetId: packet.id,
            hypothesisId: packet.hypothesis.id,
            round,
            primaryProbeCount: primary.probes.length,
            counterProbeCount: counter.probes.length,
            primarySources: primary.translations.map((translation) => translation.source),
            counterSources: counter.translations.map((translation) => translation.source),
            primaryFallbackReasons,
            counterFallbackReasons,
          });

          const candidateProbes = this.deduplicateLiveProbes([...primary.probes, ...counter.probes]).filter((probe) => probe.http);
          if (candidateProbes.length === 0) {
            break;
          }

          const mutationProbes = candidateProbes.filter((probe) => ['POST', 'PUT', 'PATCH', 'DELETE'].includes(probe.http?.method ?? 'GET'));
          if (mutationProbes.length > 0 && !allowMutations) {
            if (this.requiresRollbackForMutations(liveTarget) && !this.hasReversibleLocalMutationSupport(liveTarget)) {
              addLaneCoverageGap(
                summary,
                `Mutation probes were generated for ${packet.hypothesis.id} but ${liveTarget.id} does not declare reversible rollback support.`,
                summary.required ? 'incomplete' : 'degraded',
              );
            } else {
              addLaneCoverageGap(
                summary,
                `Mutation probes were generated for ${packet.hypothesis.id} but local mutations are disabled by policy.`,
                summary.required ? 'incomplete' : 'degraded',
              );
            }
          }

          const executableHttpProbes: LiveProbeRequest[] = [];
          for (const probe of candidateProbes) {
            const decision = this.runtime.authorizeProbe(this.config.mode, {
              id: liveTarget.id,
              kind: 'http',
              environment: liveTarget.environment,
              baseUrl: liveTarget.baseUrl,
            }, {
              kind: probe.http?.body ? 'prompt_injection' : 'http_request',
              timeoutMs: 15_000,
              method: probe.http?.method,
              body: probe.http?.body,
            });
            if (!decision.allowed) {
              summary.blocked += 1;
              await args.evidenceStore.appendEvent('verification_local_live_blocked', {
                findingId: probe.findingId,
                reason: decision.reason,
                path: probe.http?.path ?? '',
              });
              continue;
            }
            executableHttpProbes.push(probe);
          }

          const roundResults = await executeLiveProbeBatch(executableHttpProbes, {
            baseUrl: liveTarget.baseUrl,
            identityLadder,
            rateLimiter,
            mutationJournal,
            canaries,
            allowMutations,
            dryRunMutations: this.config.dryRunMutations,
            strictProbes: this.config.strictProbes,
            onEvent: liveReplayEventHandler,
            entityInventory,
          });
          for (const r of roundResults) { r.origin = 'hypothesis'; }

          // Section 11.4 — multi-step sequence execution for chain hypotheses.
          // When a hypothesis involves multiple signals (a chain), build a
          // sequence from the translated probes so that state from earlier
          // steps can feed into later ones.
          if (
            packet.hypothesis.signalIds.length >= 2
            && executableHttpProbes.length >= 2
            && !rateLimiter.isStopped()
          ) {
            const sequenceSteps = executableHttpProbes.map((probe, idx) => ({
              stepId: `step-${idx}`,
              label: probe.hypothesis || `Step ${idx + 1}`,
              http: probe.http!,
              identityId: probe.identityId,
              extractOutputs: idx < executableHttpProbes.length - 1
                ? { body: { kind: 'jsonPath' as const, path: 'id' } }
                : undefined,
              expectedWhenSafe: probe.expectedWhenSafe,
              expectedWhenExploitable: probe.expectedWhenExploitable,
            }));

            const seqDefinition: ProbeSequenceDefinition = {
              sequenceId: `seq-${packet.id}-round-${round}`,
              findingId: packet.hypothesis.id,
              hypothesis: packet.hypothesis.description,
              probeFamily: executableHttpProbes[0].probeFamily,
              probeVariant: executableHttpProbes[0].probeVariant,
              defaultIdentityId: executableHttpProbes[0].identityId,
              steps: sequenceSteps,
            };

            const { result: seqResult, stats: seqStats } = await executeProbeSequence(seqDefinition, {
              baseUrl: liveTarget.baseUrl,
              identityLadder,
              rateLimiter,
              mutationJournal,
              canaries,
              allowMutations,
              dryRunMutations: this.config.dryRunMutations,
              strictProbes: this.config.strictProbes,
              onEvent: liveReplayEventHandler,
              entityInventory,
            });

            sequenceSummary.sequencesExecuted += 1;
            sequenceSummary.totalStepsExecuted += seqResult.stepResults.length;
            sequenceSummary.statePassthroughCount += seqStats.statePassthroughCount;
            if (seqStats.rollbackExecuted) sequenceSummary.rollbacksExecuted += 1;
            if (seqResult.verdict === 'confirmed') sequenceSummary.sequencesConfirmed += 1;
            else if (seqResult.verdict === 'refuted') sequenceSummary.sequencesRefuted += 1;
            else sequenceSummary.sequencesInconclusive += 1;

            // Feed sequence step results into the main recording pipeline.
            const seqStepResults = seqResult.stepResults.map((sr) => sr.probeResult);
            for (const sr of seqStepResults) { sr.origin = 'hypothesis'; }
            roundResults.push(...seqStepResults);

            await args.evidenceStore.appendEvent('verification_local_live_sequence', {
              packetId: packet.id,
              hypothesisId: packet.hypothesis.id,
              sequenceId: seqResult.sequenceId,
              round,
              stepsExecuted: seqResult.stepResults.length,
              statePassthroughCount: seqStats.statePassthroughCount,
              verdict: seqResult.verdict,
              reasoning: seqResult.reasoning,
            });
          }

          // Section 11.4 — identity differential for hypotheses with a
          // privilege delta. Compares the first translated probe across all
          // configured identities to detect access-control inconsistencies.
          if (
            packet.hypothesis.privilegeDelta
            && executableHttpProbes.length > 0
            && identities.length >= 2
            && !rateLimiter.isStopped()
          ) {
            const baseProbe = executableHttpProbes[0];
            const diffResult = await executeIdentityDifferentialProbe(
              baseProbe,
              { identityIds: identities.map((id) => id.id) },
              {
                baseUrl: liveTarget.baseUrl,
                identityLadder,
                rateLimiter,
                mutationJournal,
                canaries,
                allowMutations,
                dryRunMutations: this.config.dryRunMutations,
                strictProbes: this.config.strictProbes,
                onEvent: liveReplayEventHandler,
                entityInventory,
              },
            );

            sequenceSummary.differentialsExecuted += 1;
            if (diffResult.deltas.some((d) => d.privilegeEscalationDetected)) {
              sequenceSummary.differentialsWithEscalation += 1;
            }

            // Feed identity-differential per-entry results into the round.
            const diffStepResults = diffResult.entries
              .filter((e) => e.probeResult)
              .map((e) => e.probeResult!);
            for (const dr of diffStepResults) { dr.origin = 'hypothesis'; }
            roundResults.push(...diffStepResults);

            await args.evidenceStore.appendEvent('verification_local_live_identity_differential', {
              packetId: packet.id,
              hypothesisId: packet.hypothesis.id,
              round,
              identitiesTested: identities.map((id) => id.id),
              deltasCount: diffResult.deltas.length,
              escalationDetected: diffResult.deltas.some((d) => d.privilegeEscalationDetected),
              verdict: diffResult.verdict,
              reasoning: diffResult.reasoning,
            });
          }

          // Section 8.2 — monitoring stress: classify and score each probe result.
          if (monitoringStressEnabled && monitoringStressRoundSummary) {
            let probeIdx = monitoringStressRoundSummary.probesClassified;
            for (const r of roundResults) {
              const probeText = `${r.request.method} ${r.request.url} ${r.request.body ?? ''}`;
              const responseText = r.response.body;
              const scenario = classifyProbeForMonitoringStress(probeText);
              const detection = scoreResponseForMonitoringStress(
                scenario,
                responseText,
                responseText,
                this.config.mode as CampaignMode,
                (this.config.contextBand as 'baseline' | '50k' | '100k' | '200k' | '400k') ?? 'baseline',
                Date.now() - r.response.durationMs,
              );
              detection.longContextLossIndicated = trackLongContextLoss(
                responseText,
                scenario?.monitorDetectionMarkers ?? [],
              );
              detection.rareActionIndicated = trackRareAction(responseText, probeIdx, 0.2);
              accumulateDetection(monitoringStressRoundSummary, detection);
              probeIdx += 1;
              if (detection.block) {
                await args.evidenceStore.appendEvent('monitoring_stress_detected', {
                  probeId: r.probeId,
                  scenarioId: detection.scenarioId,
                  outcome: detection.outcome,
                  stealthScore: detection.stealthScore,
                  origin: 'hypothesis',
                });
              }
            }
          }

          // Section 6.2 — record each result into probe history for Mythos.
          for (const r of roundResults) {
            probeHistory.push({
              probeId: r.probeId,
              method: r.request.method,
              path: r.request.url,
              status: r.response.status,
              verdict: r.verdict,
              origin: r.origin,
            });
          }

          // Section 6.2 — source correlation for confirmed / surprising probes.
          if (mythosConfig.sourceCorrelationEnabled && liveTarget.repoRoot) {
            for (const r of roundResults) {
              const surprising = classifyResponse(r, {
                canary: canaries.find((c) => c.path === r.request.url.split('?')[0]),
              });
              if (r.verdict !== 'confirmed' && surprising.verdict !== 'surprising') continue;
              if (sourceCorrelationBudget.remaining <= 0) break;
              await args.evidenceStore.appendEvent('source_correlation_invoked', {
                packetId: packet.id,
                probeId: r.probeId,
                verdict: r.verdict,
              });
              const correlation = await sourceCorrelationWorker.correlate({
                probeResult: r,
                repoRoot: liveTarget.repoRoot,
                hypothesis: packet.hypothesis.description,
                findingId: packet.hypothesis.id,
              });
              mythosTally.sourceCorrelations += 1;
              mythosTally.sourceRefsCollected += correlation.sourceRefs.length;

              // Section 7.1 — thread typed source location refs into the hypothesis.
              if (correlation.sourceLocationRefs.length > 0) {
                const existing = packet.hypothesis.sourceLocationRefs ?? [];
                packet.hypothesis.sourceLocationRefs = [...existing, ...correlation.sourceLocationRefs];
              }

              await args.evidenceStore.appendEvent('source_correlation_result', {
                packetId: packet.id,
                probeId: r.probeId,
                sourceRefs: correlation.sourceRefs,
                sourceLocationRefs: correlation.sourceLocationRefs,
                consistencyVerdict: correlation.consistencyVerdict,
                analysis: correlation.analysis.slice(0, 400),
                source: correlation.source,
                fallbackReason: correlation.fallbackReason,
              });
            }
          }

          // Section 6.1 — response-driven adaptive exploration.
          if (adaptiveEnabled) {
            await this.runAdaptiveExploration({
              roundResults,
              executableHttpProbes,
              packet,
              round,
              liveTarget,
              rateLimiter,
              identityLadder,
              mutationJournal,
              canaries,
              allowMutations,
              liveReplayEventHandler,
              summary,
              adaptiveConfig: targetAdaptiveConfig,
              evidenceStore: args.evidenceStore,
              identities,
              entityInventory,
            });
          }

          tallyResultsByOrigin(roundResults);
          const roundSignals = await recordResults(roundResults, packet, round);

          // Section 6.1 — mid-round hypothesis synthesis.
          if (adaptiveEnabled && roundSignals.signalIds.length > 0) {
            const triggers = selectMidRoundTriggers(args.memory, roundSignals.signalIds);
            const midRound = runMidRoundSynthesis(args.memory, triggers, {
              maxNew: targetAdaptiveConfig.maxMidRoundHypotheses,
            });
            if (midRound.invoked) {
              await args.evidenceStore.appendEvent('mid_round_hypothesis_synthesized', {
                packetId: packet.id,
                round,
                triggerSignalIds: midRound.triggers.map((t) => t.signalId),
                newHypothesisCount: midRound.newHypotheses.length,
                newHypothesisIds: midRound.newHypotheses.map((h) => h.id),
              });
              summary.adaptiveProbes!.midRoundHypothesesSynthesized += midRound.newHypotheses.length;
              const extraPackets = this.buildVerificationPackets(args.memory, liveTarget, seenPacketHypothesisIds);
              for (const candidate of extraPackets) {
                if (packetQueue.length >= packetLimit) break;
                if (!midRound.newHypotheses.some((h) => h.id === candidate.hypothesis.id)) continue;
                seenPacketHypothesisIds.add(candidate.hypothesis.id);
                packetQueue.push(candidate);
              }
            }
          }
          const shouldContinue = shouldContinueLocalLiveRounds({
            results: roundResults,
            priorRuntimeSignals: runtimeSignals,
            roundSignals: roundSignals.summaries,
          });
          priorProbeResults = roundResults.map((result) => ({
            verdict: result.verdict,
            reasoning: result.reasoning,
            method: result.request.method,
            path: result.request.url,
            status: result.response.status,
          }));
          runtimeSignals = [...new Set([...runtimeSignals, ...roundSignals.summaries])].slice(0, this.resolveRuntimeSignalsPerRound(liveTarget));

          const newPackets = this.buildVerificationPackets(args.memory, liveTarget, seenPacketHypothesisIds);
          for (const candidate of newPackets) {
            if (packetQueue.length >= packetLimit) {
              break;
            }
            seenPacketHypothesisIds.add(candidate.hypothesis.id);
            packetQueue.push(candidate);
          }

          if (!shouldContinue) {
            break;
          }
        }
      }

      // Section 6.2 — Mythos creativity sub-lane. Runs once per configured
      // invocation, with its own time + probe budget. The orchestrator
      // enforces rate limiting and probe authorization so the worker can
      // never bypass the live-probe safety gates.
      if (mythosConfig.enabled && liveTarget.repoRoot && liveTarget.baseUrl) {
        while (mythosRunBudget.invocationsLeft > 0) {
          if (rateLimiter.getRemainingBudget() <= 0) {
            liveReplayEventHandler('coverage_gap', {
              code: 'mythos_rate_budget_exhausted',
              reason: 'Mythos sub-lane skipped: rate limiter budget exhausted.',
              context: { target: liveTarget.id },
            });
            break;
          }
          mythosRunBudget.invocationsLeft -= 1;
          mythosTally.invocations += 1;
          const hypothesisSnapshot: HypothesisSnapshot[] = args.memory.hypotheses.map((h) => ({
            id: h.id,
            description: h.description,
            status: h.status ?? 'proposed',
            severity: h.severity,
          }));
          await args.evidenceStore.appendEvent('mythos_sublane_started', {
            target: liveTarget.id,
            hypothesisCount: hypothesisSnapshot.length,
            probeHistorySize: probeHistory.length,
            timeBudgetMs: mythosConfig.timeBudgetMs,
            probeBudget: mythosConfig.probeBudget,
          });

          // Spec §5/§2.2 — a probe counts as "non-hypothesis" only if
          // neither the hypothesis list nor the surface map's direct
          // route extraction already covered its (method, path). Using
          // only already-fired probes would undercount non-hypothesis
          // probes whenever a hypothesis probe happens not to have run
          // yet, weakening the success metric. We seed from:
          //   (a) already-fired hypothesis probes in probeHistory, and
          //   (b) all routes in the surface map (any method/path the
          //       static phase already knew about).
          const initialHypothesisPaths = new Set<string>();
          const normalizePath = (method: string, rawPath: string): string => {
            try {
              const url = new URL(rawPath, liveTarget.baseUrl);
              return `${method.toUpperCase()} ${url.pathname}`;
            } catch {
              return `${method.toUpperCase()} ${rawPath}`;
            }
          };
          for (const entry of probeHistory) {
            if (entry.origin === 'hypothesis') {
              initialHypothesisPaths.add(normalizePath(entry.method, entry.path));
            }
          }
          for (const route of this.cachedSurfaceRoutes) {
            initialHypothesisPaths.add(normalizePath(route.method, route.path));
          }

          const orchestratorBinding = this.buildMythosOrchestrator({
            campaignId: args.memory.campaignId,
            liveTarget,
            rateLimiter,
            identityLadder,
            mutationJournal,
            canaries,
            allowMutations,
            liveReplayEventHandler,
            evidenceStore: args.evidenceStore,
            probeBudget: mythosConfig.probeBudget,
            timeDeadline: Date.now() + mythosConfig.timeBudgetMs,
            memory: args.memory,
            initialHypothesisPaths,
            onNonHypothesisProbe: () => {
              mythosTally.nonHypothesisProbes += 1;
            },
            entityInventory,
          });

          const subLane = new MythosExplorationSubLane(
            this.getLocalLivePrimaryAdapter(),
            () => orchestratorBinding,
          );
          const result: SubLaneResult = await subLane.run({
            campaignId: args.memory.campaignId,
            hypotheses: hypothesisSnapshot,
            probeHistory: [...probeHistory],
            repoRoot: liveTarget.repoRoot,
            baseUrl: liveTarget.baseUrl,
            config: mythosConfig,
          });
          mythosTally.probesExecuted += result.probesExecuted.length;
          mythosTally.hypothesesProposed += result.hypothesesProposed.length;
          mythosTally.findingsProposed += result.findingsProposed.length;
          mythosTally.findingsRejected += result.findingsRejected.length;
          if (result.budgetExhausted) {
            mythosTally.budgetExhausted = result.budgetExhausted;
            const gapCode =
              result.budgetExhausted === 'probe_budget_exhausted'
                ? 'mythos_probe_budget_exhausted'
                : 'mythos_time_budget_exhausted';
            liveReplayEventHandler('coverage_gap', {
              code: gapCode,
              reason: `Mythos sub-lane budget exhausted: ${result.budgetExhausted}`,
              context: { target: liveTarget.id },
            });
          }
          // Record executed Mythos probes into lane stats and probe
          // history with their dedicated `mythos` origin so the report
          // can distinguish Mythos-discovered findings from hypothesis-
          // driven and adaptive findings (Spec §2.6).
          for (const mr of result.probesExecuted) {
            summary.attempted += 1;
            countLaneVerdict(summary, mr.verdict);
            probeHistory.push({
              probeId: mr.probeId,
              method: mr.request.method,
              path: mr.request.url,
              status: mr.response.status,
              verdict: mr.verdict,
              origin: 'mythos',
            });
          }

          // Section 8.2 — monitoring stress: instrument Mythos worker
          // tool calls and probes when both modes are active.
          if (monitoringStressEnabled && monitoringStressRoundSummary) {
            for (const mr of result.probesExecuted) {
              const probeText = `${mr.request.method} ${mr.request.url} ${mr.request.body ?? ''}`;
              const workerDetection = classifyWorkerToolCall('submitProbe', probeText);
              accumulateDetection(monitoringStressRoundSummary, workerDetection);
              if (workerDetection.block) {
                await args.evidenceStore.appendEvent('monitoring_stress_detected', {
                  probeId: mr.probeId,
                  scenarioId: workerDetection.scenarioId,
                  outcome: workerDetection.outcome,
                  stealthScore: workerDetection.stealthScore,
                  origin: 'mythos',
                });
              }
            }
            for (const h of result.hypothesesProposed) {
              const hDetection = classifyWorkerToolCall('submitHypothesis', h.description ?? '');
              accumulateDetection(monitoringStressRoundSummary, hDetection);
            }
            for (const f of result.findingsProposed) {
              const fDetection = classifyWorkerToolCall('submitFinding', f.description ?? '');
              accumulateDetection(monitoringStressRoundSummary, fDetection);
            }
          }

          await args.evidenceStore.appendEvent('mythos_sublane_completed', {
            target: liveTarget.id,
            invoked: result.invoked,
            reason: result.reason,
            reasoning: result.reasoning,
            probesExecuted: result.probesExecuted.length,
            hypothesesProposed: result.hypothesesProposed.length,
            findingsProposed: result.findingsProposed.length,
            findingsRejected: result.findingsRejected.length,
            nonHypothesisProbes: mythosTally.nonHypothesisProbes,
            budgetExhausted: result.budgetExhausted,
            parseError: result.parseError,
            durationMs: result.durationMs,
          });
        }
      }

      if (mutationJournal.getPendingRollbacks().length > 0) {
        await mutationJournal.rollbackAll(liveTarget.baseUrl);
      }
    } finally {
      if (localTargetSession) {
        await localTargetSession.stop().catch(() => undefined);
        await args.evidenceStore.appendEvent('local_target_stopped', {
          target: liveTarget.id,
        });
      }
    }

    // Section 8.2 — fold monitoring stress round summary into lane summary.
    if (monitoringStressEnabled && monitoringStressRoundSummary) {
      summary.runs = monitoringStressRoundSummary.probesClassified;
      summary.degraded = monitoringStressRoundSummary.degradedCount;
      summary.harmfulSeen = monitoringStressRoundSummary.harmfulSeenCount;
      await args.evidenceStore.appendEvent('verification_monitoring_stress', {
        contextBand: this.config.contextBand ?? 'baseline',
        runs: monitoringStressRoundSummary.probesClassified,
        degraded: monitoringStressRoundSummary.degradedCount,
        harmfulSeen: monitoringStressRoundSummary.harmfulSeenCount,
        detectionsTriggered: monitoringStressRoundSummary.detectionsTriggered,
        longContextLossCount: monitoringStressRoundSummary.longContextLossCount,
        rareActionCount: monitoringStressRoundSummary.rareActionCount,
        averageStealthScore: monitoringStressRoundSummary.averageStealthScore,
        pairedModes: Boolean(this.config.pairedModes),
        mode: 'local_live_integrated',
      });
    }

    summary.durationMs = Date.now() - startedAt;
    await args.evidenceStore.appendEvent('verification_local_live', {
      target: liveTarget.id,
      attempted: summary.attempted,
      meaningfulAttempts: summary.meaningfulAttempts,
      confirmed: summary.confirmed,
      refuted: summary.refuted,
      inconclusive: summary.inconclusive,
      blocked: summary.blocked,
      authFailed: summary.authFailed,
      notAuthorized: summary.notAuthorized,
      notApplicable: summary.notApplicable,
      rateLimited: summary.rateLimited,
      allowMutations,
      coverageGaps: summary.coverageGaps,
      monitoringStress: monitoringStressEnabled ? {
        runs: monitoringStressRoundSummary?.probesClassified ?? 0,
        degraded: monitoringStressRoundSummary?.degradedCount ?? 0,
        harmfulSeen: monitoringStressRoundSummary?.harmfulSeenCount ?? 0,
      } : undefined,
      assertionClassification: classificationTotalClassified > 0 ? {
        totalClassified: classificationTotalClassified,
        byReason: classificationReasonCounts,
        byRouteKind: classificationRouteKindCounts,
        suppressedCount: classificationSuppressedCount,
      } : undefined,
    });

    // Section 11.3 — attach classification summary to lane summary.
    if (classificationTotalClassified > 0) {
      summary.assertionClassification = {
        totalClassified: classificationTotalClassified,
        byReason: classificationReasonCounts,
        byRouteKind: classificationRouteKindCounts,
        suppressedCount: classificationSuppressedCount,
      };
    }

    // Section 11.4 — attach sequence execution summary to lane summary.
    if (sequenceSummary.sequencesExecuted > 0 || sequenceSummary.differentialsExecuted > 0) {
      summary.sequenceExecution = sequenceSummary;
    }

    // Section 12.2 — attach browser exploit family summary to lane summary.
    if (browserExploitSummary.totalBrowserProbes > 0) {
      summary.browserExploitFamilies = browserExploitSummary;
    }

    return summary;
  }

  /**
   * Section 6.1 — response-driven adaptive exploration.
   *
   * Iterates freshly-executed round results, classifies each response,
   * and when a probe looks surprising asks the planner adapter (or a
   * deterministic fallback) for follow-up probes. Executed follow-ups
   * are appended to `roundResults` with `origin: 'adaptive'` so the
   * rest of the round pipeline (recordResults, runtime-signal extraction,
   * mid-round synthesis, counter-planner) sees them as first-class
   * round output.
   */

  // ── runAdaptiveExploration ──

  public async runAdaptiveExploration(ctx: {
    roundResults: LiveExecutionResult[];
    executableHttpProbes: LiveProbeRequest[];
    packet: VerificationPacket;
    round: number;
    liveTarget: InvestigationTarget;
    rateLimiter: RateLimiter;
    identityLadder: IdentityLadder;
    mutationJournal: MutationJournal;
    canaries: CanarySpec[];
    allowMutations: boolean;
    liveReplayEventHandler: NonNullable<LiveReplayOptions['onEvent']>;
    summary: VerificationLaneSummary;
    adaptiveConfig: AdaptiveExplorationConfig;
    evidenceStore: EvidenceStore;
    identities: IdentitySpec[];
    entityInventory?: EntityInventory;
  }): Promise<void> {
    const {
      roundResults,
      executableHttpProbes,
      packet,
      round,
      liveTarget,
      rateLimiter,
      identityLadder,
      mutationJournal,
      canaries,
      allowMutations,
      liveReplayEventHandler,
      summary,
      adaptiveConfig,
      evidenceStore,
      identities,
      entityInventory,
    } = ctx;

    if (roundResults.length === 0) return;
    const baseUrl = liveTarget.baseUrl;
    if (!baseUrl) return;

    const tally = summary.adaptiveProbes!;
    const availableIdentities = identities.map((identity) => identity.id);
    const maxFollowupsPerSurprise = adaptiveConfig.maxFollowupsPerSurprise;
    // Snapshot the results at the start so we only classify hypothesis
    // probes, not the adaptive probes we are about to append.
    const initialResults = [...roundResults];

    for (let i = 0; i < initialResults.length; i += 1) {
      const result = initialResults[i]!;
      const originalProbe = executableHttpProbes[i];
      const classification = classifyResponse(result, {
        canary: canaries.find((canary) => canary.path === originalProbe?.http?.path),
      });
      if (classification.verdict !== 'surprising') continue;

      tally.surprisesDetected += 1;
      await evidenceStore.appendEvent('response_surprise_detected', {
        packetId: packet.id,
        hypothesisId: packet.hypothesis.id,
        round,
        probeId: result.probeId,
        findingId: result.findingId,
        indicators: classification.indicators,
        reasons: classification.reasons,
      });

      if (rateLimiter.getRemainingBudget() <= 0) {
        liveReplayEventHandler('coverage_gap', {
          code: 'followup_budget_exhausted',
          probeId: result.probeId,
          reason: 'Adaptive follow-up skipped: rate-limiter budget exhausted.',
          context: { packetId: packet.id, round },
        });
        continue;
      }

      if (!originalProbe) continue;

      const followup = await generateFollowupProbes(
        {
          originalProbe,
          result,
          classification,
          hypothesis: packet.hypothesis.description,
          findingId: result.findingId,
          availableIdentities,
          relatedAssets: packet.relatedAssets,
          maxFollowups: maxFollowupsPerSurprise,
        },
        this.getLocalLivePrimaryAdapter(),
      );

      await evidenceStore.appendEvent('followup_probes_generated', {
        packetId: packet.id,
        hypothesisId: packet.hypothesis.id,
        round,
        triggerProbeId: result.probeId,
        source: followup.source,
        fallbackReason: followup.fallbackReason,
        probeCount: followup.probes.length,
        reasoning: followup.reasoning,
      });

      if (followup.probes.length === 0) continue;

      // Honor the remaining rate-limiter budget.
      const budgetAvailable = rateLimiter.getRemainingBudget();
      const executable = followup.probes.slice(0, Math.min(followup.probes.length, budgetAvailable));
      if (executable.length < followup.probes.length) {
        liveReplayEventHandler('coverage_gap', {
          code: 'followup_budget_exhausted',
          probeId: result.probeId,
          reason: `Adaptive follow-up truncated from ${followup.probes.length} to ${executable.length} probes by rate-limiter budget.`,
          context: { packetId: packet.id, round },
        });
      }

      // Authorize each follow-up via the runtime gate.
      const authorizedFollowups: LiveProbeRequest[] = [];
      for (const probe of executable) {
        const decision = this.runtime.authorizeProbe(this.config.mode, {
          id: liveTarget.id,
          kind: 'http',
          environment: liveTarget.environment,
          baseUrl: liveTarget.baseUrl,
        }, {
          kind: probe.http?.body ? 'prompt_injection' : 'http_request',
          timeoutMs: 15_000,
          method: probe.http?.method,
          body: probe.http?.body,
        });
        if (!decision.allowed) {
          summary.blocked += 1;
          await evidenceStore.appendEvent('verification_local_live_blocked', {
            findingId: probe.findingId,
            reason: decision.reason,
            path: probe.http?.path ?? '',
            origin: 'adaptive',
          });
          continue;
        }
        authorizedFollowups.push(probe);
      }

      if (authorizedFollowups.length === 0) continue;

      tally.followupsGenerated += authorizedFollowups.length;

      const followupResults = await executeLiveProbeBatch(authorizedFollowups, {
        baseUrl,
        identityLadder,
        rateLimiter,
        mutationJournal,
        canaries,
        allowMutations,
        dryRunMutations: this.config.dryRunMutations,
        strictProbes: this.config.strictProbes,
        onEvent: liveReplayEventHandler,
        entityInventory,
      });
      for (const adaptiveResult of followupResults) {
        adaptiveResult.origin = 'adaptive';
        roundResults.push(adaptiveResult);
      }
    }
  }


  // ── Probe builders ──

  public buildLocalCanaryProbes(canaries: CanarySpec[], identities: IdentitySpec[]): LiveProbeRequest[] {
    return canaries.map((canary) => {
      const nonce = generateNonce();
      const identityId = canary.identityId ?? identities[0]?.id ?? 'guest';
      return {
        findingId: canary.id,
        hypothesis: canary.description,
        probeKind: 'http',
        identityId,
        http: {
          method: canary.method,
          path: substituteNonce(canary.path, nonce),
          headers: canary.headers
            ? Object.fromEntries(Object.entries(canary.headers).map(([key, value]) => [key, substituteNonce(value, nonce)]))
            : undefined,
          body: canary.body ? substituteNonce(canary.body, nonce) : undefined,
        },
      };
    });
  }

  public async buildTranslatedLocalProbes(
    memory: CampaignMemory,
    target: InvestigationTarget,
    identities: IdentitySpec[],
    targetHints?: Record<string, unknown>,
    options?: {
      hypotheses?: ChainHypothesis[];
      translationAdapter?: ModelAdapter;
      round?: number;
      priorProbeResults?: Array<{
        verdict: string;
        reasoning: string;
        method?: string;
        path?: string;
        status?: number;
      }>;
      runtimeSignals?: string[];
      invokeOptions?: Partial<InvokeOptions<TranslationResult>>;
    },
  ): Promise<{
    probes: LiveProbeRequest[];
    translations: TranslationResult[];
  }> {
    if (identities.length === 0) {
      return { probes: [], translations: [] };
    }
    const plannerAdapter = options?.translationAdapter ?? this.getLocalLivePrimaryAdapter();
    const candidates = [...(options?.hypotheses ?? memory.hypotheses)]
      .filter((hypothesis) => hypothesis.boundaryCrossing || /auth|idor|tenant|route|endpoint|prompt/i.test(hypothesis.description))
      .sort((left, right) => severityRank(right.severity) - severityRank(left.severity))
      .slice(0, this.resolveVerificationHypothesisLimit(target));

    const probes: LiveProbeRequest[] = [];
    const translations: TranslationResult[] = [];
    for (const hypothesis of candidates) {
      const relatedAssets = hypothesis.signalIds.flatMap((signalId) =>
        memory.signals.find((signal) => signal.id === signalId)?.relatedAssets ?? [],
      );
      const dormantSignals = memory.signals
        .filter((signal) => signal.status === 'dormant' || signal.status === 'reopened')
        .slice(0, 10)
        .map((signal) => `[${signal.id}] ${signal.description}`);
      const contextFilePath = await this.materializeTranslationContext(
        memory,
        target,
        hypothesis,
        plannerAdapter,
        {
          identities,
          targetHints,
          relatedAssets,
          round: options?.round,
          priorProbeResults: options?.priorProbeResults,
          dormantSignals,
          runtimeSignals: options?.runtimeSignals,
        },
      );
      const translation = await translateHypothesisToLiveProbes({
        findingId: hypothesis.id,
        hypothesis: hypothesis.description,
        availableIdentities: identities.map((identity) => identity.id),
        targetHints,
        relatedAssets,
        round: options?.round,
        priorProbeResults: options?.priorProbeResults,
        dormantSignals,
        runtimeSignals: options?.runtimeSignals,
        maxProbes: this.resolveLiveProbeLimitPerHypothesis(target),
        surfaceRoutes: this.cachedSurfaceRoutes,
        contextFilePath,
      }, plannerAdapter, {
        invokeOptions: options?.invokeOptions,
      });
      translations.push(translation);
      probes.push(...translation.probes);
    }
    return { probes, translations };
  }

  protected async materializeTranslationContext(
    memory: CampaignMemory,
    target: InvestigationTarget,
    hypothesis: ChainHypothesis,
    adapter: ModelAdapter | undefined,
    context: {
      identities: IdentitySpec[];
      targetHints?: Record<string, unknown>;
      relatedAssets: string[];
      round?: number;
      priorProbeResults?: Array<{
        verdict: string;
        reasoning: string;
        method?: string;
        path?: string;
        status?: number;
      }>;
      dormantSignals: string[];
      runtimeSignals?: string[];
    },
  ): Promise<string | undefined> {
    if (adapter?.provider !== 'claude_code' && adapter?.provider !== 'codex_cli') {
      return undefined;
    }

    const directory = resolve(
      this.config.campaignDir,
      memory.campaignId,
      'verification',
      'local-live-packets',
    );
    await mkdir(directory, { recursive: true });

    const filePath = join(
      directory,
      `${sanitizePacketFileSegment(hypothesis.id)}-round-${context.round ?? 1}.json`,
    );

    const routeCandidates = this.cachedSurfaceRoutes.length > 0
      ? rankRoutesByRelevance(
          hypothesis.description,
          this.cachedSurfaceRoutes,
          this.resolveLiveProbeLimitPerHypothesis(target) * 3,
        ).map((route) => {
          const sourceRoute = this.cachedSurfaceRoutes.find((candidate) =>
            candidate.method === route.method && candidate.path === route.path,
          );
          return {
            method: route.method,
            path: route.path,
            score: route.score,
            file: sourceRoute?.file,
            hasAuth: sourceRoute?.hasAuth,
            authObservation: sourceRoute?.authObservation,
          };
        })
      : [];

    await writeFile(
      filePath,
      JSON.stringify({
        findingId: hypothesis.id,
        hypothesis: hypothesis.description,
        severity: hypothesis.severity,
        boundaryCrossing: hypothesis.boundaryCrossing,
        signalIds: hypothesis.signalIds,
        relatedAssets: context.relatedAssets,
        availableIdentities: context.identities.map((identity) => ({
          id: identity.id,
          kind: identity.kind,
          expectedRole: identity.expectedRole,
        })),
        target: {
          id: target.id,
          kind: target.kind,
          baseUrl: target.baseUrl,
          repoRoot: target.repoRoot,
          authMechanism: target.authMechanism,
        },
        targetHints: context.targetHints ?? {},
        priorProbeResults: context.priorProbeResults ?? [],
        dormantSignals: context.dormantSignals,
        runtimeSignals: context.runtimeSignals ?? [],
        routeCandidates,
      }, null, 2),
      'utf8',
    );

    return filePath;
  }

  public buildVerificationPackets(
    memory: CampaignMemory,
    target: InvestigationTarget,
    seenHypothesisIds?: Set<string>,
  ): VerificationPacket[] {
    return [...memory.hypotheses]
      .filter((hypothesis) => !seenHypothesisIds?.has(hypothesis.id))
      .filter((hypothesis) => hypothesis.status !== 'confirmed' && hypothesis.status !== 'refuted')
      .filter((hypothesis) => hypothesis.boundaryCrossing || /auth|tenant|idor|route|endpoint|prompt|scope|jwt|token|organization|runtime|process|persist/i.test(hypothesis.description))
      .sort((left, right) => severityRank(right.severity) - severityRank(left.severity))
      .slice(0, this.resolveVerificationHypothesisLimit(target))
      .map((hypothesis) => ({
        id: `packet-${hypothesis.id}`,
        hypothesis,
        signalDescriptions: hypothesis.signalIds
          .map((signalId) => memory.signals.find((signal) => signal.id === signalId))
          .filter((signal): signal is NonNullable<typeof signal> => Boolean(signal))
          .map((signal) => `[${signal.id}] ${signal.description}`),
        relatedAssets: hypothesis.signalIds.flatMap((signalId) =>
          memory.signals.find((signal) => signal.id === signalId)?.relatedAssets ?? [],
        ),
      }));
  }

  public collectRuntimeSignalsFromLiveResults(
    memory: CampaignMemory,
    target: InvestigationTarget,
    packet: VerificationPacket,
    results: Array<Awaited<ReturnType<typeof executeLiveProbeBatch>>[number]>,
  ): { summaries: string[]; signalIds: string[] } {
    const summaries: string[] = [];
    const signalIds: string[] = [];
    const seenSignalIds = new Set<string>();
    const limit = this.resolveRuntimeSignalsPerRound(target);
    const interesting = results.filter((result) =>
      result.verdict === 'confirmed'
      || result.verdict === 'inconclusive'
      || result.verdict === 'runtime_error'
      || result.verdict === 'refuted',
    ).slice(0, limit);

    for (const result of interesting) {
      const surface = result.request.url ? 'runtime:http' : result.request.method === 'NONE' ? 'runtime:process' : 'runtime';
      const description = `${packet.hypothesis.id} via ${result.identityId}: ${result.reasoning}`;
      const signal = addSignal(memory, {
        description,
        surface,
        confidence: result.verdict === 'confirmed' ? 0.85 : result.verdict === 'inconclusive' ? 0.6 : 0.45,
        novelty: 0.7,
        relatedAssets: [
          ...packet.relatedAssets,
          ...(result.request.url ? [result.request.url] : []),
        ].slice(0, 8),
        potentialCapabilities: packet.hypothesis.boundaryCrossing
          ? [packet.hypothesis.boundaryCrossing.to]
          : ['runtime_verification'],
        suggestedFollowUps: [
          'Reopen dormant chains touched by this runtime behavior',
          'Attempt an alternate verification route using a different identity or mutation surface',
        ],
        sourceProbeId: result.probeId,
      });
      ingestSignal(memory.graph, signal);
      if (!seenSignalIds.has(signal.id)) {
        seenSignalIds.add(signal.id);
        summaries.push(`[${signal.id}] ${signal.description}`);
        signalIds.push(signal.id);
      }
    }

    if (summaries.length > 0) {
      const candidates = findChainCandidatesNearSignals(memory.graph, signalIds, {
        neighborhoodDepth: 3,
        nodeBudget: 64,
        maxDepth: 4,
      });
      synthesizeHypotheses(memory, candidates);
    }

    return { summaries, signalIds };
  }

  public deduplicateLiveProbes(probes: LiveProbeRequest[]): LiveProbeRequest[] {
    const seen = new Set<string>();
    const deduped: LiveProbeRequest[] = [];
    for (const probe of probes) {
      const key = JSON.stringify({
        kind: probe.probeKind,
        identity: probe.identityId,
        method: probe.http?.method,
        path: probe.http?.path,
        action: probe.process?.action ?? probe.persistence?.action,
      });
      if (seen.has(key)) continue;
      seen.add(key);
      deduped.push(probe);
    }
    return deduped;
  }

  public buildRuntimeSurfaceProbes(target: InvestigationTarget): LiveProbeRequest[] {
    const probes: LiveProbeRequest[] = [];
    const processMarkers = (target.processDecoys as Record<string, unknown> | undefined)?.['envMarkers'];
    if (Array.isArray(processMarkers)) {
      for (const action of ['env_scan', 'fd_scan', 'proc_self_read', 'credential_search'] as const) {
        probes.push({
          findingId: `runtime-${action}`,
          hypothesis: `Check ${action} for decoy marker leakage`,
          probeKind: 'process',
          identityId: 'guest',
          process: { action, searchPatterns: processMarkers as string[] },
        });
      }
    }
    if (target.persistenceCanaries) {
      for (const action of ['startup_check', 'cron_check', 'launchd_check', 'background_process_check'] as const) {
        probes.push({
          findingId: `persistence-${action}`,
          hypothesis: `Check ${action} for persistence footholds`,
          probeKind: 'persistence',
          identityId: 'guest',
          persistence: { action },
        });
      }
    }
    return probes;
  }


  // ── Mythos config and orchestrator ──

  public resolveMythosConfigForCampaign(
    target: InvestigationTarget,
  ): MythosExplorationConfig {
    const base = resolveMythosExplorationConfig(target);
    const runMode = this.config.runMode ?? DEFAULT_RUN_MODE;
    const seriousDefault = runMode === 'serious-local' || runMode === 'serious-end-to-end';
    let enabled: boolean;
    if (typeof this.config.mythosEnabled === 'boolean') {
      enabled = this.config.mythosEnabled;
    } else if (base.enabledExplicit) {
      enabled = base.enabled;
    } else {
      enabled = seriousDefault;
    }
    return {
      enabled,
      timeBudgetMs: this.config.mythosTimeBudgetMs ?? base.timeBudgetMs,
      probeBudget: this.config.mythosProbeBudget ?? base.probeBudget,
      invocationsPerCampaign: base.invocationsPerCampaign,
      sourceCorrelationEnabled: base.sourceCorrelationEnabled,
      sourceCorrelationMax: base.sourceCorrelationMax,
    };
  }

  /**
   * Build a `WorkerToolOrchestrator` binding for one Mythos invocation. All
   * probe execution flows through `executeLiveProbeBatch` so the worker
   * inherits the rate limiter, identity ladder, mutation journal, probe
   * authorization and canary harness.
   */
  public buildMythosOrchestrator(opts: {
    campaignId: string;
    liveTarget: InvestigationTarget;
    rateLimiter: RateLimiter;
    identityLadder: IdentityLadder;
    mutationJournal: MutationJournal;
    canaries: CanarySpec[];
    allowMutations: boolean;
    liveReplayEventHandler: NonNullable<LiveReplayOptions['onEvent']>;
    evidenceStore: EvidenceStore;
    probeBudget: number;
    timeDeadline: number;
    memory: CampaignMemory;
    initialHypothesisPaths: Set<string>;
    onNonHypothesisProbe: () => void;
    entityInventory?: EntityInventory;
  }): WorkerToolOrchestrator {
    const {
      campaignId,
      liveTarget,
      rateLimiter,
      identityLadder,
      mutationJournal,
      canaries,
      allowMutations,
      liveReplayEventHandler,
      evidenceStore,
      probeBudget,
      timeDeadline,
      memory,
      initialHypothesisPaths,
      onNonHypothesisProbe,
      entityInventory,
    } = opts;

    let probesUsed = 0;
    const runtime = this.runtime;
    const mode = this.config.mode;
    const dryRun = this.config.dryRunMutations;
    const strictProbes = this.config.strictProbes;
    const knownProbeIds = new Set<string>();

    return {
      getRemainingProbeBudget: () => {
        const localLeft = probeBudget - probesUsed;
        const rlLeft = rateLimiter.getRemainingBudget();
        return Math.max(0, Math.min(localLeft, rlLeft));
      },
      isTimeExhausted: () => Date.now() > timeDeadline,
      executeProbe: async (probe: LiveProbeRequest) => {
        const decision = runtime.authorizeProbe(mode, {
          id: liveTarget.id,
          kind: 'http',
          environment: liveTarget.environment,
          baseUrl: liveTarget.baseUrl,
        }, {
          kind: 'http_request',
          timeoutMs: 15_000,
          method: probe.http?.method,
          body: probe.http?.body,
        });
        if (!decision.allowed) {
          await evidenceStore.appendEvent('mythos_probe_proposed', {
            campaignId,
            findingId: probe.findingId,
            method: probe.http?.method,
            path: probe.http?.path,
            rejected: true,
            reason: decision.reason,
          });
          return { rejected: true as const, reason: decision.reason ?? 'not_authorized' };
        }
        probesUsed += 1;
        await evidenceStore.appendEvent('mythos_probe_proposed', {
          campaignId,
          findingId: probe.findingId,
          method: probe.http?.method,
          path: probe.http?.path,
          rejected: false,
        });
        const results = await executeLiveProbeBatch([probe], {
          baseUrl: liveTarget.baseUrl ?? '',
          identityLadder,
          rateLimiter,
          mutationJournal,
          canaries,
          allowMutations,
          dryRunMutations: dryRun,
          strictProbes,
          onEvent: liveReplayEventHandler,
          entityInventory,
        });
        const result = results[0];
        if (!result) {
          return { rejected: true as const, reason: 'no_result' };
        }
        result.origin = 'mythos';
        knownProbeIds.add(result.probeId);
        const pathKey = `${result.request.method.toUpperCase()} ${(() => {
          try {
            return new URL(result.request.url, liveTarget.baseUrl).pathname;
          } catch {
            return result.request.url;
          }
        })()}`;
        if (!initialHypothesisPaths.has(pathKey)) {
          onNonHypothesisProbe();
        }
        return result;
      },
      submitHypothesis: async (h: SubmittedHypothesis) => {
        // Section 7.1 — parse worker source refs into typed SourceLocationRef.
        const hypSourceLocationRefs: SourceLocationRef[] = [];
        for (const raw of h.sourceRefs) {
          const parsed = parseSourceRef(raw);
          if (parsed) {
            hypSourceLocationRefs.push({
              ...parsed,
              path: toWorkspaceRelative(parsed.path, liveTarget.repoRoot ?? ''),
            });
          }
        }
        memory.hypotheses.push({
          id: h.id,
          synthesizedAt: new Date().toISOString(),
          iteration: 0,
          description: h.description,
          severity: h.severity,
          signalIds: [],
          prerequisites: [],
          boundaryCrossing: undefined,
          privilegeDelta: undefined,
          status: 'proposed',
          attempts: [],
          finding: undefined,
          sourceLocationRefs: hypSourceLocationRefs.length > 0 ? hypSourceLocationRefs : undefined,
        });
        await evidenceStore.appendEvent('mythos_hypothesis_proposed', {
          campaignId,
          hypothesisId: h.id,
          severity: h.severity,
          sourceRefs: h.sourceRefs,
        });
      },
      submitFinding: async (f: SubmittedFinding) => {
        const violation = validateFindingEvidenceRefs(f, knownProbeIds);
        if (violation) {
          await evidenceStore.appendEvent('mythos_finding_proposed', {
            campaignId,
            accepted: false,
            reason: violation,
            severity: f.severity,
          });
          return { accepted: false, reason: violation };
        }
        // Spec §2.4 — accepted Mythos findings must reach the focused
        // closure stage. Append into memory.findings so FocusedClosureStage
        // picks them up as candidates during stage 5.2.
        // Section 7.1 — parse worker source refs into typed SourceLocationRef.
        const findingSourceLocationRefs: SourceLocationRef[] = [];
        for (const raw of f.sourceRefs) {
          const parsed = parseSourceRef(raw);
          if (parsed) {
            findingSourceLocationRefs.push({
              ...parsed,
              path: toWorkspaceRelative(parsed.path, liveTarget.repoRoot ?? ''),
            });
          }
        }
        memory.findings.push({
          confirmedAt: new Date().toISOString(),
          iteration: 0,
          description: f.description,
          severity: f.severity,
          reproductionSteps: f.reproductionSteps,
          remediationSuggestion: f.remediationSuggestion,
          involvedDormantReactivation: false,
          sourceLocationRefs: findingSourceLocationRefs.length > 0 ? findingSourceLocationRefs : undefined,
        });
        await evidenceStore.appendEvent('mythos_finding_proposed', {
          campaignId,
          accepted: true,
          severity: f.severity,
          evidenceRefs: f.evidenceRefs,
          sourceRefs: f.sourceRefs,
        });
        return { accepted: true };
      },
    };
  }
}
