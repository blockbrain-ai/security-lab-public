/**
 * Section 11.5 — Focused lead confirmation sessions.
 *
 * Orchestrates the handoff from static leads to persistent worker sessions.
 * Workers inspect code and artifacts directly and request probes back through
 * the orchestrator. The orchestrator retains control over live execution,
 * rollback, rate limiting, evidence capture, and final structured outcomes.
 */

import type { ChainHypothesis, CampaignMemory } from '../../autonomous/contracts.js';
import type { EvidenceStore } from '../../../../evidence-plane/src/store.js';
import type { LiveProbeRequest } from '../local-live/contracts.js';
import type { VerificationVerdict } from '../shared/contracts.js';
import { rankLeads, type LeadRankingConfig, DEFAULT_RANKING_CONFIG } from './lead-ranker.js';
import { buildLeadBrief, writeBriefManifests } from './lead-brief.js';
import type { LeadBrief } from './lead-brief.js';

// Re-export LeadBrief for consumers that import from this module.
export type { LeadBrief } from './lead-brief.js';

// ---------------------------------------------------------------------------
// Confirmation outcome statuses (spec §1.5)
// ---------------------------------------------------------------------------

/**
 * Bounded set of confirmation outcomes. Each focused lead session must
 * conclude with exactly one of these.
 */
export type ConfirmationStatus =
  | 'confirmed'
  | 'refuted'
  | 'narrowed'
  | 'needs_browser'
  | 'needs_human_setup'
  | 'insufficient_evidence';

export const CONFIRMATION_STATUSES: readonly ConfirmationStatus[] = [
  'confirmed',
  'refuted',
  'narrowed',
  'needs_browser',
  'needs_human_setup',
  'insufficient_evidence',
] as const;

export function isConfirmationStatus(value: string): value is ConfirmationStatus {
  return (CONFIRMATION_STATUSES as readonly string[]).includes(value);
}

// ---------------------------------------------------------------------------
// Worker probe request — what the worker sends back to the orchestrator
// ---------------------------------------------------------------------------

/**
 * A probe request from a focused worker back to the orchestrator.
 * The worker describes what it wants tested; the orchestrator executes it
 * with proper authorization, rollback, and evidence capture.
 */
export interface WorkerProbeRequest {
  /** Which brief/hypothesis this probe is for. */
  hypothesisId: string;
  /** Worker's rationale for requesting this probe. */
  rationale: string;
  /** The probe specification to execute. */
  probe: LiveProbeRequest;
  /** Whether this is a follow-up to a prior probe result. */
  isFollowUp: boolean;
  /** Worker session ID for attribution. */
  workerSessionId: string;
  /** Worker role: primary investigator or counter/reviewer. */
  workerRole: 'primary' | 'counter';
}

// ---------------------------------------------------------------------------
// Probe execution result — what the orchestrator returns to the worker
// ---------------------------------------------------------------------------

export interface ProbeExecutionResult {
  /** The probe that was executed. */
  probeId: string;
  /** Verdict from the assertion classifier. */
  verdict: VerificationVerdict;
  /** Observed response summary. */
  observation: string;
  /** Confidence in the verdict. */
  confidence: number;
  /** Evidence refs produced during execution. */
  evidenceRefs: string[];
  /** Whether rollback was needed and executed. */
  rollbackExecuted: boolean;
}

// ---------------------------------------------------------------------------
// Session record — tracks one focused confirmation session
// ---------------------------------------------------------------------------

export interface FocusedConfirmationSession {
  /** Session identifier. */
  sessionId: string;
  /** The hypothesis being confirmed. */
  hypothesisId: string;
  /** Brief provided to the worker. */
  brief: LeadBrief;
  /** Worker role assignments. */
  primaryWorkerId: string;
  counterWorkerId?: string;
  /** Probe requests submitted by the worker. */
  probeRequests: WorkerProbeRequest[];
  /** Probe results returned by the orchestrator. */
  probeResults: ProbeExecutionResult[];
  /** Final confirmation status. */
  status: ConfirmationStatus;
  /** Reasoning for the final status. */
  reasoning: string;
  /** Timestamp when the session started. */
  startedAt: string;
  /** Timestamp when the session concluded. */
  completedAt: string;
  /** Total probes executed in this session. */
  totalProbes: number;
}

// ---------------------------------------------------------------------------
// Orchestrator configuration
// ---------------------------------------------------------------------------

export interface FocusedConfirmationConfig {
  /** Lead ranking config. */
  ranking: LeadRankingConfig;
  /** Maximum probes per focused session. */
  maxProbesPerSession: number;
  /** Whether to assign a counter/reviewer worker. */
  useCounterWorker: boolean;
  /** Campaign directory for brief persistence. */
  campaignDir: string;
}

export const DEFAULT_CONFIRMATION_CONFIG: Omit<FocusedConfirmationConfig, 'campaignDir'> = {
  ranking: DEFAULT_RANKING_CONFIG,
  maxProbesPerSession: 10,
  useCounterWorker: false,
};

// ---------------------------------------------------------------------------
// Orchestrator result
// ---------------------------------------------------------------------------

export interface FocusedConfirmationResult {
  /** All sessions that were run. */
  sessions: FocusedConfirmationSession[];
  /** Summary counts. */
  confirmed: number;
  refuted: number;
  narrowed: number;
  needsBrowser: number;
  needsHumanSetup: number;
  insufficientEvidence: number;
  totalProbesExecuted: number;
  /** Brief paths written to disk. */
  briefPaths: string[];
}

// ---------------------------------------------------------------------------
// Probe executor callback — the orchestrator's execution boundary
// ---------------------------------------------------------------------------

/**
 * Callback the orchestrator uses to execute a worker-requested probe.
 * This is the boundary where the orchestrator retains control: it handles
 * authorization, rate limiting, rollback, and evidence capture.
 *
 * Implementations are provided by the investigation runner or test harness.
 */
export type ProbeExecutor = (
  request: WorkerProbeRequest,
) => Promise<ProbeExecutionResult>;

// ---------------------------------------------------------------------------
// Worker callback — the worker inspection/request cycle
// ---------------------------------------------------------------------------

/**
 * Callback representing a focused worker session. The worker receives
 * the brief and a function to request probes. It returns the final
 * status and reasoning. The worker is free to inspect files and artifacts
 * before/between probe requests.
 */
export type WorkerSession = (
  brief: LeadBrief,
  requestProbe: (request: Omit<WorkerProbeRequest, 'workerSessionId' | 'workerRole'>) => Promise<ProbeExecutionResult>,
  role: 'primary' | 'counter',
) => Promise<{ status: ConfirmationStatus; reasoning: string }>;

// ---------------------------------------------------------------------------
// Core orchestrator
// ---------------------------------------------------------------------------

function generateSessionId(hypothesisId: string): string {
  const ts = Date.now();
  const rand = Math.random().toString(36).slice(2, 8);
  return `fcs-${hypothesisId}-${ts}-${rand}`;
}

/**
 * Run a single focused confirmation session for one lead.
 *
 * The orchestrator:
 * 1. Provides the brief to the worker.
 * 2. Intercepts probe requests, executes them with proper controls.
 * 3. Returns results to the worker.
 * 4. Records the final structured outcome.
 */
export async function runFocusedSession(
  brief: LeadBrief,
  workerSession: WorkerSession,
  probeExecutor: ProbeExecutor,
  config: FocusedConfirmationConfig,
  evidenceStore: EvidenceStore,
  role: 'primary' | 'counter' = 'primary',
): Promise<FocusedConfirmationSession> {
  const sessionId = generateSessionId(brief.hypothesisId);
  const startedAt = new Date().toISOString();
  const probeRequests: WorkerProbeRequest[] = [];
  const probeResults: ProbeExecutionResult[] = [];
  let probeCount = 0;

  await evidenceStore.appendEvent('focused_confirmation_session_started', {
    sessionId,
    hypothesisId: brief.hypothesisId,
    role,
    rank: brief.rank,
    severity: brief.severity,
    probeFamily: brief.suggestedProbeFamily,
  });

  const requestProbe = async (
    request: Omit<WorkerProbeRequest, 'workerSessionId' | 'workerRole'>,
  ): Promise<ProbeExecutionResult> => {
    if (probeCount >= config.maxProbesPerSession) {
      return {
        probeId: 'rate-limited',
        verdict: 'rate_limited',
        observation: `Session probe limit (${config.maxProbesPerSession}) reached`,
        confidence: 0,
        evidenceRefs: [],
        rollbackExecuted: false,
      };
    }

    const fullRequest: WorkerProbeRequest = {
      ...request,
      workerSessionId: sessionId,
      workerRole: role,
    };

    probeRequests.push(fullRequest);
    probeCount++;

    const result = await probeExecutor(fullRequest);
    probeResults.push(result);

    await evidenceStore.appendEvent('focused_confirmation_probe_executed', {
      sessionId,
      hypothesisId: brief.hypothesisId,
      probeId: result.probeId,
      verdict: result.verdict,
      confidence: result.confidence,
      rollbackExecuted: result.rollbackExecuted,
    });

    return result;
  };

  const { status, reasoning } = await workerSession(brief, requestProbe, role);

  const completedAt = new Date().toISOString();

  const session: FocusedConfirmationSession = {
    sessionId,
    hypothesisId: brief.hypothesisId,
    brief,
    primaryWorkerId: sessionId,
    counterWorkerId: role === 'counter' ? sessionId : undefined,
    probeRequests,
    probeResults,
    status,
    reasoning,
    startedAt,
    completedAt,
    totalProbes: probeCount,
  };

  await evidenceStore.appendEvent('focused_confirmation_session_completed', {
    sessionId,
    hypothesisId: brief.hypothesisId,
    role,
    status,
    reasoning,
    totalProbes: probeCount,
    durationMs: new Date(completedAt).getTime() - new Date(startedAt).getTime(),
  });

  return session;
}

function confirmationStatusRank(status: ConfirmationStatus): number {
  switch (status) {
    case 'confirmed':
      return 6;
    case 'refuted':
      return 5;
    case 'needs_browser':
      return 4;
    case 'needs_human_setup':
      return 3;
    case 'narrowed':
      return 2;
    case 'insufficient_evidence':
      return 1;
  }
}

function mergeFocusedSessions(
  primary: FocusedConfirmationSession,
  counter: FocusedConfirmationSession,
): FocusedConfirmationSession {
  const finalStatus =
    confirmationStatusRank(counter.status) >= confirmationStatusRank(primary.status)
      ? counter.status
      : primary.status;

  return {
    ...primary,
    counterWorkerId: counter.counterWorkerId ?? counter.primaryWorkerId,
    probeRequests: [...primary.probeRequests, ...counter.probeRequests],
    probeResults: [...primary.probeResults, ...counter.probeResults],
    status: finalStatus,
    reasoning: `${primary.reasoning}\n\nCounter review: ${counter.reasoning}`,
    completedAt: counter.completedAt,
    totalProbes: primary.totalProbes + counter.totalProbes,
  };
}

// ---------------------------------------------------------------------------
// Full orchestration: rank → brief → worker sessions → outcomes
// ---------------------------------------------------------------------------

/**
 * Run the full focused lead confirmation workflow.
 *
 * 1. Rank top leads from static investigation.
 * 2. Build per-lead briefs and write to disk.
 * 3. Run worker sessions for each lead.
 * 4. Collect structured outcomes.
 */
export async function runFocusedConfirmation(
  memory: CampaignMemory,
  workerSessionFactory: (hypothesisId: string) => WorkerSession,
  probeExecutor: ProbeExecutor,
  config: FocusedConfirmationConfig,
  evidenceStore: EvidenceStore,
): Promise<FocusedConfirmationResult> {
  // 1. Rank
  const rankedLeads = rankLeads(memory.hypotheses, memory.signals, config.ranking);

  await evidenceStore.appendEvent('focused_confirmation_leads_ranked', {
    totalHypotheses: memory.hypotheses.length,
    rankedCount: rankedLeads.length,
    rankedIds: rankedLeads.map((r) => r.hypothesis.id),
    scores: rankedLeads.map((r) => ({ id: r.hypothesis.id, score: r.score, rank: r.rank })),
  });

  if (rankedLeads.length === 0) {
    return {
      sessions: [],
      confirmed: 0,
      refuted: 0,
      narrowed: 0,
      needsBrowser: 0,
      needsHumanSetup: 0,
      insufficientEvidence: 0,
      totalProbesExecuted: 0,
      briefPaths: [],
    };
  }

  // 2. Build briefs
  const briefs = rankedLeads.map((ranked) =>
    buildLeadBrief(ranked, memory.signals),
  );
  const writtenBriefs = await writeBriefManifests(briefs, config.campaignDir);

  // 3. Run sessions
  const sessions: FocusedConfirmationSession[] = [];
  for (const brief of writtenBriefs) {
    const worker = workerSessionFactory(brief.hypothesisId);
    const primarySession = await runFocusedSession(
      brief,
      worker,
      probeExecutor,
      config,
      evidenceStore,
    );
    if (
      config.useCounterWorker
      && primarySession.status !== 'confirmed'
      && primarySession.status !== 'refuted'
    ) {
      const counterSession = await runFocusedSession(
        brief,
        worker,
        probeExecutor,
        config,
        evidenceStore,
        'counter',
      );
      sessions.push(mergeFocusedSessions(primarySession, counterSession));
      continue;
    }

    sessions.push(primarySession);
  }

  // 4. Summarize
  const result: FocusedConfirmationResult = {
    sessions,
    confirmed: sessions.filter((s) => s.status === 'confirmed').length,
    refuted: sessions.filter((s) => s.status === 'refuted').length,
    narrowed: sessions.filter((s) => s.status === 'narrowed').length,
    needsBrowser: sessions.filter((s) => s.status === 'needs_browser').length,
    needsHumanSetup: sessions.filter((s) => s.status === 'needs_human_setup').length,
    insufficientEvidence: sessions.filter((s) => s.status === 'insufficient_evidence').length,
    totalProbesExecuted: sessions.reduce((sum, s) => sum + s.totalProbes, 0),
    briefPaths: writtenBriefs.map((b) => b.briefPath!).filter(Boolean),
  };

  await evidenceStore.appendEvent('focused_confirmation_completed', {
    sessionsRun: sessions.length,
    confirmed: result.confirmed,
    refuted: result.refuted,
    narrowed: result.narrowed,
    needsBrowser: result.needsBrowser,
    needsHumanSetup: result.needsHumanSetup,
    insufficientEvidence: result.insufficientEvidence,
    totalProbesExecuted: result.totalProbesExecuted,
  });

  return result;
}

// ---------------------------------------------------------------------------
// Hypothesis status mapping — map confirmation outcomes to hypothesis status
// ---------------------------------------------------------------------------

/**
 * Map a confirmation status to a hypothesis status mutation.
 * Used by the stage to update campaign memory after focused sessions.
 */
export function mapConfirmationToHypothesisStatus(
  status: ConfirmationStatus,
): ChainHypothesis['status'] {
  switch (status) {
    case 'confirmed':
      return 'confirmed';
    case 'refuted':
      return 'refuted';
    case 'narrowed':
    case 'needs_browser':
    case 'needs_human_setup':
    case 'insufficient_evidence':
      return 'needs_more_data';
  }
}

// ---------------------------------------------------------------------------
// Report summary record (consumed by investigation-report.ts)
// ---------------------------------------------------------------------------

export interface FocusedLeadConfirmationSummary {
  sessionsRun: number;
  confirmed: number;
  refuted: number;
  narrowed: number;
  needsBrowser: number;
  needsHumanSetup: number;
  insufficientEvidence: number;
  totalProbesExecuted: number;
  leads: Array<{
    hypothesisId: string;
    rank: number;
    severity: string;
    probeFamily: string;
    status: ConfirmationStatus;
    totalProbes: number;
  }>;
}

/**
 * Build a report-ready summary from the confirmation result.
 */
export function buildConfirmationSummary(
  result: FocusedConfirmationResult,
): FocusedLeadConfirmationSummary {
  return {
    sessionsRun: result.sessions.length,
    confirmed: result.confirmed,
    refuted: result.refuted,
    narrowed: result.narrowed,
    needsBrowser: result.needsBrowser,
    needsHumanSetup: result.needsHumanSetup,
    insufficientEvidence: result.insufficientEvidence,
    totalProbesExecuted: result.totalProbesExecuted,
    leads: result.sessions.map((s) => ({
      hypothesisId: s.hypothesisId,
      rank: s.brief.rank,
      severity: s.brief.severity,
      probeFamily: s.brief.suggestedProbeFamily,
      status: s.status,
      totalProbes: s.totalProbes,
    })),
  };
}
