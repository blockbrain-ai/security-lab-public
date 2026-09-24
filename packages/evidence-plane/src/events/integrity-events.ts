/**
 * Integrity event payload contracts — typed shapes for the execution
 * integrity events introduced in Section 1.1.
 *
 * These are additive to the evidence-plane event stream. Existing event
 * types remain unchanged; these are new stage/payload names only.
 */

// ---------------------------------------------------------------------------
// Stage boundary events
// ---------------------------------------------------------------------------

export interface StageStartedPayload {
  stage: string;
  campaignId: string;
  startedAt: string;
  resumedFrom?: string | null;
}

export interface StageCompletedPayload {
  stage: string;
  campaignId: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  summary?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Writer lock events
// ---------------------------------------------------------------------------

export interface WriterLockContentionPayload {
  campaignId: string;
  existingLock: {
    pid: number;
    hostname: string;
    acquiredAt: string;
    campaignId: string;
  };
  currentPid: number;
  currentHostname: string;
}

export interface WriterLockReclaimedPayload {
  campaignId: string;
  oldLock: {
    pid: number;
    hostname: string;
    acquiredAt: string;
    campaignId: string;
  };
  newLock: {
    pid: number;
    hostname: string;
    acquiredAt: string;
    campaignId: string;
  };
}

// ---------------------------------------------------------------------------
// Provider timeout event
// ---------------------------------------------------------------------------

export interface ProviderTimeoutPayload {
  provider: string;
  model: string;
  role?: string;
  elapsedMs: number;
  timeoutMs: number;
  label: string;
}

// ---------------------------------------------------------------------------
// Heartbeat events
// ---------------------------------------------------------------------------

export interface HeartbeatPayload {
  stage: string;
  role?: string;
  elapsedMs: number;
  lastActivityAt: string;
  expectedTimeoutMs?: number;
}

// ---------------------------------------------------------------------------
// Preflight doctor events
// ---------------------------------------------------------------------------

export interface PreflightCheckResult {
  id: string;
  status: 'pass' | 'fail' | 'skip';
  message: string;
  details?: string;
}

export interface PreflightReportPayload {
  campaignId: string;
  mode: string;
  checks: PreflightCheckResult[];
  allPassed: boolean;
}

export interface PreflightFailedPayload {
  campaignId: string;
  mode: string;
  failedChecks: PreflightCheckResult[];
}

// ---------------------------------------------------------------------------
// Integrity event stage names (for use with EvidenceStore.appendEvent)
// ---------------------------------------------------------------------------

export const INTEGRITY_EVENT_STAGES = {
  STAGE_STARTED: 'stage_started',
  STAGE_COMPLETED: 'stage_completed',
  WRITER_LOCK_CONTENTION: 'writer_lock_contention',
  WRITER_LOCK_RECLAIMED: 'writer_lock_reclaimed',
  PROVIDER_TIMEOUT: 'provider_timeout',
  HEARTBEAT: 'heartbeat',
  PREFLIGHT_REPORT: 'preflight_report',
  PREFLIGHT_FAILED: 'preflight_failed',
} as const;
