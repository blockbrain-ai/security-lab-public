import { z } from 'zod';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type DegradationLevel = 0 | 1 | 2 | 3;

export const AnomalyKindSchema = z.enum([
  'format_repair',
  'context_exhaustion',
  'tool_loop',
  'evidence_fabrication',
  'docker_failure',
  'no_progress',
]);
export type AnomalyKind = z.infer<typeof AnomalyKindSchema>;

export interface AnomalyEvent {
  at: string;
  kind: AnomalyKind;
  candidateId?: string;
  detail?: string;
}

export interface DegradationState {
  currentLevel: DegradationLevel;
  escalatedAt?: string;
  anomalyCounts: Record<AnomalyKind, number>;
  anomalyHistory: AnomalyEvent[];
  levelHistory: Array<{ level: DegradationLevel; at: string; trigger: string }>;
  lastActivityAt: string;
}

export interface DegradationThresholds {
  formatRepairLimit: number;
  contextExhaustionLimit: number;
  toolLoopLimit: number;
  fabricationLimit: number;
  dockerFailureLimit: number;
  noProgressTimeoutMs: number;
  cumulativeHaltThreshold: number;
}

export interface DegradationBehavior {
  enableAudit: boolean;
  enableSecondaryFollowups: boolean;
  allowBorderlineRuntimeEscalation: boolean;
  allowNonCriticalRuntime: boolean;
  halt: boolean;
  description: string;
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

export const DEFAULT_THRESHOLDS: DegradationThresholds = {
  formatRepairLimit: 4,
  contextExhaustionLimit: 3,
  toolLoopLimit: 3,
  fabricationLimit: 2,
  dockerFailureLimit: 3,
  noProgressTimeoutMs: 900_000,
  cumulativeHaltThreshold: 10,
};

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createDegradationState(): DegradationState {
  return {
    currentLevel: 0,
    anomalyCounts: {
      format_repair: 0,
      context_exhaustion: 0,
      tool_loop: 0,
      evidence_fabrication: 0,
      docker_failure: 0,
      no_progress: 0,
    },
    anomalyHistory: [],
    levelHistory: [{ level: 0, at: new Date().toISOString(), trigger: 'init' }],
    lastActivityAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Behavior per level
// ---------------------------------------------------------------------------

export function behaviorForLevel(level: DegradationLevel): DegradationBehavior {
  switch (level) {
    case 0:
      return {
        enableAudit: true,
        enableSecondaryFollowups: true,
        allowBorderlineRuntimeEscalation: true,
        allowNonCriticalRuntime: true,
        halt: false,
        description: 'normal',
      };
    case 1:
      return {
        enableAudit: false,
        enableSecondaryFollowups: false,
        allowBorderlineRuntimeEscalation: true,
        allowNonCriticalRuntime: true,
        halt: false,
        description: 'conservative — audit and defense critic disabled',
      };
    case 2:
      return {
        enableAudit: false,
        enableSecondaryFollowups: false,
        allowBorderlineRuntimeEscalation: false,
        allowNonCriticalRuntime: false,
        halt: false,
        description: 'bounded — only critical-tier runtime candidates',
      };
    case 3:
      return {
        enableAudit: false,
        enableSecondaryFollowups: false,
        allowBorderlineRuntimeEscalation: false,
        allowNonCriticalRuntime: false,
        halt: true,
        description: 'halt — remaining candidates skipped',
      };
  }
}

// ---------------------------------------------------------------------------
// Gate-result to anomaly mapping
// ---------------------------------------------------------------------------

export function gateClassToAnomalyKind(failureClass: string): AnomalyKind | null {
  if (
    failureClass.startsWith('format_') ||
    failureClass === 'schema_mismatch' ||
    failureClass === 'partial_schema_mismatch'
  ) {
    return 'format_repair';
  }
  if (failureClass === 'context_exhaustion') return 'context_exhaustion';
  if (failureClass === 'tool_loop_stall') return 'tool_loop';
  if (failureClass === 'evidence_fabricated') return 'evidence_fabrication';
  return null;
}

// ---------------------------------------------------------------------------
// Anomaly recording + escalation
// ---------------------------------------------------------------------------

function cumulativeCount(counts: Record<AnomalyKind, number>): number {
  return Object.values(counts).reduce((s, n) => s + n, 0);
}

function tryEscalate(
  state: DegradationState,
  thresholds: DegradationThresholds,
  triggerKind: string,
): { escalated: boolean; newLevel: DegradationLevel } {
  const counts = state.anomalyCounts;
  const cumulative = cumulativeCount(counts);
  let targetLevel: DegradationLevel = state.currentLevel;

  // L0 → L1 checks
  if (state.currentLevel < 1) {
    if (
      counts.format_repair >= thresholds.formatRepairLimit ||
      counts.context_exhaustion >= thresholds.contextExhaustionLimit ||
      counts.tool_loop >= thresholds.toolLoopLimit
    ) {
      targetLevel = 1;
    }
  }

  // L1 → L2 checks
  if (state.currentLevel < 2 && targetLevel < 2) {
    if (
      counts.evidence_fabrication >= thresholds.fabricationLimit ||
      counts.docker_failure >= thresholds.dockerFailureLimit ||
      cumulative >= Math.floor(thresholds.cumulativeHaltThreshold / 2)
    ) {
      targetLevel = Math.max(targetLevel, 2) as DegradationLevel;
    }
  }

  // L2 → L3 checks
  if (state.currentLevel < 3 && targetLevel < 3) {
    if (cumulative >= thresholds.cumulativeHaltThreshold) {
      targetLevel = 3;
    }
  }

  if (targetLevel > state.currentLevel) {
    const now = new Date().toISOString();
    state.currentLevel = targetLevel;
    state.escalatedAt = now;
    state.levelHistory.push({ level: targetLevel, at: now, trigger: triggerKind });
    return { escalated: true, newLevel: targetLevel };
  }

  return { escalated: false, newLevel: state.currentLevel };
}

export function recordAnomaly(
  state: DegradationState,
  event: AnomalyEvent,
  thresholds: DegradationThresholds = DEFAULT_THRESHOLDS,
): { state: DegradationState; escalated: boolean; newLevel: DegradationLevel } {
  state.anomalyCounts[event.kind] = (state.anomalyCounts[event.kind] ?? 0) + 1;
  state.anomalyHistory.push(event);

  const result = tryEscalate(state, thresholds, event.kind);
  return { state, ...result };
}

export function recordProgress(
  state: DegradationState,
  at: string = new Date().toISOString(),
): DegradationState {
  state.lastActivityAt = at;
  return state;
}

export function checkNoProgressTimeout(
  state: DegradationState,
  lastActivityAt: string,
  now: string,
  thresholds: DegradationThresholds = DEFAULT_THRESHOLDS,
): { state: DegradationState; escalated: boolean; newLevel: DegradationLevel } {
  const elapsed = new Date(now).getTime() - new Date(lastActivityAt).getTime();
  if (elapsed < thresholds.noProgressTimeoutMs) {
    return { state, escalated: false, newLevel: state.currentLevel };
  }

  if (state.currentLevel >= 3) {
    return { state, escalated: false, newLevel: state.currentLevel };
  }

  const event: AnomalyEvent = {
    at: now,
    kind: 'no_progress',
    detail: `No activity for ${Math.round(elapsed / 1000)}s`,
  };
  state.anomalyCounts.no_progress = (state.anomalyCounts.no_progress ?? 0) + 1;
  state.anomalyHistory.push(event);

  // no_progress jumps to L3 if already at L2, else to L2
  const targetLevel: DegradationLevel = state.currentLevel >= 2 ? 3 : Math.max(state.currentLevel + 1, 2) as DegradationLevel;
  if (targetLevel > state.currentLevel) {
    state.currentLevel = targetLevel;
    state.escalatedAt = now;
    state.levelHistory.push({ level: targetLevel, at: now, trigger: 'no_progress' });
    return { state, escalated: true, newLevel: targetLevel };
  }

  return { state, escalated: false, newLevel: state.currentLevel };
}
