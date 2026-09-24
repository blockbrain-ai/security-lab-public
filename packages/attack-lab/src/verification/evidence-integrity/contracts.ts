/**
 * Evidence and evaluator integrity contracts — types for proving that
 * the scoring/reporting layers themselves have not been tampered with.
 * Catches cases where a finding looks "refuted" because someone moved
 * the ruler, not because the system is safe.
 */

// ---------------------------------------------------------------------------
// Policy and rubric drift
// ---------------------------------------------------------------------------

export interface PolicySnapshot {
  policyVersion: string;
  policyHash: string;
  rubricHash: string;
  capturedAt: string;
}

export interface PolicyDrift {
  previous: PolicySnapshot;
  current: PolicySnapshot;
  changedFields: string[];
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  reason: string;
}

// ---------------------------------------------------------------------------
// Scorer integrity
// ---------------------------------------------------------------------------

export interface ScorerIntegrityResult {
  scorerId: string;
  expectedHash: string;
  observedHash: string;
  intact: boolean;
  notes: string;
}

// ---------------------------------------------------------------------------
// Replay verification
// ---------------------------------------------------------------------------

export interface ReportReplayResult {
  reportId: string;
  originalVerdictHash: string;
  replayedVerdictHash: string;
  matches: boolean;
  /** Per-finding deltas if the replayed verdict differs. */
  deltas: Array<{
    findingId: string;
    field: string;
    original: unknown;
    replayed: unknown;
  }>;
  notes: string;
}

// ---------------------------------------------------------------------------
// Top-level evaluator integrity verdict
// ---------------------------------------------------------------------------

export type EvaluatorIntegrityVerdict = 'clean' | 'drift_detected' | 'tampered' | 'not_applicable';

export interface EvaluatorIntegrityReport {
  verdict: EvaluatorIntegrityVerdict;
  policyDrifts: PolicyDrift[];
  scorerResults: ScorerIntegrityResult[];
  replayResults: ReportReplayResult[];
  reasoning: string;
}
