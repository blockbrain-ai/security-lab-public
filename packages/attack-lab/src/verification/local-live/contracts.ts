/**
 * Local live verification contracts — types for HTTP and runtime
 * surface confirmation against a locally-running instance with
 * canary harnesses and reversible mutations.
 */

import type { VerificationVerdict } from '../shared/contracts.js';

// ---------------------------------------------------------------------------
// Live probe request
// ---------------------------------------------------------------------------

export interface LiveProbeRequest {
  /** Finding ID being verified. */
  findingId: string;
  /** Hypothesis to test. */
  hypothesis: string;
  /** What kind of probe to run. */
  probeKind: 'http' | 'process' | 'persistence' | 'browser';
  /** Identity to use (matches an entry in the target's identity ladder). */
  identityId: string;
  /** Optional explanation of why this probe was generated. */
  rationale?: string;
  /** Section 11.2 — probe family that generated this probe. */
  probeFamily?: string;
  /** Section 11.2 — variant key within the family. */
  probeVariant?: string;
  /** HTTP probe parameters if applicable. */
  http?: {
    method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD';
    path: string;
    headers?: Record<string, string>;
    body?: string;
  };
  /** Expected result profile when the system is behaving safely. */
  expectedWhenSafe?: ExpectedResponse;
  /** Expected result profile when the system is exploitable. */
  expectedWhenExploitable?: ExpectedResponse;
  /** Process probe parameters if applicable. */
  process?: {
    action: 'env_scan' | 'fd_scan' | 'proc_self_read' | 'credential_search';
    searchPatterns?: string[];
  };
  /** Persistence probe parameters if applicable. */
  persistence?: {
    action: 'cron_check' | 'launchd_check' | 'background_process_check' | 'startup_check';
  };
}

// ---------------------------------------------------------------------------
// Canary specification
// ---------------------------------------------------------------------------

export interface CanarySpec {
  id: string;
  description: string;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD';
  path: string;
  headers?: Record<string, string>;
  body?: string;
  expectedWhenSafe: ExpectedResponse;
  expectedWhenExploitable: ExpectedResponse;
  identityId?: string;
}

export interface ExpectedResponse {
  status?: number;
  statusIn?: number[];
  bodyContains?: string[];
  bodyNotContains?: string[];
}

// ---------------------------------------------------------------------------
// Identity ladder
// ---------------------------------------------------------------------------

export interface IdentitySpec {
  id: string;
  kind: 'anonymous' | 'session_cookie' | 'bearer_token' | 'api_key' | 'iap_header';
  cookieEnv?: string;
  tokenEnv?: string;
  apiKeyEnv?: string;
  organizationId?: string;
  expectedRole?: string;
  expectedScope?: string;
}

// ---------------------------------------------------------------------------
// Seed data
// ---------------------------------------------------------------------------

export interface SeedTenant {
  id: string;
  metadata?: Record<string, unknown>;
}

export interface SeedRecord {
  id: string;
  tenantId: string;
  type?: string;
  metadata?: Record<string, unknown>;
}

export interface SeedDataSpec {
  tenants: SeedTenant[];
  records: SeedRecord[];
}

// ---------------------------------------------------------------------------
// Rollback
// ---------------------------------------------------------------------------

export interface RollbackCommand {
  method: 'DELETE' | 'POST';
  path: string;
  headers?: Record<string, string>;
  body?: string;
}

export interface RollbackSpec {
  strategy: 'api_cleanup' | 'snapshot_restore' | 'manual';
  commands?: RollbackCommand[];
}

// ---------------------------------------------------------------------------
// Probe origin (Section 6.1)
// ---------------------------------------------------------------------------

/**
 * How a live probe entered the round queue.
 *
 * - `hypothesis`: translated from a static hypothesis by the hypothesis
 *   translator.
 * - `adaptive`: proposed by the follow-up generator in response to a
 *   surprising live response.
 * - `canary`: part of the canary harness that runs before hypothesis
 *   probes.
 * - `mythos`: Section 6.2 — proposed by the Mythos creativity sub-lane,
 *   routed through the worker orchestrator so it stays distinct from
 *   hypothesis and adaptive probes for reporting and finding provenance.
 */
export type ProbeOrigin = 'hypothesis' | 'adaptive' | 'canary' | 'mythos';

// ---------------------------------------------------------------------------
// Adaptive exploration configuration (Section 6.1)
// ---------------------------------------------------------------------------

export interface AdaptiveExplorationConfig {
  /** When false, adaptive exploration is fully disabled for the lane. */
  enabled: boolean;
  /** Max follow-up probes generated per surprising response. */
  maxFollowupsPerSurprise: number;
  /** Max hypotheses synthesized mid-round, per round. */
  maxMidRoundHypotheses: number;
}

export const DEFAULT_ADAPTIVE_EXPLORATION_CONFIG: AdaptiveExplorationConfig = {
  enabled: true,
  maxFollowupsPerSurprise: 3,
  maxMidRoundHypotheses: 5,
};

// ---------------------------------------------------------------------------
// Route-kind classification (Section 11.3)
// ---------------------------------------------------------------------------

/**
 * Inferred kind of the route/endpoint that responded.
 * Used by the assertion classifier to avoid treating SPA shells,
 * redirects, or static assets as meaningful API responses.
 */
export type RouteKind =
  | 'json_api'
  | 'spa_shell'
  | 'html_page'
  | 'asset_static'
  | 'redirect_bootstrap'
  | 'websocket_upgrade'
  | 'unknown';

// ---------------------------------------------------------------------------
// Assertion-based classification (Section 11.3)
// ---------------------------------------------------------------------------

/**
 * Reason the classifier chose a particular outcome. Stored in evidence
 * so reviewers can see *why* a probe was classified the way it was.
 */
export type ClassificationReason =
  | 'spa_fallback'
  | 'empty_authorized_state'
  | 'explicit_refutation'
  | 'response_shape_match'
  | 'response_shape_mismatch'
  | 'redirect_not_confirmation'
  | 'static_asset_not_confirmation'
  | 'websocket_upgrade_not_confirmation'
  | 'identity_differential_match'
  | 'identity_differential_no_change'
  | 'negative_control_passed'
  | 'canary_match';

/**
 * Full classification output from the assertion classifier.
 */
export interface AssertionClassification {
  /** Final verdict after assertion checks. */
  verdict: import('../shared/contracts.js').VerificationVerdict;
  /** Primary reason for this classification. */
  reason: ClassificationReason;
  /** Human-readable explanation. */
  explanation: string;
  /** Detected route kind. */
  routeKind: RouteKind;
  /** Whether this counts as a meaningful attempt for accounting. */
  isMeaningfulAttempt: boolean;
}

// ---------------------------------------------------------------------------
// Probe sequence (Section 11.4)
// ---------------------------------------------------------------------------

/**
 * A single step within a multi-step probe sequence. Each step can
 * extract named outputs from the response and reference outputs
 * from prior steps via `{{stepRef.outputName}}` placeholders.
 */
export interface ProbeSequenceStep {
  /** Unique step identifier within the sequence. */
  stepId: string;
  /** Human-readable label for this step. */
  label: string;
  /** HTTP parameters for this step. */
  http: {
    method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD';
    path: string;
    headers?: Record<string, string>;
    body?: string;
  };
  /** Identity to use for this step. When omitted, uses the sequence default. */
  identityId?: string;
  /**
   * Named outputs to extract from the response. Each key is a name
   * and the value is a JSONPath-like dot-path or a regex with a
   * named capture group.
   */
  extractOutputs?: Record<string, OutputExtractor>;
  /** Per-step assertion — if present, verdict is computed per step. */
  expectedWhenSafe?: ExpectedResponse;
  expectedWhenExploitable?: ExpectedResponse;
}

/**
 * How to extract a named value from a step response.
 * - `jsonPath`: a dot-separated path into the parsed JSON body (e.g. `data.token`).
 * - `regex`: a regular expression with a named capture group (e.g. `"token":"(?<value>[^"]+)"`).
 * - `header`: extract from a response header.
 */
export type OutputExtractor =
  | { kind: 'jsonPath'; path: string }
  | { kind: 'regex'; pattern: string }
  | { kind: 'header'; headerName: string };

/**
 * A multi-step probe sequence definition. Steps execute in order;
 * each step can reference outputs from earlier steps.
 */
export interface ProbeSequenceDefinition {
  /** Unique sequence identifier. */
  sequenceId: string;
  /** Finding being verified. */
  findingId: string;
  /** Hypothesis the sequence tests. */
  hypothesis: string;
  /** Probe family (Section 11.2). */
  probeFamily?: string;
  /** Probe variant (Section 11.2). */
  probeVariant?: string;
  /** Default identity for steps that don't override. */
  defaultIdentityId: string;
  /** Ordered steps. */
  steps: ProbeSequenceStep[];
  /** Rollback commands to execute after the sequence completes. */
  rollback?: RollbackCommand[];
}

/**
 * Result of executing one step within a sequence.
 */
export interface ProbeSequenceStepResult {
  stepId: string;
  label: string;
  /** Extracted output values (name → value). */
  extractedOutputs: Record<string, string>;
  /** The underlying probe execution result. */
  probeResult: LiveExecutionResult;
}

/**
 * Result of executing a complete multi-step sequence.
 */
export interface ProbeSequenceResult {
  sequenceId: string;
  findingId: string;
  hypothesis: string;
  /** Per-step results in execution order. */
  stepResults: ProbeSequenceStepResult[];
  /** Sequence-level verdict: confirmed if any step confirmed and none
   *  had a blocking failure; refuted if the final step refuted; etc. */
  verdict: import('../shared/contracts.js').VerificationVerdict;
  /** Human-readable reasoning for the sequence-level verdict. */
  reasoning: string;
  /** Whether rollback was executed after the sequence. */
  rollbackExecuted: boolean;
  rollbackResult?: string;
  /** Total duration across all steps. */
  totalDurationMs: number;
}

// ---------------------------------------------------------------------------
// Identity differential (Section 11.4)
// ---------------------------------------------------------------------------

/**
 * Configuration for running identity-differential execution.
 * The same probe or sequence runs across multiple identities
 * and the results are compared.
 */
export interface IdentityDifferentialConfig {
  /** Identities to compare. At least two required. */
  identityIds: string[];
  /** When true, also runs a sequence rather than a single probe. */
  sequenceMode?: boolean;
}

/**
 * Per-identity result within a differential run.
 */
export interface IdentityDifferentialEntry {
  identityId: string;
  /** Single-probe result (when not in sequence mode). */
  probeResult?: LiveExecutionResult;
  /** Sequence result (when in sequence mode). */
  sequenceResult?: ProbeSequenceResult;
}

/**
 * A delta between two identity results within a differential.
 */
export interface IdentityDelta {
  identityA: string;
  identityB: string;
  statusDelta: { a: number; b: number } | null;
  bodyDiffers: boolean;
  verdictA: import('../shared/contracts.js').VerificationVerdict;
  verdictB: import('../shared/contracts.js').VerificationVerdict;
  privilegeEscalationDetected: boolean;
  explanation: string;
}

/**
 * Result of running a probe or sequence across multiple identities.
 */
export interface IdentityDifferentialResult {
  findingId: string;
  hypothesis: string;
  entries: IdentityDifferentialEntry[];
  deltas: IdentityDelta[];
  /** Overall verdict: confirmed if any delta shows privilege escalation. */
  verdict: import('../shared/contracts.js').VerificationVerdict;
  reasoning: string;
}

// ---------------------------------------------------------------------------
// Sequence summary for reporting (Section 11.4)
// ---------------------------------------------------------------------------

/**
 * Summary statistics for sequence and identity-differential execution,
 * attached to the lane summary for report rendering.
 */
export interface SequenceExecutionSummary {
  /** Total sequences executed. */
  sequencesExecuted: number;
  /** Total sequence steps executed across all sequences. */
  totalStepsExecuted: number;
  /** Sequences that produced a confirmed verdict. */
  sequencesConfirmed: number;
  /** Sequences that produced a refuted verdict. */
  sequencesRefuted: number;
  /** Sequences with inconclusive outcome. */
  sequencesInconclusive: number;
  /** Total identity differentials executed. */
  differentialsExecuted: number;
  /** Differentials that detected privilege escalation. */
  differentialsWithEscalation: number;
  /** Steps where extracted outputs were consumed by later steps. */
  statePassthroughCount: number;
  /** Rollbacks executed after sequences. */
  rollbacksExecuted: number;
}

// ---------------------------------------------------------------------------
// Live execution result
// ---------------------------------------------------------------------------

export interface LiveExecutionResult {
  probeId: string;
  findingId: string;
  identityId: string;
  /** Section 6.1 — how this probe entered the round queue. */
  origin?: ProbeOrigin;
  request: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
  };
  response: {
    status: number;
    headers: Record<string, string>;
    body: string;
    durationMs: number;
  };
  canaryMatched?: 'safe' | 'exploitable' | 'neither';
  rollbackExecuted: boolean;
  rollbackResult?: string;
  verdict: VerificationVerdict;
  reasoning: string;
  /** Section 11.3 — assertion-based classification details. */
  classification?: AssertionClassification;
}

// ---------------------------------------------------------------------------
// Live verdict (per finding)
// ---------------------------------------------------------------------------

export interface LiveVerdict {
  findingId: string;
  verdict: VerificationVerdict;
  transitionsTested: string[];
  confirmedTransitions: string[];
  canaryResults: Array<{ canaryId: string; matched: 'safe' | 'exploitable' | 'neither' }>;
  reasoning: string;
  evidenceRefs: string[];
}

// ---------------------------------------------------------------------------
// Browser exploit family summary (Section 12.2)
// ---------------------------------------------------------------------------

// The canonical BrowserExploitFamilySummaryRecord lives in
// evidence-plane/src/investigation-report.ts (SL1 — single definition).
// Import it from there when needed for report rendering.
