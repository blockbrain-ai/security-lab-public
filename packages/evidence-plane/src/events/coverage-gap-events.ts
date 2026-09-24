/**
 * Coverage gap event contracts — typed shapes for probe-level degradation
 * events introduced in Section 3.1.
 *
 * Coverage gaps are not findings and not refutations. They record that a
 * probe could not run for a specific, structured reason so the operator
 * can see what was tested and what was not.
 */

// ---------------------------------------------------------------------------
// Coverage gap reason codes (closed enum)
// ---------------------------------------------------------------------------

export type CoverageGapReasonCode =
  | 'identity_missing'
  | 'mutation_rollback_missing'
  | 'test_synthesis_compile_retry_exhausted'
  | 'live_target_unreachable'
  | 'worker_unavailable'
  | 'auth_bootstrap_unavailable'
  | 'auth_bootstrap_refused_production_secret'
  | 'followup_budget_exhausted'
  | 'mythos_probe_budget_exhausted'
  | 'mythos_time_budget_exhausted'
  | 'mythos_rate_budget_exhausted'
  | 'parameter_unresolved';

/**
 * All valid reason codes as a runtime array for validation.
 */
export const COVERAGE_GAP_REASON_CODES: readonly CoverageGapReasonCode[] = [
  'identity_missing',
  'mutation_rollback_missing',
  'test_synthesis_compile_retry_exhausted',
  'live_target_unreachable',
  'worker_unavailable',
  'auth_bootstrap_unavailable',
  'auth_bootstrap_refused_production_secret',
  'followup_budget_exhausted',
  'mythos_probe_budget_exhausted',
  'mythos_time_budget_exhausted',
  'mythos_rate_budget_exhausted',
  'parameter_unresolved',
] as const;

// ---------------------------------------------------------------------------
// Coverage gap event payload
// ---------------------------------------------------------------------------

export interface CoverageGapEventPayload {
  /** Reason code from the closed enum. */
  code: CoverageGapReasonCode;
  /** Probe or finding ID that could not run. */
  probeId?: string;
  /** Identity that was missing or refused. */
  identityId?: string;
  /** Human-readable reason string. */
  reason: string;
  /** Additional context (e.g. the method/path for a dry-run probe). */
  context?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Dry-run probe event payload
// ---------------------------------------------------------------------------

export interface DryRunProbeEventPayload {
  probeId: string;
  findingId: string;
  identityId: string;
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
  reason: string;
}

// ---------------------------------------------------------------------------
// Coverage gap event stage names
// ---------------------------------------------------------------------------

export const COVERAGE_GAP_EVENT_STAGES = {
  COVERAGE_GAP: 'coverage_gap',
  DRY_RUN_PROBE: 'dry_run_probe',
} as const;

// ---------------------------------------------------------------------------
// Entity inventory event stages (Section 11.1)
// ---------------------------------------------------------------------------

export const ENTITY_INVENTORY_EVENT_STAGES = {
  ENTITY_INVENTORY_SEEDED: 'entity_inventory_seeded',
  ENTITY_INVENTORY_DISCOVERED: 'entity_inventory_discovered',
  PROBE_PARAMETER_RESOLUTION_FAILED: 'probe_parameter_resolution_failed',
  PROBE_PARAMETER_RESOLUTION_SUCCEEDED: 'probe_parameter_resolution_succeeded',
} as const;

// ---------------------------------------------------------------------------
// Entity inventory event payloads (Section 11.1)
// ---------------------------------------------------------------------------

export interface EntityInventorySeededPayload {
  /** Number of entities seeded. */
  count: number;
  /** Entity kinds that were seeded. */
  kinds: string[];
  /** Source of the seed (e.g. 'target_profile', 'auth_bootstrap'). */
  source: string;
}

export interface EntityInventoryDiscoveredPayload {
  /** The entity kind discovered. */
  kind: string;
  /** The parameter name, if applicable. */
  parameterName?: string;
  /** Where the entity was discovered (e.g. 'response:/api/auth/login'). */
  source: string;
  /** Provenance tag. */
  provenance: string;
}

export interface ProbeParameterResolutionFailedPayload {
  /** Probe or finding ID. */
  probeId?: string;
  /** The original path with unresolved placeholders. */
  originalPath: string;
  /** Which placeholders could not be resolved. */
  unresolvedParameters: string[];
  /** Whether any of the unresolved parameters were critical. */
  hasCriticalUnresolved: boolean;
}

export interface ProbeParameterResolutionSucceededPayload {
  /** Probe or finding ID. */
  probeId?: string;
  /** The original path before resolution. */
  originalPath: string;
  /** The resolved path. */
  resolvedPath: string;
  /** Number of parameters resolved. */
  resolvedCount: number;
}

// ---------------------------------------------------------------------------
// Remediation hints (one-line per reason code)
// ---------------------------------------------------------------------------

export const COVERAGE_GAP_REMEDIATION_HINTS: Record<CoverageGapReasonCode, string> = {
  identity_missing: 'Set the required identity environment variable (e.g. TARGET_USER_A_TOKEN) or configure authBootstrap in the target profile.',
  mutation_rollback_missing: 'Declare a rollback path in the target profile or use --allow-local-mutations to permit mutations without rollback.',
  test_synthesis_compile_retry_exhausted: 'Check that the suspect file compiles independently; the synthesizer could not produce a valid test after 3 attempts.',
  live_target_unreachable: 'Verify the target is running and accessible at the declared baseUrl.',
  worker_unavailable: 'Install the required CLI worker (claude_code or codex_cli) or use a different transport.',
  auth_bootstrap_unavailable: 'Set the issuer secret env var declared in the target profile authBootstrap section.',
  auth_bootstrap_refused_production_secret: 'The issuer secret contains production markers. Use a test/canary issuer secret instead.',
  followup_budget_exhausted: 'Adaptive follow-up probes were generated but the live rate-limiter budget was exhausted. Increase maxRequestsPerCampaign or reduce adaptive exploration breadth.',
  mythos_probe_budget_exhausted: 'The Mythos creativity sub-lane hit its per-invocation probe budget. Increase liveProbing.mythos.probeBudget or reduce the sub-lane breadth.',
  mythos_time_budget_exhausted: 'The Mythos creativity sub-lane exceeded its time budget. Increase liveProbing.mythos.timeBudgetMs or narrow the prompt.',
  mythos_rate_budget_exhausted: 'The Mythos sub-lane was skipped because the rate-limiter budget for the local-live lane was already exhausted.',
  parameter_unresolved: 'A probe required entity parameters (e.g. :companyId, :userId) that could not be resolved from the entity inventory. Seed the values in the target profile or ensure bootstrap/runtime discovery populates them.',
};
