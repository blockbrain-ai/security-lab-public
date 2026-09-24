/**
 * Run mode (Section 3.2) — serious vs smoke mode split.
 *
 * `smoke` mode is low-ceremony and degrades honestly when prerequisites are
 * missing. `serious-local` and `serious-end-to-end` modes are high-ceremony
 * and fail closed on missing required verification coverage.
 *
 * The existing `--mode declared|blind` flag controls evaluator visibility
 * and is completely separate from run mode.
 */

import type { CoverageGap, ExecutionStatus } from './investigation-runner.js';
// Type-only import above breaks the runtime cycle with investigation-runner.

// ---------------------------------------------------------------------------
// Enum
// ---------------------------------------------------------------------------

export const RUN_MODES = ['smoke', 'serious-local', 'serious-end-to-end'] as const;
export type RunMode = (typeof RUN_MODES)[number];

export const DEFAULT_RUN_MODE: RunMode = 'smoke';

export function isRunMode(value: unknown): value is RunMode {
  return typeof value === 'string' && (RUN_MODES as readonly string[]).includes(value);
}

/**
 * Map the legacy `--preset` portfolio flag to an implied run mode.
 * Returns `null` if the preset does not imply a run mode (e.g. diagnostic).
 */
export function inferModeFromPreset(preset: string | undefined): RunMode | null {
  switch (preset) {
    case 'serious-local':
      return 'serious-local';
    case 'serious-end-to-end':
      return 'serious-end-to-end';
    case 'smoke':
      return 'smoke';
    default:
      return null;
  }
}

/** Short human-readable description of what each mode promises. */
export function describeRunMode(mode: RunMode): string {
  switch (mode) {
    case 'smoke':
      return 'low-ceremony, best-effort; degrades honestly when prerequisites are missing';
    case 'serious-local':
      return 'high-ceremony; fails closed on missing local verification coverage';
    case 'serious-end-to-end':
      return 'high-ceremony; fails closed on missing local or hosted verification coverage';
  }
}

// ---------------------------------------------------------------------------
// Coverage evaluation
// ---------------------------------------------------------------------------

export interface ModeCoverageEvaluation {
  /** Execution status that should apply based on the mode + observed gaps. */
  executionStatus: ExecutionStatus;
  /** Gaps that force the status to `incomplete` under the current mode. */
  incompleteGaps: CoverageGap[];
  /** Gaps that merely lower the status to `degraded` under the current mode. */
  degradedGaps: CoverageGap[];
  /** Whether the runner should fail closed (serious mode + required-lane gap). */
  failClosed: boolean;
}

/**
 * Evaluate a set of coverage gaps against the mode and required lanes.
 * - Smoke: any gap -> `degraded`, never fail-closed.
 * - Serious-local: a gap in any required lane other than `hosted` -> `incomplete` + fail-closed.
 * - Serious-end-to-end: a gap in any required lane (including `hosted`) -> `incomplete` + fail-closed.
 */
export function evaluateCoverageAgainstMode(
  gaps: CoverageGap[],
  requiredLanes: string[],
  mode: RunMode,
): ModeCoverageEvaluation {
  const incompleteGaps: CoverageGap[] = [];
  const degradedGaps: CoverageGap[] = [];
  const requiredSet = new Set(requiredLanes);

  for (const gap of gaps) {
    const isRequired = gap.required !== false && requiredSet.has(gap.lane);
    // A gap recorded as severity 'degraded' is a soft warning and must not
    // escalate the run to 'incomplete' even under a serious mode. Only gaps
    // flagged 'incomplete' (or 'blocked') can fail a serious run closed.
    const isHardGap = gap.severity === 'incomplete' || gap.severity === 'blocked';
    if (mode === 'smoke') {
      degradedGaps.push(gap);
      continue;
    }
    if (!isRequired || !isHardGap) {
      degradedGaps.push(gap);
      continue;
    }
    if (mode === 'serious-local') {
      if (gap.lane === 'hosted') {
        // serious-local does not fail closed on hosted lane gaps
        degradedGaps.push(gap);
      } else {
        incompleteGaps.push(gap);
      }
      continue;
    }
    // serious-end-to-end
    incompleteGaps.push(gap);
  }

  let executionStatus: ExecutionStatus = 'complete';
  if (incompleteGaps.length > 0) {
    executionStatus = 'incomplete';
  } else if (degradedGaps.length > 0) {
    executionStatus = 'degraded';
  }

  return {
    executionStatus,
    incompleteGaps,
    degradedGaps,
    failClosed: incompleteGaps.length > 0 && mode !== 'smoke',
  };
}

// ---------------------------------------------------------------------------
// Mid-pipeline gate (Step 5 of god-object refactor)
// ---------------------------------------------------------------------------

export interface MidPipelineGateResult {
  /** Whether the gate passed. */
  passed: boolean;
  /** Gaps that caused the gate to fail or degrade. */
  gaps: CoverageGap[];
  /** Whether the runner should abort (serious mode + hard gap). */
  shouldAbort: boolean;
}

/**
 * Evaluate readiness for verification stages AFTER the static stage
 * but BEFORE expensive local-live, test-synthesis, or hosted stages
 * consume provider budget.
 *
 * In serious mode, any hard gap here causes the pipeline to abort
 * before spending verification budget. In smoke mode, gaps are
 * recorded and the pipeline continues.
 *
 * Checks:
 * (a) Static scan produced signals (if requiresSourceScan)
 * (b) Required identities are resolvable
 * (c) Live target responds to health check (if local-live required)
 * (d) Rollback support exists for required reversible mutations
 */
export function evaluateMidPipelineReadiness(input: {
  mode: RunMode;
  signalCount: number;
  requiresSourceScan: boolean;
  liveTargetConfigured: boolean;
  requiredIdentitiesMissing: string[];
  localLiveTransportReady: boolean;
  testSynthesisRequired: boolean;
  testSynthesisTransportReady: boolean;
  liveTargetReachable: boolean | null;
  localLiveRequired: boolean;
  linuxRuntimeRequired: boolean;
  linuxRuntimeAvailable: boolean | null;
  rollbackAvailable: boolean;
  mutationCanariesPresent: boolean;
  rollbackRequired: boolean;
}): MidPipelineGateResult {
  const gaps: CoverageGap[] = [];

  // (a) Source scan check
  if (input.requiresSourceScan && input.signalCount === 0) {
    gaps.push({
      lane: 'static',
      code: 'zero_signals_after_static',
      message: 'Static scan produced zero signals — verification stages will have no hypotheses to test',
      severity: 'incomplete',
      required: true,
    });
  }

  if (input.localLiveRequired && !input.liveTargetConfigured) {
    gaps.push({
      lane: 'local-live',
      code: 'live_target_missing',
      message: 'Local-live verification was requested but no live target is configured',
      severity: 'incomplete',
      required: true,
    });
  }

  // (b) Required identities
  if (input.requiredIdentitiesMissing.length > 0) {
    gaps.push({
      lane: 'local-live',
      code: 'required_identities_missing',
      message: `Required identities not resolvable: ${input.requiredIdentitiesMissing.join(', ')}`,
      severity: 'incomplete',
      required: input.localLiveRequired,
    });
  }

  if (input.localLiveRequired && !input.localLiveTransportReady) {
    gaps.push({
      lane: 'local-live',
      code: 'local_live_transport_unavailable',
      message: 'Local-live verification requires a usable planner/worker transport, but none is available',
      severity: 'incomplete',
      required: true,
    });
  }

  if (input.testSynthesisRequired && !input.testSynthesisTransportReady) {
    gaps.push({
      lane: 'test-synthesis',
      code: 'test_synthesis_transport_unavailable',
      message: 'Test synthesis requires a usable synthesizer/planner transport, but none is available',
      severity: 'incomplete',
      required: true,
    });
  }

  // (c) Live target reachability
  if (input.localLiveRequired && input.liveTargetReachable === false) {
    gaps.push({
      lane: 'local-live',
      code: 'live_target_unreachable',
      message: 'Live target health check failed — local-live probes will not reach the target',
      severity: 'incomplete',
      required: true,
    });
  }

  if (input.linuxRuntimeRequired && input.linuxRuntimeAvailable === false) {
    gaps.push({
      lane: 'local-live',
      code: 'linux_runtime_unavailable',
      message: 'Linux-backed runtime verification is required but the target runtime/container is unavailable',
      severity: 'incomplete',
      required: input.localLiveRequired,
    });
  }

  // (d) Rollback for mutations
  if (input.mutationCanariesPresent && input.rollbackRequired && !input.rollbackAvailable) {
    gaps.push({
      lane: 'local-live',
      code: 'rollback_unavailable',
      message: 'Mutation canaries present but rollback support is missing',
      severity: 'incomplete',
      required: input.localLiveRequired,
    });
  }

  const hardGaps = gaps.filter((g) => g.severity === 'incomplete' || g.severity === 'blocked');
  const shouldAbort = hardGaps.length > 0 && input.mode !== 'smoke';

  return {
    passed: gaps.length === 0,
    gaps,
    shouldAbort,
  };
}
