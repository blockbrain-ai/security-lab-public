/**
 * Section 5.1 — StaticInvestigationStage.
 *
 * Owns the static investigation loop: planner / counter-planner / judge panel
 * iteration, dead-end escape, dormant signal resurfacing, chain synthesis,
 * novelty ranking. During Section 5.1 the bulk of the loop still lives inline
 * in `InvestigationRunner.run()` — this module defines the stage interface
 * boundary and houses the selective counter-worker trigger helper that is
 * new for Section 5.1. Section 5.2 will move the remaining inline code.
 *
 * ## Selective counter-worker trigger
 *
 * Prior to Section 5.1 the counter-worker was invoked on a profile-level
 * heuristic (`shouldUseCounterPlanner` in `portfolio-profiles.ts`) that fired
 * relatively liberally. Section 5.1 refines the trigger with a claim-shape
 * check: the counter-worker is invoked only when one of five claim-shape
 * signals is present. The rationale is that counter-work is only valuable
 * when the primary claim is shaped such that a contrarian perspective could
 * plausibly refine or refute it. A plain low-complexity hypothesis does not
 * benefit from a second-pass review and invoking the counter-worker on every
 * iteration is wasted budget.
 *
 * The five triggers:
 *
 *   1. Cross-boundary claim — hypothesis crosses a trust boundary
 *      (auth / tenant / scope).
 *   2. Identity / tenant claim — hypothesis references identity escalation
 *      or tenant isolation.
 *   3. Chain depth ≥ 3 — composed hypothesis spans three or more signals.
 *   4. Dormant-signal reopening — a previously-dormant signal is resurfaced
 *      into a hypothesis.
 *   5. Disputed or inconclusive rounds — a judge panel disagreement or an
 *      inconclusive verdict.
 */

import type { ChainHypothesis } from '../contracts.js';
import type { Stage, StageContext, StageResult } from './contracts.js';
import { emptyStageResult } from './contracts.js';

/**
 * Signals a stage iteration can supply to the trigger helper. These mirror
 * the state the runner already tracks per-iteration; we expose them as an
 * explicit type so tests can exercise the trigger in isolation without
 * spinning up a full investigation context.
 */
export interface CounterWorkerTriggerInput {
  hypothesis: ChainHypothesis;
  /**
   * Summary of the judge panel result for the current iteration, if any.
   * Presence of a disputed panel or an inconclusive verdict triggers
   * counter-work. We accept a minimal summary rather than the full
   * `PanelResult` so the trigger is easy to exercise in tests.
   */
  judgePanelResult?: {
    unanimous?: boolean;
    distinctVerdicts?: number;
    consensusVerdict?: string | null;
  };
  /**
   * Whether the hypothesis in this iteration has been resurfaced from a
   * dormant signal.
   */
  resurfacedFromDormant?: boolean;
  /**
   * IDs of signals currently marked dormant in campaign memory. If the
   * hypothesis references any of them, its dormant-reopen trigger fires.
   */
  dormantSignalIds?: ReadonlySet<string>;
}

const IDENTITY_TENANT_KEYWORDS = /tenant|identity|organization|org_id|user_id|principal|role|impersonat|escalat|privilege/i;
const CROSS_BOUNDARY_KEYWORDS = /auth|jwt|token|scope|boundary|cors|origin|sandbox/i;

function isCrossBoundaryClaim(hypothesis: ChainHypothesis): boolean {
  if (hypothesis.boundaryCrossing && hypothesis.boundaryCrossing.from !== hypothesis.boundaryCrossing.to) {
    return true;
  }
  return CROSS_BOUNDARY_KEYWORDS.test(hypothesis.description);
}

function isIdentityOrTenantClaim(hypothesis: ChainHypothesis): boolean {
  if (hypothesis.privilegeDelta) {
    return true;
  }
  return IDENTITY_TENANT_KEYWORDS.test(hypothesis.description);
}

function isChainDepthAtLeastThree(hypothesis: ChainHypothesis): boolean {
  return (hypothesis.signalIds?.length ?? 0) >= 3;
}

function isDormantReopening(input: CounterWorkerTriggerInput): boolean {
  if (input.resurfacedFromDormant) {
    return true;
  }
  if (!input.dormantSignalIds || input.dormantSignalIds.size === 0) {
    return false;
  }
  return (input.hypothesis.signalIds ?? []).some((id) => input.dormantSignalIds!.has(id));
}

function isDisputedOrInconclusive(input: CounterWorkerTriggerInput): boolean {
  const panel = input.judgePanelResult;
  if (!panel) return false;
  if (panel.unanimous === false) return true;
  if ((panel.distinctVerdicts ?? 0) >= 2) return true;
  if (panel.consensusVerdict == null) return true;
  if (panel.consensusVerdict === 'inconclusive' || panel.consensusVerdict === 'needs_more_data') return true;
  return false;
}

/**
 * Pure predicate for the Section 5.1 selective counter-worker trigger.
 * Returns true if any of the five claim-shape triggers fire. Tests for
 * this helper live in `static-investigation.test.ts`.
 */
export function shouldInvokeCounterWorker(input: CounterWorkerTriggerInput): boolean {
  if (isCrossBoundaryClaim(input.hypothesis)) return true;
  if (isIdentityOrTenantClaim(input.hypothesis)) return true;
  if (isChainDepthAtLeastThree(input.hypothesis)) return true;
  if (isDormantReopening(input)) return true;
  if (isDisputedOrInconclusive(input)) return true;
  return false;
}

/**
 * The extracted StaticInvestigationStage. In Section 5.1 the stage acts as
 * a seam: the runner continues to own the loop implementation (because the
 * loop is deeply entangled with cross-stage state that will be untangled in
 * 5.2) and the stage's `run()` method is a no-op placeholder that the runner
 * calls at the stage boundary. The stage exists so that:
 *
 *   - the `Stage` contract is firmly established and visible to any future
 *     extraction work;
 *   - the selective counter-worker trigger helper has a natural home alongside
 *     the stage it refines;
 *   - behavior-equivalence tests can compare stage instances before and after
 *     deeper extraction in 5.2.
 *
 * The stage name is `static` (from the SL6 vocabulary in Section 1.1).
 */
export class StaticInvestigationStage implements Stage {
  readonly name = 'static' as const;

  async run(_context: StageContext): Promise<StageResult> {
    // The static loop remains inline in the runner during Section 5.1.
    // Section 5.2 will move the loop body here and this method will
    // grow into the authoritative implementation.
    return emptyStageResult('static');
  }
}
