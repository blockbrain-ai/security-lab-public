/**
 * Investigation runner — thin coordinator.
 *
 * LINE LIMIT: 500 non-blank non-comment lines — enforced by
 * `investigation-runner.line-count.test.ts`. See SL6 in
 * the engineering standards and the
 * Section 5.2 Stage Contract doc at `docs/STAGE-CONTRACT.md`.
 *
 * Section 5.2 reduces the runner to coordinator responsibilities only:
 * config parsing, pipeline assembly, stage iteration, lock acquisition /
 * release, error handling, and result aggregation. All heavy lifting
 * lives in `investigation-runner-internals.ts` on the abstract base
 * class `InvestigationRunnerInternals`, and in the named stage modules
 * under `./stages/`. Do NOT add inline stage logic here — extend a
 * stage module instead.
 */

import {
  InvestigationRunnerInternals,
  type InvestigationConfig,
  type InvestigationResult,
  type ExecutionStatus,
  type CoverageGap,
  type VerificationLaneSummary,
  type VerificationLanesSummary,
  type ChildCampaignSummary,
} from './investigation-runner-internals.js';

export type {
  InvestigationConfig,
  InvestigationResult,
  ExecutionStatus,
  CoverageGap,
  VerificationLaneSummary,
  VerificationLanesSummary,
  ChildCampaignSummary,
};

export {
  buildLinuxSidecarCommand,
  buildRoleSessionKey,
  countNovelRuntimeSignals,
  shouldContinueLocalLiveRounds,
  shouldUseCounterPlannerForLocalLive,
  createLaneSummary,
  addLaneCoverageGap,
  countLaneVerdict,
  usableAdapter,
} from './investigation-runner-internals.js';

/**
 * Concrete investigation runner. The class inherits all pipeline
 * implementation details from `InvestigationRunnerInternals`; this file
 * exists to keep the public entrypoint stable and to enforce the
 * coordinator-only line budget.
 */
export class InvestigationRunner extends InvestigationRunnerInternals {
  /**
   * Run the investigation pipeline end-to-end. Thin delegator to the
   * base-class implementation. Keeping the public method named `run()`
   * preserves the CLI / test API contract from before Section 5.2.
   */
  async run(): Promise<InvestigationResult> {
    return this.executeCampaignPipeline();
  }
}
