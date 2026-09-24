/**
 * Resume checkpoints.
 *
 * A resumed campaign skips every stage up to `state.lastCompletedStage`. The
 * `--resume-at verification|assessment` flag used to move only `state.phase`,
 * so `shouldSkipStage()` returned false for every stage: the static planner and
 * judge loop re-ran (spending budget a second time) and its completion event
 * rewound `lastCompletedStage` back to `static`, leaving a worse checkpoint
 * than the campaign started with.
 */

import { STAGES, type Stage } from './contracts.js';

export type ResumeAt = 'auto' | 'verification' | 'assessment';

/** The stage a resume should begin at, or null when nothing should be skipped. */
export function firstStageForResume(
  resumeAt: ResumeAt,
  resumeAtStage: Stage | undefined,
): Stage | null {
  if (resumeAtStage) {
    return resumeAtStage;
  }
  if (resumeAt === 'verification') {
    return 'verification_packet_build';
  }
  if (resumeAt === 'assessment') {
    return 'assessment';
  }
  return null;
}

/** The checkpoint that makes a campaign resume at `stage` (the stage before it). */
export function checkpointBefore(stage: Stage): Stage | null {
  const index = STAGES.indexOf(stage);
  if (index <= 0) {
    return null;
  }
  return STAGES[index - 1] ?? null;
}
