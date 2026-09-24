import test from 'node:test';
import assert from 'node:assert/strict';
import { STAGES } from './contracts.js';
import { checkpointBefore, firstStageForResume } from './resume-checkpoint.js';

test('--resume-at verification skips the static stage', () => {
  const stage = firstStageForResume('verification', undefined);
  assert.equal(stage, 'verification_packet_build');
  // The checkpoint is the stage *before* the resume point, which is what makes
  // shouldSkipStage() skip static instead of re-running it.
  assert.equal(checkpointBefore(stage!), 'static');
});

test('--resume-at assessment skips everything before the assessment', () => {
  const stage = firstStageForResume('assessment', undefined);
  assert.equal(stage, 'assessment');
  assert.equal(checkpointBefore(stage!), 'focused_closure');
});

test('an explicit --resume-at-stage wins over --resume-at', () => {
  assert.equal(firstStageForResume('assessment', 'local_live'), 'local_live');
  assert.equal(checkpointBefore('local_live'), 'focused_lead_confirmation');
});

test('the default resume does not move the checkpoint', () => {
  assert.equal(firstStageForResume('auto', undefined), null);
});

test('resuming at the first stage clears the checkpoint', () => {
  assert.equal(checkpointBefore(STAGES[0]!), null);
});

test('every resume point maps to a real stage that is skipped next time', () => {
  for (const resumeAt of ['verification', 'assessment'] as const) {
    const stage = firstStageForResume(resumeAt, undefined);
    assert.ok(stage && STAGES.includes(stage), `${resumeAt} must map to a canonical stage`);
    const checkpoint = checkpointBefore(stage!);
    assert.ok(
      checkpoint === null || STAGES.indexOf(checkpoint) === STAGES.indexOf(stage) - 1,
      `${resumeAt}: checkpoint must immediately precede the resume point`,
    );
  }
});
