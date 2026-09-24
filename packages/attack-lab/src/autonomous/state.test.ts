import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  StateStore,
  canResume,
  createInitialState,
  isBudgetExhausted,
  isIterationLimitReached,
  shouldEscapeDeadEnds,
} from './state.js';

test('StateStore namespaces state and memory per campaign and preserves failed-run resume', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-state-'));

  try {
    const state = createInitialState({
      campaignId: 'campaign-42',
      targetId: 'fixture-target',
      maxIterations: 8,
      maxCostUsd: 12,
      mode: 'blind',
      campaignDir: root,
    });

    assert.equal(state.memoryPath, join(root, 'campaign-42', 'memory.json'));

    const store = new StateStore(root, 'campaign-42');
    await store.write(state);
    await stat(join(root, 'campaign-42', 'state.json'));

    await store.setFailed('planner crashed', 'planning');
    const failed = await store.read();
    assert.equal(failed.phase, 'failed');
    assert.equal(failed.failurePhase, 'planning');
    assert.equal(canResume(failed), true);

    await store.setCompleted();
    const completed = await store.read();
    assert.equal(completed.phase, 'completed');
    assert.equal(canResume(completed), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('state helper guards trigger on dead ends, budget exhaustion, and iteration limits', () => {
  const state = createInitialState({
    campaignId: 'campaign-helpers',
    targetId: 'fixture-target',
    maxIterations: 3,
    maxCostUsd: 1.5,
    mode: 'declared',
    campaignDir: '/tmp/security-lab',
  });

  state.consecutiveDeadEnds = 3;
  state.costUsd = 1.5;
  state.iteration = 3;

  assert.equal(shouldEscapeDeadEnds(state), true);
  assert.equal(isBudgetExhausted(state), true);
  assert.equal(isIterationLimitReached(state), true);
});
