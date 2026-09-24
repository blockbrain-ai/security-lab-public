import test from 'node:test';
import assert from 'node:assert/strict';
import { BoundedScheduler } from './scheduler.js';

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

test('BoundedScheduler respects concurrency caps and completes queued work', async () => {
  const scheduler = new BoundedScheduler<number>({
    maxConcurrency: 2,
    maxPerTarget: 1,
    maxPerKind: 2,
    maxCostUsd: 10,
  });

  let active = 0;
  let maxActive = 0;

  for (const task of [
    { id: 'a', targetId: 't1', probeKind: 'code_read', value: 1 },
    { id: 'b', targetId: 't1', probeKind: 'code_read', value: 2 },
    { id: 'c', targetId: 't2', probeKind: 'dependency_read', value: 3 },
  ]) {
    scheduler.enqueue({
      id: task.id,
      targetId: task.targetId,
      probeKind: task.probeKind,
      priority: 1,
      execute: async () => {
        active += 1;
        maxActive = Math.max(maxActive, active);
        await wait(20);
        active -= 1;
        return task.value;
      },
    });
  }

  const results = await scheduler.runAll();
  assert.equal(results.length, 3);
  assert.equal(maxActive, 2);
  assert.deepEqual(
    results
      .filter((entry) => entry.result != null)
      .map((entry) => entry.result)
      .sort(),
    [1, 2, 3],
  );
});
