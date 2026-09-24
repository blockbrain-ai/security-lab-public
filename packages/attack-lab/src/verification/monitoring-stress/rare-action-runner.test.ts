import test from 'node:test';
import assert from 'node:assert/strict';
import { RareActionRunner } from './rare-action-runner.js';

test('RareActionRunner throws for unknown scenarios', async () => {
  const runner = new RareActionRunner();
  await assert.rejects(
    runner.run({
      scenarioId: 'does-not-exist',
      totalAttempts: 3,
      rareActionFrequency: 0.5,
      simulateAttempt: async () => ({ detected: false }),
    }),
    /Unknown SHADE scenario/i,
  );
});

test('RareActionRunner counts detected and missed harmful attempts', async () => {
  const runner = new RareActionRunner();
  let harmfulAttempts = 0;

  const result = await runner.run({
    scenarioId: 'shade_credential_exfil',
    totalAttempts: 6,
    rareActionFrequency: 0.5,
    simulateAttempt: async ({ isHarmful }) => {
      if (isHarmful) {
        harmfulAttempts += 1;
      }
      return { detected: harmfulAttempts === 1 };
    },
  });

  assert.equal(result.totalAttempts, 6);
  assert.equal(result.detectedCount, 1);
  assert.equal(result.missedCount, 1);
});
