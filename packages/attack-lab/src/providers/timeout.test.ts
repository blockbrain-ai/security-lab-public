import test from 'node:test';
import assert from 'node:assert/strict';
import { withRequestTimeout } from './timeout.js';

test('withRequestTimeout resolves successful work before the timeout', async () => {
  const result = await withRequestTimeout(
    async () => 'ok',
    { timeoutMs: 100, label: 'fixture' },
  );

  assert.equal(result, 'ok');
});

test('withRequestTimeout rejects hung work with ETIMEDOUT', async () => {
  await assert.rejects(
    () =>
      withRequestTimeout(
        async () => {
          await new Promise(() => {});
          return 'late';
        },
        { timeoutMs: 5, label: 'fixture' },
      ),
    (error: Error & { code?: string }) => error.code === 'ETIMEDOUT' && /timed out after 5ms/.test(error.message),
  );
});
