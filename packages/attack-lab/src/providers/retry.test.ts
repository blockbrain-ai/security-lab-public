import test from 'node:test';
import assert from 'node:assert/strict';
import { withRetry } from './retry.js';

/**
 * Retry behaviour guards the paid provider calls: it must retry the statuses
 * that mean "try again later", and it must not silently retry a request the
 * provider rejected on its merits (which would multiply cost for no gain).
 */
test('withRetry returns immediately when the first attempt succeeds', async () => {
  let calls = 0;
  const result = await withRetry(async () => {
    calls += 1;
    return 'ok';
  });
  assert.equal(result, 'ok');
  assert.equal(calls, 1);
});

test('withRetry retries rate-limit and overload statuses with the configured delays', async () => {
  const calls: number[] = [];
  const delays: number[] = [];
  let attempt = 0;

  const result = await withRetry(
    async () => {
      attempt += 1;
      if (attempt < 3) {
        const error = new Error('rate limited') as Error & { status: number };
        error.status = 429;
        throw error;
      }
      return 'recovered';
    },
    {
      delays: [1, 1, 1],
      onRetry: (n, delay) => {
        calls.push(n);
        delays.push(delay);
      },
    },
  );

  assert.equal(result, 'recovered');
  assert.deepEqual(calls, [1, 2]);
  assert.deepEqual(delays, [1, 1]);
});

test('withRetry rethrows a non-retryable error without further attempts', async () => {
  let calls = 0;
  const error = new Error('bad request') as Error & { status: number };
  error.status = 400;

  await assert.rejects(
    () =>
      withRetry(async () => {
        calls += 1;
        throw error;
      }, { delays: [1, 1, 1] }),
    /bad request/,
  );
  assert.equal(calls, 1, 'a 400 must not be retried');
});

test('withRetry gives up after the delay sequence is exhausted', async () => {
  let calls = 0;
  const error = new Error('still overloaded') as Error & { status: number };
  error.status = 529;

  await assert.rejects(
    () =>
      withRetry(async () => {
        calls += 1;
        throw error;
      }, { delays: [1, 1] }),
    /still overloaded/,
  );
  // One initial attempt plus one per configured delay.
  assert.equal(calls, 3);
});

test('withRetry honours a custom retryable status set', async () => {
  let calls = 0;
  const error = new Error('teapot') as Error & { status: number };
  error.status = 418;

  const result = await withRetry(
    async () => {
      calls += 1;
      if (calls === 1) {
        throw error;
      }
      return 'ok';
    },
    { delays: [1], retryableStatusCodes: [418] },
  );

  assert.equal(result, 'ok');
  assert.equal(calls, 2);
});
