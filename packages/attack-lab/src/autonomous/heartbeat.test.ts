import test from 'node:test';
import assert from 'node:assert/strict';
import { withHeartbeat } from './heartbeat.js';

test('withHeartbeat emits heartbeats at the expected interval', async () => {
  const events: Array<{ stage: string; payload: Record<string, unknown> }> = [];
  const emit = async (stage: string, payload: Record<string, unknown>) => {
    events.push({ stage, payload });
  };

  // Leave enough headroom for scheduler jitter on busy CI hosts.
  const result = await withHeartbeat(
    new Promise<string>((resolve) => setTimeout(() => resolve('done'), 220)),
    { stage: 'test_stage', role: 'planner', intervalMs: 40, emit },
  );

  assert.equal(result, 'done');
  // At 40ms over ~220ms, even with jitter we should see multiple heartbeats.
  assert.ok(events.length >= 2, `Expected at least 2 heartbeats, got ${events.length}`);
  assert.equal(events[0]!.stage, 'test_stage_heartbeat');
  assert.equal((events[0]!.payload as Record<string, unknown>).stage, 'test_stage');
  assert.equal((events[0]!.payload as Record<string, unknown>).role, 'planner');
  assert.ok(typeof (events[0]!.payload as Record<string, unknown>).elapsedMs === 'number');
});

test('withHeartbeat stops emitting after operation completes', async () => {
  const events: Array<{ stage: string }> = [];
  const emit = async (stage: string, payload: Record<string, unknown>) => {
    events.push({ stage });
  };

  await withHeartbeat(
    new Promise<void>((resolve) => setTimeout(resolve, 80)),
    { stage: 'quick', intervalMs: 30, emit },
  );

  const countAfterCompletion = events.length;

  // Wait a bit more — no new heartbeats should arrive
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.equal(events.length, countAfterCompletion);
});

test('withHeartbeat propagates errors from the wrapped operation', async () => {
  const emit = async () => {};

  await assert.rejects(
    () =>
      withHeartbeat(
        Promise.reject(new Error('boom')),
        { stage: 'failing', intervalMs: 10, emit },
      ),
    { message: 'boom' },
  );
});

test('withHeartbeat includes expectedTimeoutMs when provided', async () => {
  const events: Array<{ stage: string; payload: Record<string, unknown> }> = [];
  const emit = async (stage: string, payload: Record<string, unknown>) => {
    events.push({ stage, payload });
  };

  await withHeartbeat(
    new Promise<void>((resolve) => setTimeout(resolve, 80)),
    { stage: 'bounded', intervalMs: 30, expectedTimeoutMs: 180_000, emit },
  );

  assert.ok(events.length > 0);
  assert.equal((events[0]!.payload as Record<string, unknown>).expectedTimeoutMs, 180_000);
});
