import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { RateLimiter } from './rate-limiter.js';

describe('RateLimiter', () => {
  it('stops when consecutive 5xx threshold is hit', () => {
    const limiter = new RateLimiter({
      requestsPerSecond: 1000,
      maxRequestsPerCampaign: 100,
      autoStopOn5xxStreak: 2,
      autoStopOnLatencyDoubling: false,
    });
    limiter.recordResult(500, 10);
    assert.equal(limiter.isStopped(), false);
    limiter.recordResult(500, 10);
    assert.equal(limiter.isStopped(), true);
    assert.match(limiter.getStopReason() ?? '', /5xx/);
  });

  it('resets streak on a 2xx response', () => {
    const limiter = new RateLimiter({
      requestsPerSecond: 1000,
      maxRequestsPerCampaign: 100,
      autoStopOn5xxStreak: 3,
      autoStopOnLatencyDoubling: false,
    });
    limiter.recordResult(500, 10);
    limiter.recordResult(500, 10);
    limiter.recordResult(200, 10);
    limiter.recordResult(500, 10);
    assert.equal(limiter.isStopped(), false);
  });

  it('exhausts the campaign budget', async () => {
    const limiter = new RateLimiter({
      requestsPerSecond: 1000,
      maxRequestsPerCampaign: 2,
      autoStopOn5xxStreak: 100,
      autoStopOnLatencyDoubling: false,
    });
    await limiter.acquire();
    await limiter.acquire();
    await assert.rejects(() => limiter.acquire(), /budget/);
  });
});
