import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { AutoStopMonitor } from './auto-stop.js';

describe('AutoStopMonitor', () => {
  it('halts on first 5xx', () => {
    const monitor = new AutoStopMonitor('staging.example', { dailyBudget: 1000, latencySpikeMs: 5_000 });
    const incident = monitor.recordResult(500, 100, {});
    assert.equal(incident?.reason, 'first_5xx');
  });

  it('halts on IAP redirect', () => {
    const monitor = new AutoStopMonitor('staging.example', { dailyBudget: 1000, latencySpikeMs: 5_000 });
    const incident = monitor.recordResult(302, 100, { location: 'https://accounts.google.com/login' });
    assert.equal(incident?.reason, 'iap_redirect');
  });

  it('halts on WAF block', () => {
    const monitor = new AutoStopMonitor('staging.example', { dailyBudget: 1000, latencySpikeMs: 5_000 });
    const incident = monitor.recordResult(403, 100, { 'cf-ray': 'cloudflare-waf' });
    assert.equal(incident?.reason, 'waf_block');
  });

  it('halts when kill switch file exists', () => {
    const dir = mkdtempSync(resolve(tmpdir(), 'auto-stop-'));
    const killPath = resolve(dir, '.kill');
    writeFileSync(killPath, 'stop');
    try {
      const monitor = new AutoStopMonitor('staging.example', {
        dailyBudget: 1000,
        latencySpikeMs: 5_000,
        killSwitchPath: killPath,
      });
      const incident = monitor.preflight();
      assert.equal(incident?.reason, 'kill_switch');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
