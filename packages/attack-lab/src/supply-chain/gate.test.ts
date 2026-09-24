import test from 'node:test';
import assert from 'node:assert/strict';
import { getApprovedResults, getPendingResults, shouldBlockBuild, summarizePendingDrift } from './gate.js';
import type { SentinelResult } from './contracts.js';

function buildResult(overrides: Partial<SentinelResult> = {}): SentinelResult {
  return {
    baselineStatus: 'loaded',
    baselinePath: '/tmp/baseline.json',
    policyVersion: '1.0.0',
    policyHash: 'abc123',
    policyReviewedAt: '2026-04-10',
    drifts: [],
    quarantineResults: [],
    approvedPackages: [],
    blockedPackages: [],
    needsReviewPackages: [],
    shouldBlockBuild: false,
    ...overrides,
  };
}

test('supply-chain gate blocks severe unresolved drift and summarizes pending packages', () => {
  const result = buildResult({
    drifts: [
      {
        detectedAt: '2026-04-10T00:00:00.000Z',
        kind: 'version_changed',
        packageName: 'risky-lib',
        currentVersion: '2.0.0',
        severity: 'critical',
        reason: 'risky-lib version changed',
      },
    ],
    quarantineResults: [
      {
        packageName: 'risky-lib',
        version: '2.0.0',
        verdict: 'needs_review',
        checks: [
          { name: 'install_script', passed: false, severity: 'high', details: 'networking install script' },
          { name: 'native_binary', passed: true, severity: 'info', details: 'none' },
        ],
        reason: 'Needs review',
        inspectedAt: '2026-04-10T00:00:00.000Z',
      },
      {
        packageName: 'safe-lib',
        version: '1.0.0',
        verdict: 'approved',
        checks: [
          { name: 'package_json', passed: true, severity: 'info', details: 'ok' },
        ],
        reason: 'Approved',
        inspectedAt: '2026-04-10T00:00:00.000Z',
      },
    ],
    needsReviewPackages: ['risky-lib@2.0.0'],
  });

  assert.equal(shouldBlockBuild(result), true);
  assert.deepEqual(getApprovedResults(result.quarantineResults).map((entry) => entry.packageName), ['safe-lib']);
  assert.deepEqual(getPendingResults(result.quarantineResults).map((entry) => entry.packageName), ['risky-lib']);
  assert.match(summarizePendingDrift(result), /NEEDS REVIEW: risky-lib@2.0.0/);
});
