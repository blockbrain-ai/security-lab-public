import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runPreflight, PreflightFailedError } from './doctor.js';
import type { InvestigationTarget } from './target-profile.js';

function makeTarget(overrides: Partial<InvestigationTarget> = {}): InvestigationTarget {
  return {
    id: 'test-target',
    name: 'Test Target',
    kind: 'code',
    environment: 'fixture',
    supportedProbeKinds: ['code_read'],
    hints: {},
    ...overrides,
  };
}

test('runPreflight passes with minimal target and no workers needed', async () => {
  const report = await runPreflight({
    target: makeTarget(),
    campaignId: 'test-1',
    mode: 'declared',
  });

  assert.ok(report.allPassed);
});

test('runPreflight checks repo markers when repoRoot is set', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-doctor-'));
  try {
    // Create a package.json marker
    await writeFile(join(root, 'package.json'), '{}', 'utf8');

    const report = await runPreflight({
      target: makeTarget({ repoRoot: root }),
      campaignId: 'test-2',
      mode: 'declared',
    });

    const markerCheck = report.checks.find((c) => c.id === 'repo_markers');
    assert.ok(markerCheck);
    assert.equal(markerCheck.status, 'pass');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('runPreflight fails when repo markers are missing', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-doctor-'));
  try {
    // Empty directory — no package.json
    const report = await runPreflight({
      target: makeTarget({ repoRoot: root }),
      campaignId: 'test-3',
      mode: 'declared',
    });

    const markerCheck = report.checks.find((c) => c.id === 'repo_markers');
    assert.ok(markerCheck);
    assert.equal(markerCheck.status, 'fail');
    assert.ok(!report.allPassed);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('runPreflight fails when required identities are missing', async () => {
  const report = await runPreflight({
    target: makeTarget({
      requiredIdentities: ['NONEXISTENT_SECRET_12345'],
    }),
    campaignId: 'test-4',
    mode: 'declared',
  });

  const identityCheck = report.checks.find((c) => c.id === 'required_identities');
  assert.ok(identityCheck);
  assert.equal(identityCheck.status, 'fail');
  assert.ok(!report.allPassed);
});

test('runPreflight fails when rollback is missing for targets with canaries', async () => {
  const report = await runPreflight({
    target: makeTarget({
      canaries: [{ id: 'test-canary', type: 'mutation' }],
      rollback: undefined,
    }),
    campaignId: 'test-5',
    mode: 'declared',
  });

  const rollbackCheck = report.checks.find((c) => c.id === 'rollback_declared');
  assert.ok(rollbackCheck);
  assert.equal(rollbackCheck.status, 'fail');
});

test('runPreflight passes when rollback is declared for targets with canaries', async () => {
  const report = await runPreflight({
    target: makeTarget({
      canaries: [{ id: 'test-canary', type: 'mutation' }],
      rollback: { strategy: 'git-reset' },
    }),
    campaignId: 'test-6',
    mode: 'declared',
  });

  const rollbackCheck = report.checks.find((c) => c.id === 'rollback_declared');
  assert.ok(rollbackCheck);
  assert.equal(rollbackCheck.status, 'pass');
});

test('runPreflight checks docker when linuxSidecar.enabled is true', async () => {
  const report = await runPreflight({
    target: makeTarget({
      linuxSidecar: { enabled: true },
    }),
    campaignId: 'test-7',
    mode: 'declared',
  });

  const dockerCheck = report.checks.find((c) => c.id === 'docker_runtime');
  assert.ok(dockerCheck);
  // Docker may or may not be available in the test environment — just verify the check ran
  assert.ok(dockerCheck.status === 'pass' || dockerCheck.status === 'fail');
});

test('runPreflight checks pi when needsPiCli is true', async () => {
  const report = await runPreflight({
    target: makeTarget(),
    campaignId: 'test-pi',
    mode: 'declared',
    needsPiCli: true,
  });

  const piCheck = report.checks.find((c) => c.id === 'worker_pi_cli');
  assert.ok(piCheck, 'should include a pi_cli check');
  assert.ok(piCheck.status === 'pass' || piCheck.status === 'fail');
});

test('runPreflight skips pi check when needsPiCli is not set', async () => {
  const report = await runPreflight({
    target: makeTarget(),
    campaignId: 'test-no-pi',
    mode: 'declared',
  });

  const piCheck = report.checks.find((c) => c.id === 'worker_pi_cli');
  assert.equal(piCheck, undefined, 'should not include a pi_cli check when not needed');
});

test('PreflightFailedError has structured report', () => {
  const report = {
    checks: [
      { id: 'test', status: 'fail' as const, message: 'test failed' },
    ],
    allPassed: false,
  };
  const error = new PreflightFailedError(report);
  assert.ok(error.message.includes('test'));
  assert.equal(error.report, report);
});
