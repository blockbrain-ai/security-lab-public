import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runShellProbe } from './shell-probe.js';

test('runShellProbe executes commands with cwd and merged env overrides', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-shell-probe-'));

  try {
    const result = await runShellProbe(
      {
        kind: 'shell_command',
        command: ['sh', '-c', 'printf "%s|%s" "$PWD" "$TEST_VAR"'],
        timeoutMs: 1000,
        cwd: root,
        env: { TEST_VAR: 'from-probe' },
      },
      {
        kind: 'shell',
        id: 'fixture-shell',
        environment: 'sandbox',
        cwd: root,
        env: { TEST_VAR: 'from-target' },
      },
    );

    assert.equal(result.exitCode, 0);
    const [observedCwd, observedEnv] = (result.stdout ?? '').split('|');
    assert.equal(observedEnv, 'from-probe');
    assert.equal(await realpath(observedCwd ?? ''), await realpath(root));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('runShellProbe does not hand the operator environment to the child', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-shell-probe-'));
  const canaryName = 'SECURITY_LAB_ENV_CANARY';
  const previous = process.env[canaryName];
  process.env[canaryName] = 'must-not-reach-the-child';

  try {
    const result = await runShellProbe(
      {
        kind: 'shell_command',
        command: ['sh', '-c', `printf "%s" "\${${canaryName}:-unset}"`],
        timeoutMs: 1000,
        cwd: root,
      },
      {
        id: 'shell-fixture',
        kind: 'shell',
        environment: 'sandbox',
      },
    );

    assert.equal(result.exitCode, 0);
    assert.equal(result.stdout?.trim(), 'unset', 'a probe must not inherit the operator environment');
  } finally {
    if (previous === undefined) {
      delete process.env[canaryName];
    } else {
      process.env[canaryName] = previous;
    }
    await rm(root, { recursive: true, force: true });
  }
});

test('runShellProbe still passes PATH so ordinary commands resolve', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-shell-probe-'));
  try {
    const result = await runShellProbe(
      {
        kind: 'shell_command',
        command: ['sh', '-c', 'printf "%s" "$PATH"'],
        timeoutMs: 1000,
        cwd: root,
      },
      { id: 'shell-fixture', kind: 'shell', environment: 'sandbox' },
    );

    assert.equal(result.exitCode, 0);
    assert.ok((result.stdout ?? '').trim().length > 0, 'PATH must be forwarded');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
