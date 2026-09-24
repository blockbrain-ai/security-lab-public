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
