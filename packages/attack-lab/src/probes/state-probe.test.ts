import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runStateProbe } from './state-probe.js';

test('runStateProbe reports writable and mutation-sensitive state files', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-state-probe-'));

  try {
    const relPath = 'state.json';
    const content = JSON.stringify({
      MAX_AUDIT_ITERATIONS: 8,
      bypassPermissions: true,
    });
    await writeFile(join(root, relPath), content, 'utf8');

    const writable = await runStateProbe(
      { kind: 'state_check', action: 'writability_check', filePath: relPath, timeoutMs: 1000 },
      root,
    );
    assert.equal(writable.exitCode, 1);
    assert.match(writable.stdout ?? '', /writable:/i);

    const mutation = await runStateProbe(
      { kind: 'state_check', action: 'config_mutation_check', filePath: relPath, timeoutMs: 1000 },
      root,
    );
    assert.equal(mutation.exitCode, 1);
    assert.match(mutation.stdout ?? '', /sensitive_config:/i);
    assert.match(mutation.stdout ?? '', /mutable:/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('runStateProbe detects tamper drift against an expected hash', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-state-probe-hash-'));

  try {
    const relPath = 'state.json';
    const content = '{"mode":"strict"}';
    await writeFile(join(root, relPath), content, 'utf8');
    const expectedHash = createHash('sha256').update(content).digest('hex');

    const matching = await runStateProbe(
      {
        kind: 'state_check',
        action: 'tamper_detect',
        filePath: relPath,
        expectedHash,
        timeoutMs: 1000,
      },
      root,
    );
    assert.equal(matching.exitCode, 0);
    assert.match(matching.stdout ?? '', /integrity: matches expected hash/i);

    const drifted = await runStateProbe(
      {
        kind: 'state_check',
        action: 'tamper_detect',
        filePath: relPath,
        expectedHash: 'bad-hash',
        timeoutMs: 1000,
      },
      root,
    );
    assert.equal(drifted.exitCode, 1);
    assert.match(drifted.stdout ?? '', /TAMPERED/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
