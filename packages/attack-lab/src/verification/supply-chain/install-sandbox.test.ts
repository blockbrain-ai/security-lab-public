import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { mkdtemp } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { InstallSandbox } from './install-sandbox.js';
import type { ArtifactFetchResult } from './contracts.js';

const execFileAsync = promisify(execFile);

async function createFetchedArtifact(root: string): Promise<ArtifactFetchResult> {
  const staging = join(root, 'staging');
  const pkgDir = join(staging, 'package');
  await mkdir(pkgDir, { recursive: true });
  await writeFile(
    join(pkgDir, 'package.json'),
    JSON.stringify({ name: 'sandbox-fixture', version: '1.0.0', main: 'index.js' }, null, 2),
    'utf8',
  );
  await writeFile(join(pkgDir, 'index.js'), 'module.exports = 1;\n', 'utf8');

  const tarballPath = join(root, 'sandbox-fixture.tgz');
  await execFileAsync('tar', ['-czf', tarballPath, '-C', staging, 'package']);

  const unpackedPath = join(root, 'unpacked');
  await mkdir(unpackedPath, { recursive: true });

  return {
    packageName: 'sandbox-fixture',
    version: '1.0.0',
    tarballPath,
    unpackedPath,
    tarballSha256: 'hash',
    fetchedFrom: 'https://example.test/sandbox-fixture.tgz',
    fetchedAt: new Date().toISOString(),
  };
}

test('InstallSandbox builds isolated env and snapshots path changes', async () => {
  const sandbox = new InstallSandbox();
  const env = (sandbox as any).buildIsolatedEnv(false);
  assert.match(env.HTTP_PROXY ?? '', /127\.0\.0\.1:1/);
  assert.equal(env.SECURITY_LAB_SANDBOX, '1');

  const dir = await mkdtemp(join(tmpdir(), 'security-lab-snapshot-'));
  try {
    const before = await (sandbox as any).snapshotPaths([dir]);
    await writeFile(join(dir, 'new-file.txt'), 'hello', 'utf8');
    const after = await (sandbox as any).snapshotPaths([dir]);
    const diff = (sandbox as any).diffSnapshots(before, after) as string[];
    assert.ok(diff.some((entry) => entry.includes('new-file.txt')));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('InstallSandbox installs a local tarball and reports bounded execution details', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-install-sandbox-'));

  try {
    const fetched = await createFetchedArtifact(root);
    const sandbox = new InstallSandbox();
    const result = await sandbox.run(fetched, {
      packageManager: 'npm',
      timeoutMs: 30_000,
      allowNetwork: false,
    });

    assert.equal(result.packageName, 'sandbox-fixture');
    assert.equal(result.version, '1.0.0');
    assert.equal(typeof result.exitCode, 'number');
    assert.ok(result.durationMs >= 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('InstallSandbox reports timeout and spawn errors from bounded command execution', async () => {
  const sandbox = new InstallSandbox();
  const cwd = await mkdtemp(join(tmpdir(), 'security-lab-install-command-'));

  try {
    const timedOut = await (sandbox as any).spawnBounded(
      'node',
      ['-e', 'setTimeout(() => {}, 500)'],
      cwd,
      { PATH: process.env.PATH ?? '/usr/bin:/bin' },
      20,
    );
    assert.equal(timedOut.killed, true);

    const errored = await (sandbox as any).spawnBounded(
      'definitely-not-a-command',
      [],
      cwd,
      { PATH: process.env.PATH ?? '/usr/bin:/bin' },
      20,
    );
    assert.equal(errored.exitCode, -1);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});
