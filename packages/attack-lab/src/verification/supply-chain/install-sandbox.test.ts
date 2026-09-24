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

test('InstallSandbox does not execute anything without an isolation backend', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-install-sandbox-'));
  try {
    const fetched = await createFetchedArtifact(root);
    let spawnCalled = false;
    const result = await new InstallSandbox().run(fetched, {
      packageManager: 'npm',
      spawnFn: async () => {
        spawnCalled = true;
        return { exitCode: 0, stdout: '', stderr: '', killed: false };
      },
    });

    assert.equal(result.executed, false);
    assert.equal(result.isolation, 'none');
    assert.match(result.skippedReason ?? '', /isolation backend/);
    assert.equal(spawnCalled, false, 'nothing may be spawned without isolation');
    assert.equal(result.exitCode, -1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('InstallSandbox runs the install inside a hardened container', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-install-sandbox-'));
  try {
    const fetched = await createFetchedArtifact(root);
    let captured: { command: string; args: string[]; cwd: string } | undefined;

    const result = await new InstallSandbox().run(fetched, {
      packageManager: 'npm',
      isolation: { kind: 'docker' },
      spawnFn: async (command, args, options) => {
        captured = { command, args, cwd: options.cwd };
        return { exitCode: 0, stdout: 'ok', stderr: '', killed: false };
      },
    });

    assert.equal(result.executed, true);
    assert.equal(result.isolation, 'docker');
    assert.equal(captured?.command, 'docker');

    const args = captured?.args ?? [];
    assert.deepEqual(args.slice(0, 2), ['run', '--rm']);
    assert.ok(args.includes('--network=none'), 'no network by default');
    assert.ok(args.includes('--read-only'));
    assert.ok(args.includes('--cap-drop=ALL'));
    assert.ok(args.includes('--security-opt=no-new-privileges'));
    assert.ok(args.includes('--user'));
    assert.equal(args.filter((arg) => arg === '-v').length, 1, 'exactly one host mount');
    assert.ok(args.some((arg) => arg.endsWith(':/work:rw')), 'only the sandbox is mounted');
    assert.ok(args.includes('/work'));
    assert.ok(args.includes('npm'));
    assert.ok(args.includes('--ignore-scripts=false'), 'lifecycle scripts run inside the container');

    // The container must not receive the operator's environment.
    assert.equal(args.includes('ANTHROPIC_API_KEY'), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('InstallSandbox only opens the network when explicitly allowed', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-install-sandbox-'));
  try {
    const fetched = await createFetchedArtifact(root);
    let args: string[] = [];
    await new InstallSandbox().run(fetched, {
      packageManager: 'npm',
      allowNetwork: true,
      isolation: { kind: 'docker', image: 'node:22-slim', user: '1000:1000' },
      spawnFn: async (_command, capturedArgs) => {
        args = capturedArgs;
        return { exitCode: 0, stdout: '', stderr: '', killed: false };
      },
    });

    assert.ok(args.includes('--network=bridge'));
    assert.ok(args.includes('node:22-slim'));
    assert.ok(args.includes('1000:1000'));
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
