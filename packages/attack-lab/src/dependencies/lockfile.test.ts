import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  collectIndicatorsFromLockfile,
  detectLockfile,
  extractPackagesFromLockfile,
  flattenLockfileDependencies,
  inferPackageManagerFromLockfile,
  readSelectedLockfile,
} from './lockfile.js';

test('detectLockfile respects explicit override and packageManager field', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-lockfile-'));

  try {
    await writeFile(
      join(root, 'package.json'),
      JSON.stringify({
        name: 'fixture',
        version: '1.0.0',
        packageManager: 'pnpm@10.0.0',
      }, null, 2),
      'utf8',
    );
    await writeFile(join(root, 'pnpm-lock.yaml'), "lockfileVersion: '9.0'\n", 'utf8');
    await writeFile(join(root, 'package-lock.json'), JSON.stringify({ packages: {} }, null, 2), 'utf8');

    const inferred = await detectLockfile(root);
    assert.equal(inferred.packageManager, 'pnpm');
    assert.equal(inferred.lockfileName, 'pnpm-lock.yaml');
    assert.equal(inferred.source, 'packageManagerField');
    assert.deepEqual(inferred.allLockfiles, ['pnpm-lock.yaml', 'package-lock.json']);

    const explicit = await detectLockfile(root, 'package-lock.json');
    assert.equal(explicit.packageManager, 'npm');
    assert.equal(explicit.source, 'explicit');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('readSelectedLockfile and helpers handle missing or non-npm lockfiles', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-lockfile-missing-'));

  try {
    await writeFile(
      join(root, 'package.json'),
      JSON.stringify({
        name: 'fixture',
        version: '1.0.0',
        packageManager: 'yarn@4.0.0',
      }, null, 2),
      'utf8',
    );

    const missing = await readSelectedLockfile(root);
    assert.equal(missing.selection.packageManager, 'yarn');
    assert.equal(missing.selection.source, 'none');
    assert.equal(missing.content, '');

    const yarnContent = `"safe-lib@^1.0.0":
  version "1.0.0"
  resolved "https://evil.example/safe-lib-1.0.0.tgz"
  integrity sha512-safe
`;
    const indicators = collectIndicatorsFromLockfile(yarnContent, {
      packageManager: 'yarn',
      lockfileName: 'yarn.lock',
    });
    assert.ok(indicators.includes('lockfile:yarn.lock'));
    assert.ok(indicators.some((indicator) => indicator.startsWith('unusual-registry:')));

    const packages = extractPackagesFromLockfile(yarnContent, 'yarn');
    assert.equal(packages[0]?.name, 'safe-lib');
    assert.equal(packages[0]?.version, '1.0.0');

    const deps = flattenLockfileDependencies(JSON.stringify({
      packages: {
        'node_modules/demo': { version: '2.0.0' },
      },
    }), 'unknown');
    assert.equal(deps.get('demo'), '2.0.0');

    assert.equal(inferPackageManagerFromLockfile('mystery.lock'), 'unknown');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
