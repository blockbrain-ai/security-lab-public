import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { mkdtemp } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ArtifactFetcher } from './artifact-fetcher.js';

const execFileAsync = promisify(execFile);

async function createPackageTarball(root: string, packageName = 'fixture-package'): Promise<Buffer> {
  const staging = join(root, 'staging');
  const pkgDir = join(staging, 'package');
  await mkdir(pkgDir, { recursive: true });
  await writeFile(
    join(pkgDir, 'package.json'),
    JSON.stringify({ name: packageName, version: '1.0.0' }, null, 2),
    'utf8',
  );
  await writeFile(join(pkgDir, 'index.js'), 'module.exports = 1;\n', 'utf8');

  const tarballPath = join(root, 'package.tgz');
  await execFileAsync('tar', ['-czf', tarballPath, '-C', staging, 'package']);
  return readFile(tarballPath);
}

test('ArtifactFetcher fetches, unpacks, and reads package manifests', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-fetcher-'));

  try {
    const tarballBuffer = await createPackageTarball(root);
    const fetcher = new ArtifactFetcher({
      quarantineDir: join(root, 'quarantine'),
      fetchFn: async (url) => {
        if (String(url).includes('/fixture-package/1.0.0')) {
          return new Response(JSON.stringify({ dist: { tarball: 'https://example.test/package.tgz' } }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        return new Response(tarballBuffer, { status: 200 });
      },
    });

    const result = await fetcher.fetch('fixture-package', '1.0.0');
    assert.equal(result.packageName, 'fixture-package');
    assert.equal(result.version, '1.0.0');
    assert.equal(result.tarballSha256.length, 64);

    const manifest = await fetcher.readManifest(result.unpackedPath);
    assert.equal(manifest?.['name'], 'fixture-package');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('ArtifactFetcher fails cleanly when metadata is incomplete', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-fetcher-'));

  try {
    const fetcher = new ArtifactFetcher({
      quarantineDir: join(root, 'quarantine'),
      fetchFn: async () =>
        new Response(JSON.stringify({ dist: {} }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
    });

    await assert.rejects(fetcher.fetch('fixture-package', '1.0.0'), /No tarball URL/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
