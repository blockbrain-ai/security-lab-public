import test from 'node:test';
import assert from 'node:assert/strict';
import { rm, writeFile } from 'node:fs/promises';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ProvenanceVerifier } from './provenance-verifier.js';
import type { ArtifactFetchResult } from './contracts.js';

test('ProvenanceVerifier detects install scripts, obfuscation, network calls, native binaries, and registry drift', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-provenance-'));

  try {
    await writeFile(
      join(root, 'package.json'),
      JSON.stringify({
        name: 'fixture-package',
        version: '1.0.0',
        scripts: {
          preinstall: 'node scripts/preinstall.js',
          postinstall: 'node scripts/postinstall.js',
        },
      }, null, 2),
      'utf8',
    );
    await writeFile(
      join(root, 'index.js'),
      'fetch("https://example.test"); eval(Buffer.from("6869", "hex").toString());\n',
      'utf8',
    );
    await writeFile(join(root, 'addon.node'), 'binary', 'utf8');

    const fetched: ArtifactFetchResult = {
      packageName: 'fixture-package',
      version: '1.0.0',
      tarballPath: join(root, 'package.tgz'),
      unpackedPath: root,
      tarballSha256: 'abc123',
      fetchedFrom: 'https://registry.npmjs.org/fixture-package/-/fixture-package-1.0.0.tgz',
      fetchedAt: new Date().toISOString(),
    };

    const verifier = new ProvenanceVerifier();
    const inspection = await verifier.inspect(fetched, 'https://internal.registry.example');

    assert.equal(inspection.hasInstallScript, true);
    assert.equal(inspection.hasPostInstallScript, true);
    assert.equal(inspection.hasNativeBinaries, true);
    assert.equal(inspection.containsNetworkCalls, true);
    assert.equal(inspection.hasObfuscatedSource, true);
    assert.equal(inspection.registryMatchesBaseline, false);
    assert.match(inspection.notes.join('\n'), /Registry mismatch/);
    assert.match(inspection.notes.join('\n'), /Signature verification not implemented/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
