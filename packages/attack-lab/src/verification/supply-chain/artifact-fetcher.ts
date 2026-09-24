/**
 * Artifact fetcher — fetches package tarballs into a quarantine
 * workspace without polluting the target repo. Uses npm's public
 * registry metadata API by default.
 */

import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { ArtifactFetchResult } from './contracts.js';

const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------------------
// Fetcher options
// ---------------------------------------------------------------------------

export interface ArtifactFetcherOptions {
  quarantineDir: string;
  registry?: string;
  fetchFn?: typeof fetch;
}

// ---------------------------------------------------------------------------
// Artifact fetcher
// ---------------------------------------------------------------------------

export class ArtifactFetcher {
  constructor(private readonly options: ArtifactFetcherOptions) {}

  async fetch(packageName: string, version: string): Promise<ArtifactFetchResult> {
    const fetchFn = this.options.fetchFn ?? fetch;
    const registry = this.options.registry ?? 'https://registry.npmjs.org';
    const safeName = packageName.replace('/', '_');
    const packageDir = resolve(this.options.quarantineDir, safeName, version);
    await mkdir(packageDir, { recursive: true });

    // Fetch tarball URL from registry metadata
    const metadataUrl = `${registry}/${encodeURIComponent(packageName).replace('%40', '@')}/${version}`;
    const metadataResponse = await fetchFn(metadataUrl, {
      signal: AbortSignal.timeout(20_000),
    });
    if (!metadataResponse.ok) {
      throw new Error(`Failed to fetch metadata for ${packageName}@${version}: ${metadataResponse.status}`);
    }
    const metadata = (await metadataResponse.json()) as { dist?: { tarball?: string } };
    const tarballUrl = metadata.dist?.tarball;
    if (!tarballUrl) {
      throw new Error(`No tarball URL in metadata for ${packageName}@${version}`);
    }

    // Fetch the tarball itself
    const tarballResponse = await fetchFn(tarballUrl, { signal: AbortSignal.timeout(60_000) });
    if (!tarballResponse.ok) {
      throw new Error(`Failed to fetch tarball ${tarballUrl}: ${tarballResponse.status}`);
    }
    const tarballBuffer = Buffer.from(await tarballResponse.arrayBuffer());
    const tarballPath = resolve(packageDir, 'package.tgz');
    await writeFile(tarballPath, tarballBuffer);
    const tarballSha256 = createHash('sha256').update(tarballBuffer).digest('hex');

    // Unpack into ./unpacked using tar (read-only extract, no execution)
    const unpackedPath = resolve(packageDir, 'unpacked');
    await mkdir(unpackedPath, { recursive: true });
    await execFileAsync('tar', ['-xzf', tarballPath, '-C', unpackedPath, '--strip-components=1'], {
      timeout: 30_000,
    });

    return {
      packageName,
      version,
      tarballPath,
      unpackedPath,
      tarballSha256,
      fetchedFrom: tarballUrl,
      fetchedAt: new Date().toISOString(),
    };
  }

  async readManifest(unpackedPath: string): Promise<Record<string, unknown> | null> {
    try {
      const content = await readFile(resolve(unpackedPath, 'package.json'), 'utf8');
      return JSON.parse(content) as Record<string, unknown>;
    } catch {
      return null;
    }
  }
}
