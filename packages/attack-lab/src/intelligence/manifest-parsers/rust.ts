/**
 * Rust manifest parser — extracts dependencies from Cargo.toml files.
 */

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { DependencySurface } from '../contracts.js';

const MANIFEST_FILES = ['Cargo.toml', 'Cargo.lock'] as const;

export async function detectRustManifests(repoRoot: string): Promise<string[]> {
  const found: string[] = [];
  for (const file of MANIFEST_FILES) {
    try {
      await readFile(resolve(repoRoot, file), 'utf8');
      found.push(file);
    } catch {
      // not present
    }
  }
  return found;
}

export async function parseRustDependencies(repoRoot: string): Promise<DependencySurface[]> {
  const surfaces: DependencySurface[] = [];

  try {
    const content = await readFile(resolve(repoRoot, 'Cargo.toml'), 'utf8');
    const lines = content.split('\n');
    let inDeps = false;

    for (const line of lines) {
      const trimmed = line.trim();

      if (/^\[(.*dependencies.*)\]/.test(trimmed)) {
        inDeps = true;
        continue;
      }
      if (/^\[/.test(trimmed) && inDeps) {
        inDeps = false;
        continue;
      }

      if (inDeps) {
        // Simple form: name = "version"
        const simpleMatch = trimmed.match(/^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"/);
        if (simpleMatch) {
          surfaces.push({
            name: simpleMatch[1]!,
            version: simpleMatch[2]!,
            hasInstallScript: false,
            isDirectDependency: true,
            riskIndicators: collectCargoIndicators(simpleMatch[2]!),
          });
          continue;
        }

        // Table form: name = { version = "...", ... }
        const tableMatch = trimmed.match(/^([a-zA-Z0-9_-]+)\s*=\s*\{(.*)\}/);
        if (tableMatch) {
          const name = tableMatch[1]!;
          const attrs = tableMatch[2]!;
          const versionMatch = attrs.match(/version\s*=\s*"([^"]+)"/);
          const version = versionMatch?.[1] ?? '*';
          const riskIndicators = collectCargoIndicators(version);

          if (/git\s*=/.test(attrs)) riskIndicators.push('remote-source');
          if (/path\s*=/.test(attrs)) riskIndicators.push('non-registry-source');

          surfaces.push({
            name,
            version,
            hasInstallScript: false,
            isDirectDependency: true,
            riskIndicators,
          });
        }
      }
    }
  } catch {
    // Cargo.toml not present
  }

  return surfaces;
}

function collectCargoIndicators(version: string): string[] {
  const indicators: string[] = [];
  if (version === '*') indicators.push('floating-version');
  if (/^[~^]/.test(version)) indicators.push('semver-range');
  return indicators;
}
