/**
 * Go manifest parser — extracts dependencies from go.mod files.
 */

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { DependencySurface } from '../contracts.js';

const MANIFEST_FILES = ['go.mod', 'go.sum'] as const;

export async function detectGoManifests(repoRoot: string): Promise<string[]> {
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

export async function parseGoDependencies(repoRoot: string): Promise<DependencySurface[]> {
  const surfaces: DependencySurface[] = [];

  try {
    const content = await readFile(resolve(repoRoot, 'go.mod'), 'utf8');
    const lines = content.split('\n');
    let inRequireBlock = false;

    for (const line of lines) {
      const trimmed = line.trim();

      if (trimmed === 'require (') {
        inRequireBlock = true;
        continue;
      }
      if (trimmed === ')') {
        inRequireBlock = false;
        continue;
      }

      // Single-line require
      const singleMatch = trimmed.match(/^require\s+(\S+)\s+(\S+)/);
      if (singleMatch) {
        surfaces.push({
          name: singleMatch[1]!,
          version: singleMatch[2]!,
          hasInstallScript: false,
          isDirectDependency: true,
          riskIndicators: collectGoIndicators(singleMatch[2]!),
        });
        continue;
      }

      // Block require
      if (inRequireBlock) {
        const blockMatch = trimmed.match(/^(\S+)\s+(\S+)/);
        if (blockMatch && !trimmed.startsWith('//')) {
          const isIndirect = trimmed.includes('// indirect');
          surfaces.push({
            name: blockMatch[1]!,
            version: blockMatch[2]!,
            hasInstallScript: false,
            isDirectDependency: !isIndirect,
            riskIndicators: collectGoIndicators(blockMatch[2]!),
          });
        }
      }
    }
  } catch {
    // go.mod not present
  }

  return surfaces;
}

function collectGoIndicators(version: string): string[] {
  const indicators: string[] = [];
  if (version.includes('+incompatible')) indicators.push('incompatible-version');
  if (/^v0\./.test(version)) indicators.push('pre-stable');
  return indicators;
}
