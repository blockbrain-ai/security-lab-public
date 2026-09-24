/**
 * Python manifest parser — extracts dependencies from requirements.txt
 * and pyproject.toml files.
 */

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { DependencySurface } from '../contracts.js';

const MANIFEST_FILES = ['requirements.txt', 'pyproject.toml', 'Pipfile', 'setup.py', 'setup.cfg'] as const;

export async function detectPythonManifests(repoRoot: string): Promise<string[]> {
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

export async function parsePythonDependencies(repoRoot: string): Promise<DependencySurface[]> {
  const surfaces: DependencySurface[] = [];

  // Parse requirements.txt
  try {
    const content = await readFile(resolve(repoRoot, 'requirements.txt'), 'utf8');
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;

      const match = trimmed.match(/^([a-zA-Z0-9_.-]+)\s*([><=!~]+\s*[\d.*]+(?:\s*,\s*[><=!~]+\s*[\d.*]+)*)?/);
      if (match) {
        const name = match[1]!;
        const version = match[2]?.trim() ?? '*';
        const riskIndicators: string[] = [];
        if (version === '*') riskIndicators.push('floating-version');
        if (/^git\+|^https?:\/\/|^svn\+/.test(trimmed)) riskIndicators.push('remote-source');

        surfaces.push({
          name,
          version,
          hasInstallScript: false,
          isDirectDependency: true,
          riskIndicators,
        });
      }
    }
  } catch {
    // requirements.txt not present
  }

  // Parse pyproject.toml (basic extraction)
  try {
    const content = await readFile(resolve(repoRoot, 'pyproject.toml'), 'utf8');
    const depSection = content.match(/\[project\][\s\S]*?dependencies\s*=\s*\[([\s\S]*?)\]/);
    if (depSection) {
      const depBlock = depSection[1]!;
      for (const line of depBlock.split('\n')) {
        const match = line.match(/["']([a-zA-Z0-9_.-]+)\s*([><=!~].*?)?["']/);
        if (match) {
          const name = match[1]!;
          const version = match[2]?.trim() ?? '*';
          const riskIndicators: string[] = [];
          if (version === '*') riskIndicators.push('floating-version');
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
    // pyproject.toml not present
  }

  return surfaces;
}
