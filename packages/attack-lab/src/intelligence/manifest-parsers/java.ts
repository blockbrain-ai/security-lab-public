/**
 * Java manifest parser — detects pom.xml and build.gradle presence
 * and extracts basic dependency information.
 */

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { DependencySurface } from '../contracts.js';

const MANIFEST_FILES = ['pom.xml', 'build.gradle', 'build.gradle.kts'] as const;

export async function detectJavaManifests(repoRoot: string): Promise<string[]> {
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

export async function parseJavaDependencies(repoRoot: string): Promise<DependencySurface[]> {
  const surfaces: DependencySurface[] = [];

  // Parse pom.xml — extract <dependency> blocks with regex (not a full XML parser)
  try {
    const content = await readFile(resolve(repoRoot, 'pom.xml'), 'utf8');
    const depPattern = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*(?:<version>([^<]+)<\/version>)?/g;
    let match;
    while ((match = depPattern.exec(content)) !== null) {
      const groupId = match[1]!;
      const artifactId = match[2]!;
      const version = match[3] ?? '*';
      const riskIndicators: string[] = [];
      if (version === '*' || version.includes('SNAPSHOT')) riskIndicators.push('floating-version');

      surfaces.push({
        name: `${groupId}:${artifactId}`,
        version,
        hasInstallScript: false,
        isDirectDependency: true,
        riskIndicators,
      });
    }
  } catch {
    // pom.xml not present
  }

  // Parse build.gradle — basic regex extraction
  try {
    const content = await readFile(resolve(repoRoot, 'build.gradle'), 'utf8');
    const depPattern = /(?:implementation|api|compile|testImplementation)\s+['"]([^'"]+)['"]/g;
    let match;
    while ((match = depPattern.exec(content)) !== null) {
      const parts = match[1]!.split(':');
      if (parts.length >= 2) {
        const name = `${parts[0]}:${parts[1]}`;
        const version = parts[2] ?? '*';
        const riskIndicators: string[] = [];
        if (version === '*' || version === '+' || version.includes('SNAPSHOT')) riskIndicators.push('floating-version');
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
    // build.gradle not present
  }

  return surfaces;
}
