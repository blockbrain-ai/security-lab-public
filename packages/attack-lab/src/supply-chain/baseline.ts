/**
 * Dependency baseline — fingerprints trusted dependency state,
 * detects drift, and manages baseline persistence.
 */

import { readFile, writeFile, rename, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve, dirname } from 'node:path';
import type { DependencyBaseline, ApprovedPackage, DependencyDrift } from './contracts.js';
import {
  detectLockfile,
  extractPackagesFromLockfile,
  readSelectedLockfile,
  type PackageManager,
} from '../dependencies/lockfile.js';

// ---------------------------------------------------------------------------
// Baseline creation
// ---------------------------------------------------------------------------

export async function createBaseline(repoRoot: string): Promise<DependencyBaseline> {
  const now = new Date().toISOString();
  const packageJsonContent = await safeRead(resolve(repoRoot, 'package.json'));
  const { selection, content: lockfileContent } = await readSelectedLockfile(repoRoot);

  const packages = extractApprovedPackages(lockfileContent, selection.packageManager, now);

  return {
    version: 1,
    approvedAt: now,
    packageManager: selection.packageManager,
    lockfileName: selection.lockfileName,
    packageJsonHash: sha256(packageJsonContent),
    lockfileHash: sha256(lockfileContent),
    packages,
  };
}

// ---------------------------------------------------------------------------
// Persistence (atomic tmp+mv)
// ---------------------------------------------------------------------------

export async function saveBaseline(baseline: DependencyBaseline, filePath: string): Promise<void> {
  await mkdir(dirname(filePath), { recursive: true });
  const tmp = `${filePath}.tmp`;
  await writeFile(tmp, JSON.stringify(baseline, null, 2), 'utf8');
  await rename(tmp, filePath);
}

export async function loadBaseline(filePath: string): Promise<DependencyBaseline | null> {
  try {
    const content = await readFile(filePath, 'utf8');
    return JSON.parse(content);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Drift detection
// ---------------------------------------------------------------------------

export async function detectDrift(
  baseline: DependencyBaseline,
  repoRoot: string,
): Promise<DependencyDrift[]> {
  const now = new Date().toISOString();
  const drifts: DependencyDrift[] = [];
  const selection = await detectLockfile(repoRoot);

  // Check package.json hash
  const currentPkgJson = await safeRead(resolve(repoRoot, 'package.json'));
  const currentPkgJsonHash = sha256(currentPkgJson);
  if (currentPkgJsonHash !== baseline.packageJsonHash) {
    drifts.push({
      detectedAt: now,
      kind: 'package_json_changed',
      packageName: 'package.json',
      previousHash: baseline.packageJsonHash,
      currentHash: currentPkgJsonHash,
      severity: 'medium',
      reason: 'package.json content has changed since baseline',
    });
  }

  // Check lockfile hash
  const currentLockfile = selection.lockfilePath ? await safeRead(selection.lockfilePath) : '';
  const currentLockfileHash = sha256(currentLockfile);
  if (currentLockfileHash !== baseline.lockfileHash) {
    drifts.push({
      detectedAt: now,
      kind: 'lockfile_changed',
      packageName: selection.lockfileName ?? baseline.lockfileName ?? 'lockfile',
      previousHash: baseline.lockfileHash,
      currentHash: currentLockfileHash,
      severity: 'high',
      reason: `${selection.lockfileName ?? baseline.lockfileName ?? 'Lockfile'} content has changed since baseline`,
    });

    // Detailed per-package drift
    const currentPackages = extractApprovedPackages(
      currentLockfile,
      selection.packageManager === 'unknown' ? (baseline.packageManager ?? 'unknown') : selection.packageManager,
      now,
    );
    const baselineMap = new Map(baseline.packages.map((p) => [p.name, p]));
    const currentMap = new Map(currentPackages.map((p) => [p.name, p]));

    // New packages
    for (const [name, pkg] of currentMap) {
      const prev = baselineMap.get(name);
      if (!prev) {
        drifts.push({
          detectedAt: now,
          kind: 'package_added',
          packageName: name,
          currentVersion: pkg.version,
          severity: pkg.hasInstallScript ? 'critical' : 'medium',
          reason: pkg.hasInstallScript
            ? `New package ${name}@${pkg.version} with install scripts`
            : `New package ${name}@${pkg.version}`,
        });
        continue;
      }

      if (prev.version !== pkg.version) {
        drifts.push({
          detectedAt: now,
          kind: 'version_changed',
          packageName: name,
          previousVersion: prev.version,
          currentVersion: pkg.version,
          severity: 'medium',
          reason: `${name} version changed: ${prev.version} → ${pkg.version}`,
        });
      }

      if (prev.integrityHash !== pkg.integrityHash) {
        drifts.push({
          detectedAt: now,
          kind: 'integrity_changed',
          packageName: name,
          previousHash: prev.integrityHash,
          currentHash: pkg.integrityHash,
          severity: 'high',
          reason: `${name} integrity hash changed without version change`,
        });
      }

      if (!prev.hasInstallScript && pkg.hasInstallScript) {
        drifts.push({
          detectedAt: now,
          kind: 'install_script_added',
          packageName: name,
          severity: 'critical',
          reason: `${name} gained install scripts that were not present in baseline`,
        });
      } else if (prev.installScriptHash && pkg.installScriptHash && prev.installScriptHash !== pkg.installScriptHash) {
        drifts.push({
          detectedAt: now,
          kind: 'install_script_changed',
          packageName: name,
          previousHash: prev.installScriptHash,
          currentHash: pkg.installScriptHash,
          severity: 'critical',
          reason: `${name} install script content changed`,
        });
      }

      if (prev.resolvedFrom && pkg.resolvedFrom && prev.resolvedFrom !== pkg.resolvedFrom) {
        drifts.push({
          detectedAt: now,
          kind: 'registry_changed',
          packageName: name,
          severity: 'high',
          reason: `${name} registry changed: ${prev.resolvedFrom} → ${pkg.resolvedFrom}`,
        });
      }
    }

    // Removed packages
    for (const name of baselineMap.keys()) {
      if (!currentMap.has(name)) {
        drifts.push({
          detectedAt: now,
          kind: 'package_removed',
          packageName: name,
          previousVersion: baselineMap.get(name)!.version,
          severity: 'low',
          reason: `${name} was removed`,
        });
      }
    }
  }

  return drifts;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function extractApprovedPackages(
  lockfileContent: string,
  packageManager: PackageManager,
  approvedAt: string,
): ApprovedPackage[] {
  if (!lockfileContent) return [];

  return extractPackagesFromLockfile(lockfileContent, packageManager)
    .map((pkg) => ({
      name: pkg.name,
      version: pkg.version,
      integrityHash: pkg.integrityHash ?? '',
      hasInstallScript: pkg.hasInstallScript,
      installScriptHash: pkg.installScriptHash ? sha256(pkg.installScriptHash) : undefined,
      resolvedFrom: pkg.resolvedFrom,
      approvedAt,
    }));
}

async function safeRead(path: string): Promise<string> {
  try {
    return await readFile(path, 'utf8');
  } catch {
    return '';
  }
}

function sha256(content: string): string {
  return createHash('sha256').update(content).digest('hex');
}
