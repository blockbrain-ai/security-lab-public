/**
 * Lockfile intelligence — package-manager detection, normalized package
 * extraction, and lockfile-specific risk indicator collection.
 */

import { access, readFile } from 'node:fs/promises';
import { resolve, basename } from 'node:path';
import YAML from 'yaml';

export type PackageManager = 'npm' | 'pnpm' | 'yarn' | 'unknown';

export interface LockfileSelection {
  packageManager: PackageManager;
  lockfileName: string | null;
  lockfilePath: string | null;
  source: 'explicit' | 'packageManagerField' | 'lockfilePresence' | 'none';
  allLockfiles: string[];
}

export interface NormalizedLockfilePackage {
  name: string;
  version: string;
  integrityHash?: string;
  resolvedFrom?: string;
  hasInstallScript: boolean;
  installScriptHash?: string;
}

const LOCKFILE_BY_MANAGER: Record<Exclude<PackageManager, 'unknown'>, string> = {
  pnpm: 'pnpm-lock.yaml',
  yarn: 'yarn.lock',
  npm: 'package-lock.json',
};

const DETECTION_ORDER: string[] = [
  LOCKFILE_BY_MANAGER.pnpm,
  LOCKFILE_BY_MANAGER.yarn,
  LOCKFILE_BY_MANAGER.npm,
];

export async function detectLockfile(
  repoRoot: string,
  explicitFilePath?: string,
): Promise<LockfileSelection> {
  const allLockfiles = await findLockfiles(repoRoot);

  if (explicitFilePath) {
    const explicitName = basename(explicitFilePath);
    return {
      packageManager: inferPackageManagerFromLockfile(explicitName),
      lockfileName: explicitName,
      lockfilePath: resolve(repoRoot, explicitFilePath),
      source: 'explicit',
      allLockfiles,
    };
  }

  const packageManagerField = await readPackageManagerField(repoRoot);
  if (packageManagerField && await fileExists(resolve(repoRoot, LOCKFILE_BY_MANAGER[packageManagerField]))) {
    return {
      packageManager: packageManagerField,
      lockfileName: LOCKFILE_BY_MANAGER[packageManagerField],
      lockfilePath: resolve(repoRoot, LOCKFILE_BY_MANAGER[packageManagerField]),
      source: 'packageManagerField',
      allLockfiles,
    };
  }

  const inferred = allLockfiles.find((entry) => DETECTION_ORDER.includes(entry));
  if (inferred) {
    return {
      packageManager: inferPackageManagerFromLockfile(inferred),
      lockfileName: inferred,
      lockfilePath: resolve(repoRoot, inferred),
      source: 'lockfilePresence',
      allLockfiles,
    };
  }

  return {
    packageManager: packageManagerField ?? 'unknown',
    lockfileName: packageManagerField ? LOCKFILE_BY_MANAGER[packageManagerField] : null,
    lockfilePath: packageManagerField ? resolve(repoRoot, LOCKFILE_BY_MANAGER[packageManagerField]) : null,
    source: 'none',
    allLockfiles,
  };
}

export async function readSelectedLockfile(
  repoRoot: string,
  explicitFilePath?: string,
): Promise<{ selection: LockfileSelection; content: string }> {
  const selection = await detectLockfile(repoRoot, explicitFilePath);
  if (!selection.lockfilePath) {
    return { selection, content: '' };
  }

  try {
    return {
      selection,
      content: await readFile(selection.lockfilePath, 'utf8'),
    };
  } catch {
    return { selection, content: '' };
  }
}

export function collectIndicatorsFromLockfile(
  content: string,
  selection: Pick<LockfileSelection, 'packageManager' | 'lockfileName'>,
): string[] {
  if (!content) {
    return [];
  }

  const packages = extractPackagesFromLockfile(content, selection.packageManager);
  if (packages.length === 0) {
    return [];
  }

  const indicators: string[] = [];
  for (const pkg of packages) {
    if (pkg.resolvedFrom && !isDefaultRegistryUrl(pkg.resolvedFrom)) {
      indicators.push(`unusual-registry:${pkg.resolvedFrom}`);
    }
  }

  const withIntegrity = packages.filter((pkg) => Boolean(pkg.integrityHash)).length;
  if (packages.length > 0 && withIntegrity < packages.length) {
    indicators.push(`integrity-gap:${withIntegrity}/${packages.length}`);
  }

  if (selection.lockfileName) {
    indicators.push(`lockfile:${selection.lockfileName}`);
  }

  return [...new Set(indicators)];
}

export function flattenLockfileDependencies(
  content: string,
  packageManager: PackageManager,
): Map<string, string> {
  return new Map(
    extractPackagesFromLockfile(content, packageManager).map((pkg) => [pkg.name, pkg.version]),
  );
}

export function extractPackagesFromLockfile(
  content: string,
  packageManager: PackageManager,
): NormalizedLockfilePackage[] {
  switch (packageManager) {
    case 'pnpm':
      return extractPnpmPackages(content);
    case 'yarn':
      return extractYarnPackages(content);
    case 'npm':
      return extractNpmPackages(content);
    default:
      return extractNpmPackages(content);
  }
}

export function inferPackageManagerFromLockfile(lockfileName: string): PackageManager {
  if (lockfileName === 'pnpm-lock.yaml') return 'pnpm';
  if (lockfileName === 'yarn.lock') return 'yarn';
  if (lockfileName === 'package-lock.json') return 'npm';
  return 'unknown';
}

async function findLockfiles(repoRoot: string): Promise<string[]> {
  const found: string[] = [];
  for (const name of DETECTION_ORDER) {
    if (await fileExists(resolve(repoRoot, name))) {
      found.push(name);
    }
  }
  return found;
}

async function readPackageManagerField(repoRoot: string): Promise<Exclude<PackageManager, 'unknown'> | null> {
  try {
    const pkg = JSON.parse(await readFile(resolve(repoRoot, 'package.json'), 'utf8')) as { packageManager?: string };
    const raw = pkg.packageManager?.toLowerCase().trim();
    if (!raw) {
      return null;
    }
    if (raw.startsWith('pnpm@')) return 'pnpm';
    if (raw.startsWith('yarn@')) return 'yarn';
    if (raw.startsWith('npm@')) return 'npm';
  } catch {
    // Ignore package.json issues here.
  }
  return null;
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

function extractNpmPackages(content: string): NormalizedLockfilePackage[] {
  try {
    const lockfile = JSON.parse(content) as Record<string, unknown>;
    const packages: NormalizedLockfilePackage[] = [];
    const pkgEntries = (lockfile['packages'] ?? lockfile['dependencies'] ?? {}) as Record<string, unknown>;

    for (const [rawName, info] of Object.entries(pkgEntries)) {
      if (rawName === '' || typeof info !== 'object' || info === null) {
        continue;
      }

      const pkg = info as Record<string, unknown>;
      const scripts = (pkg['scripts'] ?? {}) as Record<string, string>;
      const installScripts = [scripts['preinstall'], scripts['install'], scripts['postinstall']]
        .filter((value): value is string => typeof value === 'string');

      packages.push({
        name: rawName.replace(/^node_modules\//, ''),
        version: String(pkg['version'] ?? ''),
        integrityHash: typeof pkg['integrity'] === 'string' ? pkg['integrity'] : undefined,
        resolvedFrom: typeof pkg['resolved'] === 'string' ? pkg['resolved'] : undefined,
        hasInstallScript: installScripts.length > 0,
        installScriptHash: installScripts.length > 0 ? installScripts.join('\n') : undefined,
      });
    }

    return packages;
  } catch {
    return [];
  }
}

function extractPnpmPackages(content: string): NormalizedLockfilePackage[] {
  try {
    const lockfile = YAML.parse(content) as {
      packages?: Record<string, Record<string, unknown>>;
    };
    const entries = lockfile?.packages ?? {};
    const packages: NormalizedLockfilePackage[] = [];

    for (const [rawKey, info] of Object.entries(entries)) {
      const descriptor = parsePnpmPackageKey(rawKey);
      if (!descriptor || !info || typeof info !== 'object') {
        continue;
      }

      const resolution = (info['resolution'] ?? {}) as Record<string, unknown>;
      packages.push({
        name: descriptor.name,
        version: descriptor.version,
        integrityHash: typeof resolution['integrity'] === 'string' ? resolution['integrity'] : undefined,
        resolvedFrom: typeof resolution['tarball'] === 'string' ? resolution['tarball'] : undefined,
        hasInstallScript: Boolean(info['requiresBuild']),
      });
    }

    return packages;
  } catch {
    return [];
  }
}

function extractYarnPackages(content: string): NormalizedLockfilePackage[] {
  const packages: NormalizedLockfilePackage[] = [];
  const blocks = content.split(/\n{2,}/).map((block) => block.trim()).filter(Boolean);

  for (const block of blocks) {
    const lines = block.split('\n');
    const header = lines[0];
    if (!header?.endsWith(':')) {
      continue;
    }

    const selector = header.slice(0, -1).split(',')[0]?.trim().replace(/^"|"$/g, '');
    const descriptor = selector ? parseYarnSelector(selector) : null;
    if (!descriptor) {
      continue;
    }

    const version = lines.find((line) => line.trimStart().startsWith('version '))?.trim().replace(/^version\s+/, '').replace(/^"|"$/g, '');
    const resolved = lines.find((line) => line.trimStart().startsWith('resolved '))?.trim().replace(/^resolved\s+/, '').replace(/^"|"$/g, '');
    const integrity = lines.find((line) => line.trimStart().startsWith('integrity '))?.trim().replace(/^integrity\s+/, '');

    packages.push({
      name: descriptor.name,
      version: version ?? descriptor.version ?? '',
      integrityHash: integrity || undefined,
      resolvedFrom: resolved || undefined,
      hasInstallScript: false,
    });
  }

  return packages;
}

function parsePnpmPackageKey(rawKey: string): { name: string; version: string } | null {
  const withoutPeers = rawKey.replace(/^\//, '').split('(')[0] ?? '';
  const atIndex = withoutPeers.lastIndexOf('@');
  if (atIndex <= 0 || atIndex === withoutPeers.length - 1) {
    return null;
  }

  return {
    name: withoutPeers.slice(0, atIndex),
    version: withoutPeers.slice(atIndex + 1),
  };
}

function parseYarnSelector(selector: string): { name: string; version?: string } | null {
  const withoutAlias = selector.includes('npm:') ? selector.split('npm:')[1] ?? selector : selector;
  const atIndex = withoutAlias.lastIndexOf('@');
  if (withoutAlias.startsWith('@')) {
    if (atIndex <= 0) {
      return null;
    }
    return {
      name: withoutAlias.slice(0, atIndex),
      version: withoutAlias.slice(atIndex + 1),
    };
  }

  if (atIndex <= 0) {
    return { name: withoutAlias };
  }

  return {
    name: withoutAlias.slice(0, atIndex),
    version: withoutAlias.slice(atIndex + 1),
  };
}

function isDefaultRegistryUrl(url: string): boolean {
  return url.startsWith('https://registry.npmjs.org/')
    || url.startsWith('https://registry.yarnpkg.com/')
    || url.startsWith('https://registry.npmmirror.com/');
}
