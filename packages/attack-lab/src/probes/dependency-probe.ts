/**
 * Dependency probe — inspects lockfiles, package manifests, install scripts,
 * and provenance metadata for supply-chain risk indicators.
 */

import { readFile, stat } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import type { ProbeObservation } from '../../../evidence-plane/src/contracts.js';
import {
  collectIndicatorsFromLockfile,
  detectLockfile,
  flattenLockfileDependencies,
  readSelectedLockfile,
} from '../dependencies/lockfile.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DependencyProbeConfig {
  kind: 'dependency_read';
  action: 'inspect_lockfile' | 'check_scripts' | 'scan_provenance' | 'diff_lockfile';
  /** Path to lockfile or package.json relative to target root. */
  filePath?: string;
  /** Previous lockfile content for diff comparison. */
  previousContent?: string;
  timeoutMs: number;
}

export interface DependencyTargetConfig {
  kind: 'dependency';
  id: string;
  environment: string;
  /** Absolute path to the target repository root. */
  repoRoot: string;
}

// ---------------------------------------------------------------------------
// Risk indicators
// ---------------------------------------------------------------------------

const RISKY_SCRIPT_PATTERNS = [
  /curl\s+/i,
  /wget\s+/i,
  /eval\(/,
  /exec\(/,
  /child_process/,
  /\.sh\b/,
  /base64/i,
  /\bhttp:\/\//,
  /\$\(/,
  /`[^`]*`/,
];

const RISKY_SCRIPT_NAMES = ['preinstall', 'install', 'postinstall', 'preuninstall'];

// ---------------------------------------------------------------------------
// Probe execution
// ---------------------------------------------------------------------------

export async function runDependencyProbe(
  probe: DependencyProbeConfig,
  target: DependencyTargetConfig,
): Promise<ProbeObservation> {
  const start = Date.now();

  try {
    switch (probe.action) {
      case 'inspect_lockfile':
        return await inspectLockfile(probe, target, start);
      case 'check_scripts':
        return await checkScripts(probe, target, start);
      case 'scan_provenance':
        return await scanProvenance(target, start);
      case 'diff_lockfile':
        return await diffLockfile(probe, target, start);
      default:
        return { kind: 'dependency_read', stderr: `Unknown action: ${probe.action}`, durationMs: Date.now() - start };
    }
  } catch (error: unknown) {
    return {
      kind: 'dependency_read',
      stderr: error instanceof Error ? error.message : String(error),
      durationMs: Date.now() - start,
    };
  }
}

async function inspectLockfile(
  probe: DependencyProbeConfig,
  target: DependencyTargetConfig,
  start: number,
): Promise<ProbeObservation> {
  const { selection, content } = await readSelectedLockfile(target.repoRoot, probe.filePath);
  if (!content || !selection.lockfilePath) {
    return {
      kind: 'dependency_read',
      stderr: `No lockfile found for ${selection.packageManager === 'unknown' ? 'the detected package manager' : selection.packageManager}`,
      durationMs: Date.now() - start,
    };
  }

  const findings = collectIndicatorsFromLockfile(content, selection)
    .filter((indicator) => !indicator.startsWith('lockfile:'))
    .map((indicator) => indicator.replace(/:/, ': '));

  return {
    kind: 'dependency_read',
    stdout: findings.length > 0 ? findings.join('\n') : 'no anomalies detected',
    exitCode: findings.length > 0 ? 1 : 0,
    durationMs: Date.now() - start,
  };
}

async function checkScripts(
  probe: DependencyProbeConfig,
  target: DependencyTargetConfig,
  start: number,
): Promise<ProbeObservation> {
  const pkgPath = resolve(target.repoRoot, probe.filePath ?? 'package.json');
  const content = await readFile(pkgPath, 'utf8');
  const pkg = JSON.parse(content);
  const findings: string[] = [];

  const scripts = pkg.scripts ?? {};
  for (const name of RISKY_SCRIPT_NAMES) {
    if (scripts[name]) {
      const script = scripts[name] as string;
      for (const pattern of RISKY_SCRIPT_PATTERNS) {
        if (pattern.test(script)) {
          findings.push(`risky-script: ${name} matches ${pattern.source}: "${script}"`);
        }
      }
    }
  }

  // Check dependencies for install scripts
  const deps = { ...pkg.dependencies, ...pkg.devDependencies };
  for (const [depName, version] of Object.entries(deps)) {
    const depPkgPath = join(target.repoRoot, 'node_modules', depName, 'package.json');
    try {
      await stat(depPkgPath);
      const depPkg = JSON.parse(await readFile(depPkgPath, 'utf8'));
      const depScripts = depPkg.scripts ?? {};
      for (const scriptName of RISKY_SCRIPT_NAMES) {
        if (depScripts[scriptName]) {
          const script = depScripts[scriptName] as string;
          for (const pattern of RISKY_SCRIPT_PATTERNS) {
            if (pattern.test(script)) {
              findings.push(`dep-risky-script: ${depName}@${version} ${scriptName} matches ${pattern.source}`);
            }
          }
        }
      }
    } catch {
      // Dependency not installed locally, skip
    }
  }

  return {
    kind: 'dependency_read',
    stdout: findings.length > 0 ? findings.join('\n') : 'no risky scripts detected',
    exitCode: findings.length > 0 ? 1 : 0,
    durationMs: Date.now() - start,
  };
}

async function scanProvenance(
  target: DependencyTargetConfig,
  start: number,
): Promise<ProbeObservation> {
  const findings: string[] = [];

  // Check for .npmrc with unusual registry
  try {
    const npmrc = await readFile(resolve(target.repoRoot, '.npmrc'), 'utf8');
    if (npmrc.includes('registry=') && !npmrc.includes('registry.npmjs.org')) {
      findings.push(`custom-registry: .npmrc uses non-default registry`);
    }
  } catch {
    // No .npmrc, fine
  }

  const selection = await detectLockfile(target.repoRoot);
  const foundLocks = selection.allLockfiles;
  if (foundLocks.length > 1) {
    findings.push(`mixed-lockfiles: ${foundLocks.join(', ')}`);
  }
  if (selection.lockfileName) {
    findings.push(`detected-lockfile: ${selection.lockfileName}`);
  }

  return {
    kind: 'dependency_read',
    stdout: findings.length > 0 ? findings.join('\n') : 'no provenance anomalies',
    exitCode: findings.length > 0 ? 1 : 0,
    durationMs: Date.now() - start,
  };
}

async function diffLockfile(
  probe: DependencyProbeConfig,
  target: DependencyTargetConfig,
  start: number,
): Promise<ProbeObservation> {
  if (!probe.previousContent) {
    return { kind: 'dependency_read', stderr: 'previousContent required for diff_lockfile', durationMs: Date.now() - start };
  }

  const { selection, content: currentContent } = await readSelectedLockfile(target.repoRoot, probe.filePath);
  if (!currentContent || !selection.lockfilePath) {
    return { kind: 'dependency_read', stderr: 'no lockfile available for diff', durationMs: Date.now() - start };
  }

  const prevDeps = flattenLockfileDependencies(probe.previousContent, selection.packageManager);
  const currDeps = flattenLockfileDependencies(currentContent, selection.packageManager);

  const added: string[] = [];
  const removed: string[] = [];
  const changed: string[] = [];

  for (const [name, version] of currDeps) {
    const prevVersion = prevDeps.get(name);
    if (!prevVersion) {
      added.push(`+${name}@${version}`);
    } else if (prevVersion !== version) {
      changed.push(`~${name}: ${prevVersion} → ${version}`);
    }
  }
  for (const [name] of prevDeps) {
    if (!currDeps.has(name)) {
      removed.push(`-${name}`);
    }
  }

  const output = [...added, ...removed, ...changed];
  return {
    kind: 'dependency_read',
    stdout: output.length > 0 ? output.join('\n') : 'no changes detected',
    exitCode: output.length > 0 ? 1 : 0,
    durationMs: Date.now() - start,
  };
}
