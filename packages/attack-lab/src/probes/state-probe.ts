/**
 * State probe — tests for state/config mutation, audit bypass,
 * and evidence tampering vulnerabilities.
 */

import { readFile, stat, access, constants } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { ProbeObservation } from '../../../evidence-plane/src/contracts.js';

export interface StateProbeConfig {
  kind: 'state_check';
  action: 'writability_check' | 'tamper_detect' | 'config_mutation_check';
  /** Path to the file to check, relative to target root. */
  filePath: string;
  /** Expected content hash for tamper detection. */
  expectedHash?: string;
  timeoutMs: number;
}

export async function runStateProbe(
  probe: StateProbeConfig,
  targetRoot: string,
): Promise<ProbeObservation> {
  const start = Date.now();
  const absPath = resolve(targetRoot, probe.filePath);

  try {
    switch (probe.action) {
      case 'writability_check':
        return await writabilityCheck(absPath, probe.filePath, start);
      case 'tamper_detect':
        return await tamperDetect(absPath, probe.filePath, probe.expectedHash, start);
      case 'config_mutation_check':
        return await configMutationCheck(absPath, probe.filePath, start);
      default:
        return { kind: 'state_check', stderr: `Unknown action: ${probe.action}`, durationMs: Date.now() - start };
    }
  } catch (error: unknown) {
    return {
      kind: 'state_check',
      stderr: error instanceof Error ? error.message : String(error),
      durationMs: Date.now() - start,
    };
  }
}

async function writabilityCheck(
  absPath: string,
  relPath: string,
  start: number,
): Promise<ProbeObservation> {
  const findings: string[] = [];

  try {
    await access(absPath, constants.W_OK);
    findings.push(`writable: ${relPath} is writable by current process`);
  } catch {
    findings.push(`protected: ${relPath} is not writable`);
  }

  try {
    const info = await stat(absPath);
    const mode = (info.mode & 0o777).toString(8);
    findings.push(`permissions: ${mode}`);
    findings.push(`owner_uid: ${info.uid}`);
    findings.push(`process_uid: ${process.getuid?.() ?? 'unknown'}`);
  } catch {
    findings.push('stat: failed');
  }

  const isVulnerable = findings.some((f) => f.startsWith('writable:'));
  return {
    kind: 'state_check',
    stdout: findings.join('\n'),
    exitCode: isVulnerable ? 1 : 0,
    durationMs: Date.now() - start,
  };
}

async function tamperDetect(
  absPath: string,
  _relPath: string,
  expectedHash: string | undefined,
  start: number,
): Promise<ProbeObservation> {
  const { createHash } = await import('node:crypto');
  const content = await readFile(absPath, 'utf8');
  const actualHash = createHash('sha256').update(content).digest('hex');

  const findings: string[] = [`hash: ${actualHash}`];

  if (expectedHash) {
    if (actualHash !== expectedHash) {
      findings.push(`TAMPERED: expected ${expectedHash}, got ${actualHash}`);
    } else {
      findings.push('integrity: matches expected hash');
    }
  }

  return {
    kind: 'state_check',
    stdout: findings.join('\n'),
    exitCode: expectedHash && actualHash !== expectedHash ? 1 : 0,
    durationMs: Date.now() - start,
  };
}

async function configMutationCheck(
  absPath: string,
  relPath: string,
  start: number,
): Promise<ProbeObservation> {
  const findings: string[] = [];

  // Read current content
  const content = await readFile(absPath, 'utf8');

  // Check if file contains sensitive patterns that could be mutated
  const sensitivePatterns = [
    { pattern: /MAX_AUDIT_ITERATIONS/g, name: 'audit iteration limit' },
    { pattern: /PHASE_FAIL_MODE/g, name: 'phase failure mode' },
    { pattern: /bypassPermissions/g, name: 'permission bypass flag' },
    { pattern: /AUDIT_PROVIDER/g, name: 'audit provider setting' },
    { pattern: /kill.*switch/gi, name: 'kill switch reference' },
  ];

  for (const { pattern, name } of sensitivePatterns) {
    if (pattern.test(content)) {
      findings.push(`sensitive_config: ${name} found in ${relPath}`);
    }
    pattern.lastIndex = 0;
  }

  // Check writability
  try {
    await access(absPath, constants.W_OK);
    findings.push(`mutable: ${relPath} is writable — config mutation possible`);
  } catch {
    findings.push(`immutable: ${relPath} is read-only`);
  }

  const isVulnerable = findings.some((f) => f.startsWith('mutable:'));
  return {
    kind: 'state_check',
    stdout: findings.join('\n'),
    exitCode: isVulnerable ? 1 : 0,
    durationMs: Date.now() - start,
  };
}
