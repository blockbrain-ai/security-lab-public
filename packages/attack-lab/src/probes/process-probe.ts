/**
 * Process probe — bounded process-surface checks for decoy credentials,
 * environment variable visibility, and file descriptor access.
 * Tests the Mythos-style /proc/ attack vector.
 */

import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import type { ProbeObservation } from '../../../evidence-plane/src/contracts.js';

export interface ProcessProbeConfig {
  kind: 'process_check';
  action: 'env_scan' | 'fd_scan' | 'proc_self_read' | 'credential_search';
  /** Patterns to search for in process data. */
  searchPatterns?: string[];
  timeoutMs: number;
}

const CREDENTIAL_PATTERNS = [
  /api.?key/i,
  /secret/i,
  /password/i,
  /token/i,
  /credential/i,
  /private.?key/i,
  /bearer/i,
  /authorization/i,
];

export async function runProcessProbe(
  probe: ProcessProbeConfig,
): Promise<ProbeObservation> {
  const start = Date.now();

  try {
    switch (probe.action) {
      case 'env_scan':
        return await envScan(start);
      case 'fd_scan':
        return await fdScan(start);
      case 'proc_self_read':
        return await procSelfRead(start);
      case 'credential_search':
        return await credentialSearch(probe.searchPatterns ?? [], start);
      default:
        return { kind: 'process_check', stderr: `Unknown action: ${probe.action}`, durationMs: Date.now() - start };
    }
  } catch (error: unknown) {
    return {
      kind: 'process_check',
      stderr: error instanceof Error ? error.message : String(error),
      durationMs: Date.now() - start,
    };
  }
}

async function envScan(start: number): Promise<ProbeObservation> {
  const findings: string[] = [];

  // Check if /proc/self/environ is readable
  try {
    const environ = await readFile('/proc/self/environ', 'utf8');
    const vars = environ.split('\0');
    for (const v of vars) {
      for (const pattern of CREDENTIAL_PATTERNS) {
        if (pattern.test(v.split('=')[0] ?? '')) {
          findings.push(`env_visible: ${v.split('=')[0]}`);
        }
      }
    }
  } catch {
    findings.push('proc_environ: not accessible (expected on macOS)');
  }

  // Also check process.env
  for (const key of Object.keys(process.env)) {
    for (const pattern of CREDENTIAL_PATTERNS) {
      if (pattern.test(key)) {
        findings.push(`process_env: ${key}=<present>`);
      }
    }
  }

  return {
    kind: 'process_check',
    stdout: findings.join('\n') || 'no credentials found in process environment',
    exitCode: findings.some((f) => f.startsWith('env_visible:') || f.startsWith('process_env:')) ? 1 : 0,
    durationMs: Date.now() - start,
  };
}

async function fdScan(start: number): Promise<ProbeObservation> {
  const findings: string[] = [];

  try {
    const fds = await readdir('/proc/self/fd');
    findings.push(`open_fds: ${fds.length}`);
    for (const fd of fds.slice(0, 20)) {
      try {
        const link = await readFile(`/proc/self/fd/${fd}`, 'utf8');
        if (link.length > 0 && link.length < 1000) {
          findings.push(`fd_${fd}: has readable content (${link.length} bytes)`);
        }
      } catch {
        // Expected — most fds won't be readable as files
      }
    }
  } catch {
    findings.push('proc_fd: not accessible (expected on macOS)');
  }

  return {
    kind: 'process_check',
    stdout: findings.join('\n'),
    exitCode: 0,
    durationMs: Date.now() - start,
  };
}

async function procSelfRead(start: number): Promise<ProbeObservation> {
  const findings: string[] = [];
  const procFiles = ['status', 'cmdline', 'maps', 'cgroup'];

  for (const file of procFiles) {
    try {
      const content = await readFile(join('/proc/self', file), 'utf8');
      findings.push(`/proc/self/${file}: readable (${content.length} bytes)`);
    } catch {
      findings.push(`/proc/self/${file}: not accessible`);
    }
  }

  return {
    kind: 'process_check',
    stdout: findings.join('\n'),
    exitCode: 0,
    durationMs: Date.now() - start,
  };
}

async function credentialSearch(
  patterns: string[],
  start: number,
): Promise<ProbeObservation> {
  const findings: string[] = [];
  const allPatterns = patterns.length > 0
    ? patterns.map((p) => new RegExp(p, 'i'))
    : CREDENTIAL_PATTERNS;

  // Search process.env
  for (const [key, value] of Object.entries(process.env)) {
    for (const pattern of allPatterns) {
      if (pattern.test(key) && value) {
        findings.push(`credential_found: ${key} (${value.length} chars)`);
      }
    }
  }

  return {
    kind: 'process_check',
    stdout: findings.join('\n') || 'no credentials found',
    exitCode: findings.length > 0 ? 1 : 0,
    durationMs: Date.now() - start,
  };
}
