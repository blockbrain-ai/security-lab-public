/**
 * Evidence probe — checks for evidence baseline drift, label tampering,
 * and audit record integrity. Tests the evidence-poisoning attack vector.
 */

import { readFile, access, constants } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import type { ProbeObservation } from '../../../evidence-plane/src/contracts.js';

export interface EvidenceProbeConfig {
  kind: 'evidence_check';
  action: 'manifest_verify' | 'label_writability' | 'baseline_drift';
  /** Path to evidence directory or file. */
  filePath: string;
  /** Expected hashes for verification. */
  expectedHashes?: Record<string, string>;
  timeoutMs: number;
}

export async function runEvidenceProbe(
  probe: EvidenceProbeConfig,
  targetRoot: string,
): Promise<ProbeObservation> {
  const start = Date.now();
  const absPath = resolve(targetRoot, probe.filePath);

  try {
    switch (probe.action) {
      case 'manifest_verify': {
        const content = await readFile(absPath, 'utf8');
        const manifest = JSON.parse(content);
        const findings: string[] = [];

        for (const [file, expectedHash] of Object.entries(manifest.files ?? {})) {
          const filePath = resolve(absPath, '..', file);
          try {
            const fileContent = await readFile(filePath, 'utf8');
            const actualHash = createHash('sha256').update(fileContent).digest('hex');
            if (actualHash !== expectedHash) {
              findings.push(`TAMPERED: ${file} hash mismatch (expected ${String(expectedHash).slice(0, 12)}, got ${actualHash.slice(0, 12)})`);
            }
          } catch {
            findings.push(`MISSING: ${file} referenced in manifest but not found`);
          }
        }

        return {
          kind: 'evidence_check',
          stdout: findings.length > 0 ? findings.join('\n') : 'manifest integrity verified',
          exitCode: findings.length > 0 ? 1 : 0,
          durationMs: Date.now() - start,
        };
      }

      case 'label_writability': {
        const findings: string[] = [];
        try {
          await access(absPath, constants.W_OK);
          findings.push(`WRITABLE: ${probe.filePath} — truth labels can be modified by the runner process`);
        } catch {
          findings.push(`PROTECTED: ${probe.filePath} is read-only`);
        }

        return {
          kind: 'evidence_check',
          stdout: findings.join('\n'),
          exitCode: findings.some((f) => f.startsWith('WRITABLE:')) ? 1 : 0,
          durationMs: Date.now() - start,
        };
      }

      case 'baseline_drift': {
        const content = await readFile(absPath, 'utf8');
        const actualHash = createHash('sha256').update(content).digest('hex');
        const findings: string[] = [`current_hash: ${actualHash}`];

        if (probe.expectedHashes) {
          const expected = probe.expectedHashes[probe.filePath];
          if (expected && expected !== actualHash) {
            findings.push(`DRIFT: baseline changed (expected ${expected.slice(0, 12)}, got ${actualHash.slice(0, 12)})`);
          } else if (expected) {
            findings.push('baseline: matches expected');
          }
        }

        return {
          kind: 'evidence_check',
          stdout: findings.join('\n'),
          exitCode: findings.some((f) => f.startsWith('DRIFT:')) ? 1 : 0,
          durationMs: Date.now() - start,
        };
      }

      default:
        return { kind: 'evidence_check', stderr: `Unknown action: ${probe.action}`, durationMs: Date.now() - start };
    }
  } catch (error: unknown) {
    return {
      kind: 'evidence_check',
      stderr: error instanceof Error ? error.message : String(error),
      durationMs: Date.now() - start,
    };
  }
}
