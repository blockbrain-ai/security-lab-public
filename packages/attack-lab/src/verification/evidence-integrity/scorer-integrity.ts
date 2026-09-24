/**
 * Scorer integrity check — verifies that the deployed scorer code
 * matches the expected hash. Catches a class of attack where someone
 * modifies the rubric or scorer to make findings disappear.
 */

import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import type { ScorerIntegrityResult } from './contracts.js';

// ---------------------------------------------------------------------------
// Scorer registry
// ---------------------------------------------------------------------------

export interface ScorerEntry {
  scorerId: string;
  filePath: string;
  expectedHash: string;
}

// ---------------------------------------------------------------------------
// Scorer integrity check
// ---------------------------------------------------------------------------

export class ScorerIntegrity {
  constructor(private readonly registry: ScorerEntry[]) {}

  async check(): Promise<ScorerIntegrityResult[]> {
    const results: ScorerIntegrityResult[] = [];
    for (const entry of this.registry) {
      try {
        const content = await readFile(entry.filePath, 'utf8');
        const observedHash = createHash('sha256').update(content).digest('hex');
        const intact = observedHash === entry.expectedHash;
        results.push({
          scorerId: entry.scorerId,
          expectedHash: entry.expectedHash,
          observedHash,
          intact,
          notes: intact ? 'hash match' : 'hash mismatch — scorer may have been modified',
        });
      } catch (error) {
        results.push({
          scorerId: entry.scorerId,
          expectedHash: entry.expectedHash,
          observedHash: '',
          intact: false,
          notes: `failed to read scorer: ${error instanceof Error ? error.message : String(error)}`,
        });
      }
    }
    return results;
  }
}
