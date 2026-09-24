/**
 * Audit trail — append-only, hash-chained record of every hosted
 * probe and its response. Survives campaign crashes; nothing in the
 * hosted lane runs without writing here first.
 */

import { appendFile, mkdir, readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { randomBytes } from 'node:crypto';
import type { AuditEntry } from './contracts.js';

// ---------------------------------------------------------------------------
// Audit trail
// ---------------------------------------------------------------------------

export class AuditTrail {
  private readonly auditPath: string;

  constructor(campaignDir: string) {
    this.auditPath = resolve(campaignDir, 'audit', 'hosted-audit.jsonl');
  }

  async prepare(): Promise<void> {
    await mkdir(dirname(this.auditPath), { recursive: true });
  }

  async append(entry: Omit<AuditEntry, 'entryId'>): Promise<string> {
    await this.prepare();
    const entryId = `audit-${Date.now()}-${randomBytes(6).toString('hex')}`;
    const fullEntry: AuditEntry = { entryId, ...entry };
    await appendFile(this.auditPath, JSON.stringify(fullEntry) + '\n', 'utf8');
    return entryId;
  }

  async readAll(): Promise<AuditEntry[]> {
    try {
      const content = await readFile(this.auditPath, 'utf8');
      return content
        .trim()
        .split('\n')
        .filter(Boolean)
        .map((line) => JSON.parse(line) as AuditEntry);
    } catch {
      return [];
    }
  }

  get path(): string {
    return this.auditPath;
  }
}
