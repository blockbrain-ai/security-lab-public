/**
 * Audit trail — append-only record of every hosted probe and its response.
 *
 * Each request produces two entries: `request_started` before it leaves the
 * process and `request_completed` afterwards, so a crash mid-request still
 * leaves a record of what was sent. Entries are written with owner-only
 * permissions and pass through redaction, so a credential that reaches this
 * file is a bug rather than a policy.
 */

import { appendFile, chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { randomBytes } from 'node:crypto';
import type { AuditEntry } from './contracts.js';
import { redactBody, redactHeaders, redactSecretString } from '../shared/redaction.js';

/** Owner read/write only: the trail records which credentials were used. */
const AUDIT_FILE_MODE = 0o600;

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
    // Create with restrictive permissions when absent; repair when present.
    await writeFile(this.auditPath, '', { encoding: 'utf8', flag: 'a', mode: AUDIT_FILE_MODE });
    await chmod(this.auditPath, AUDIT_FILE_MODE).catch(() => {
      // Best effort: a filesystem without POSIX modes (or a foreign owner) must
      // not stop the campaign from recording evidence.
    });
  }

  async append(entry: Omit<AuditEntry, 'entryId'>): Promise<string> {
    await this.prepare();
    const entryId = `audit-${Date.now()}-${randomBytes(6).toString('hex')}`;
    const fullEntry: AuditEntry = {
      entryId,
      ...entry,
      // Defence in depth: redact here as well, so a future call site that
      // forgets cannot write a credential to disk.
      request: {
        ...entry.request,
        headers: redactHeaders(entry.request.headers),
        body: entry.request.body === undefined ? undefined : redactBody(entry.request.body, 8_000).body,
      },
      response: {
        ...entry.response,
        headers: redactHeaders(entry.response.headers),
        body: redactBody(entry.response.body, 8_000).body,
      },
      notes: entry.notes === undefined ? undefined : redactSecretString(entry.notes),
    };
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
