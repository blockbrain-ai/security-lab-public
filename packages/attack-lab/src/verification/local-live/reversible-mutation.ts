/**
 * Reversible mutation journal — tracks any state changes made during
 * live verification so they can be rolled back at end of campaign.
 */

import type { RollbackSpec, RollbackCommand } from './contracts.js';

export interface MutationEntry {
  id: string;
  at: string;
  description: string;
  /** What needs to happen to undo this. */
  rollback: RollbackCommand;
  rolledBack: boolean;
  rollbackError?: string;
}

export class MutationJournal {
  private readonly entries: MutationEntry[] = [];

  record(description: string, rollback: RollbackCommand): MutationEntry {
    const entry: MutationEntry = {
      id: `mut-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      at: new Date().toISOString(),
      description,
      rollback,
      rolledBack: false,
    };
    this.entries.push(entry);
    return entry;
  }

  getPendingRollbacks(): MutationEntry[] {
    return this.entries.filter((e) => !e.rolledBack);
  }

  markRolledBack(id: string, error?: string): void {
    const entry = this.entries.find((e) => e.id === id);
    if (entry) {
      entry.rolledBack = true;
      if (error) entry.rollbackError = error;
    }
  }

  getAll(): MutationEntry[] {
    return [...this.entries];
  }

  /**
   * Execute all pending rollbacks via HTTP commands.
   */
  async rollbackAll(
    baseUrl: string,
    fetchFn: typeof fetch = fetch,
  ): Promise<{ succeeded: number; failed: number }> {
    let succeeded = 0;
    let failed = 0;

    for (const entry of this.getPendingRollbacks()) {
      try {
        const url = new URL(entry.rollback.path, baseUrl).toString();
        const response = await fetchFn(url, {
          method: entry.rollback.method,
          headers: entry.rollback.headers,
          body: entry.rollback.body,
          signal: AbortSignal.timeout(10_000),
        });

        if (response.ok) {
          this.markRolledBack(entry.id);
          succeeded++;
        } else {
          this.markRolledBack(entry.id, `rollback returned ${response.status}`);
          failed++;
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        this.markRolledBack(entry.id, message);
        failed++;
      }
    }

    return { succeeded, failed };
  }
}

export function buildRollback(spec: RollbackSpec | undefined, createdId: string): RollbackCommand | null {
  if (!spec || !spec.commands || spec.commands.length === 0) return null;

  // Substitute {created_id} placeholder
  const cmd = spec.commands[0]!;
  return {
    method: cmd.method,
    path: cmd.path.replace(/\{created_id\}/g, createdId),
    headers: cmd.headers,
    body: cmd.body?.replace(/\{created_id\}/g, createdId),
  };
}
