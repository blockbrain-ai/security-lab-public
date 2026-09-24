/**
 * Rolling event hash chain — each event includes the hash of the
 * previous event, making tampering detectable at event level.
 */

import { createHash } from 'node:crypto';

export interface HashedEvent {
  /** Sequential event index. */
  index: number;
  /** Hash of the previous event (empty string for first event). */
  previousHash: string;
  /** Hash of this event (SHA-256 of index + previousHash + payload). */
  hash: string;
  /** Event timestamp. */
  at: string;
  /** Event stage. */
  stage: string;
  /** Event payload. */
  payload: Record<string, unknown>;
}

export class HashChain {
  private events: HashedEvent[] = [];
  private lastHash: string = '';

  /**
   * Compute the next event in the chain **without** committing it.
   *
   * Callers that must persist the event before it becomes part of the chain
   * (for example `EvidenceStore.appendEvent`, where a failed write must not
   * poison every later event) use this together with {@link commit}.
   */
  next(stage: string, payload: Record<string, unknown>): HashedEvent {
    const index = this.events.length;
    const previousHash = this.lastHash;
    const at = new Date().toISOString();

    const content = JSON.stringify({ index, previousHash, at, stage, payload });
    const hash = createHash('sha256').update(content).digest('hex');

    return { index, previousHash, hash, at, stage, payload };
  }

  /**
   * Commit a previously computed event to the chain. Only call this once the
   * event is durable — the in-memory chain is what later events link against.
   */
  commit(event: HashedEvent): void {
    if (event.index !== this.events.length) {
      throw new Error(
        `HashChain: out-of-order commit (expected index ${this.events.length}, got ${event.index})`,
      );
    }
    this.events.push(event);
    this.lastHash = event.hash;
  }

  append(stage: string, payload: Record<string, unknown>): HashedEvent {
    const event = this.next(stage, payload);
    this.commit(event);
    return event;
  }

  verify(): HashChainVerification {
    const errors: string[] = [];

    for (let i = 0; i < this.events.length; i++) {
      const event = this.events[i]!;

      // Check positional integrity. A removed or reordered record keeps the
      // linkage intact for its neighbours in some truncation shapes, so the
      // recorded index must be checked against its position as well.
      if (event.index !== i) {
        errors.push(`Event ${i}: index mismatch (expected ${i}, got ${String(event.index)})`);
      }

      // Check previous hash linkage
      if (i === 0) {
        if (event.previousHash !== '') {
          errors.push(`Event ${i}: first event should have empty previousHash`);
        }
      } else {
        if (event.previousHash !== this.events[i - 1]!.hash) {
          errors.push(`Event ${i}: previousHash mismatch (expected ${this.events[i - 1]!.hash.slice(0, 12)}, got ${event.previousHash.slice(0, 12)})`);
        }
      }

      // Verify hash computation
      const content = JSON.stringify({
        index: event.index,
        previousHash: event.previousHash,
        at: event.at,
        stage: event.stage,
        payload: event.payload,
      });
      const expectedHash = createHash('sha256').update(content).digest('hex');
      if (event.hash !== expectedHash) {
        errors.push(`Event ${i}: hash mismatch (computed ${expectedHash.slice(0, 12)}, stored ${event.hash.slice(0, 12)})`);
      }
    }

    return {
      valid: errors.length === 0,
      eventCount: this.events.length,
      errors,
      headHash: this.lastHash,
    };
  }

  getEvents(): HashedEvent[] {
    return [...this.events];
  }

  getEventCount(): number {
    return this.events.length;
  }

  getHeadHash(): string {
    return this.lastHash;
  }

  static fromEvents(events: HashedEvent[]): HashChain {
    const chain = new HashChain();
    chain.events = [...events];
    chain.lastHash = events.length > 0 ? events[events.length - 1]!.hash : '';
    return chain;
  }
}

export interface HashChainVerification {
  valid: boolean;
  eventCount: number;
  errors: string[];
  headHash: string;
}
