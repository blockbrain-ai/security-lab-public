import test from 'node:test';
import assert from 'node:assert/strict';
import { HashChain } from './hash-chain.js';

test('HashChain verifies valid sequences', () => {
  const chain = new HashChain();
  chain.append('started', { step: 1 });
  chain.append('observed', { step: 2 });

  const verification = chain.verify();
  assert.equal(verification.valid, true);
  assert.equal(verification.eventCount, 2);
  assert.ok(verification.headHash.length > 0);
});

test('HashChain detects tampered payloads and broken previous-hash links', () => {
  const chain = new HashChain();
  chain.append('started', { step: 1 });
  chain.append('observed', { step: 2 });

  const tamperedEvents = chain.getEvents();
  tamperedEvents[1] = {
    ...tamperedEvents[1]!,
    previousHash: 'bad-link',
    payload: { step: 999 },
  };

  const verification = HashChain.fromEvents(tamperedEvents).verify();
  assert.equal(verification.valid, false);
  assert.match(verification.errors.join('\n'), /previousHash mismatch/);
  assert.match(verification.errors.join('\n'), /hash mismatch/);
});

test('HashChain detects truncation and reordering through the recorded index', () => {
  const chain = new HashChain();
  chain.append('started', { step: 1 });
  chain.append('observed', { step: 2 });
  chain.append('finished', { step: 3 });

  // Removing a middle record leaves the surviving linkage plausible.
  const truncated = chain.getEvents().filter((event) => event.index !== 1);
  const truncationVerification = HashChain.fromEvents(truncated).verify();
  assert.equal(truncationVerification.valid, false);
  assert.match(truncationVerification.errors.join('\n'), /Event 1: index mismatch \(expected 1, got 2\)/);

  // Reordering records keeps every hash intact but changes positions.
  const events = chain.getEvents();
  const reordered = [events[0]!, events[2]!, events[1]!];
  const reorderVerification = HashChain.fromEvents(reordered).verify();
  assert.equal(reorderVerification.valid, false);
  assert.match(reorderVerification.errors.join('\n'), /index mismatch/);
});

test('HashChain next/commit lets callers persist before mutating the chain', () => {
  const chain = new HashChain();
  chain.append('started', { step: 1 });

  const pending = chain.next('observed', { step: 2 });
  // Not committed yet: the chain still reports a single event.
  assert.equal(chain.getEventCount(), 1);
  assert.equal(chain.verify().eventCount, 1);
  assert.equal(pending.index, 1);
  assert.equal(pending.previousHash, chain.getHeadHash());

  chain.commit(pending);
  assert.equal(chain.getEventCount(), 2);
  assert.equal(chain.verify().valid, true);
  assert.equal(chain.getHeadHash(), pending.hash);

  // Committing out of order is a programming error, not a silent fork.
  assert.throws(() => chain.commit(pending), /out-of-order commit/);
});

