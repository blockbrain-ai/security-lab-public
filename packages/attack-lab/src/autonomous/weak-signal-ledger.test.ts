import test from 'node:test';
import assert from 'node:assert/strict';
import { createEmptyMemory } from './contracts.js';
import {
  addCorrelation,
  addSignal,
  getCandidatesForResurfacing,
  getSignalsWithUnresolvedCorrelations,
  markDormant,
  markResurfacingDone,
  reactivateSignal,
  shouldResurface,
} from './weak-signal-ledger.js';

test('weak-signal ledger deduplicates repeated signals and boosts confidence', () => {
  const memory = createEmptyMemory('campaign-dedupe');
  memory.iteration = 2;

  const first = addSignal(memory, {
    description: 'Unexpected authz gap on private endpoint',
    surface: 'http',
    confidence: 0.4,
    novelty: 0.8,
    relatedAssets: ['/api/private'],
    potentialCapabilities: ['authorization bypass'],
    suggestedFollowUps: ['retry with alternate headers'],
  });

  const duplicate = addSignal(memory, {
    description: 'Unexpected authz gap on private endpoint',
    surface: 'http',
    confidence: 0.4,
    novelty: 0.7,
    relatedAssets: ['/api/private'],
    potentialCapabilities: ['authorization bypass'],
    suggestedFollowUps: ['retry with alternate headers'],
  });

  assert.equal(memory.signals.length, 1);
  assert.equal(duplicate.id, first.id);
  assert.equal(first.confidence, 0.5);
});

test('weak-signal ledger resurfaces dormant signals when new context changes their meaning', () => {
  const memory = createEmptyMemory('campaign-resurface');
  memory.iteration = 0;

  const dormant = addSignal(memory, {
    description: 'Low-confidence file writeability hint',
    surface: 'state',
    confidence: 0.3,
    novelty: 0.9,
    relatedAssets: ['state.json'],
    potentialCapabilities: ['state tampering'],
    suggestedFollowUps: ['check write permissions on state.json'],
  });
  markDormant(memory, dormant.id);

  memory.iteration = 5;
  const active = addSignal(memory, {
    description: 'New audit bypass hint referencing the same state file',
    surface: 'state',
    confidence: 0.75,
    novelty: 0.8,
    relatedAssets: ['state.json'],
    potentialCapabilities: ['audit bypass'],
    suggestedFollowUps: ['compare hash before and after mutation attempt'],
  });

  addCorrelation(memory, dormant.id, active.id, false);

  assert.equal(shouldResurface(memory), true);

  const candidates = getCandidatesForResurfacing(memory);
  assert.deepEqual(candidates.map((signal) => signal.id), [dormant.id]);

  const unresolved = getSignalsWithUnresolvedCorrelations(memory);
  assert.equal(unresolved.length, 2);

  reactivateSignal(memory, dormant.id, 'new state mutation context');
  assert.equal(memory.dormantSignalIds.length, 0);
  assert.equal(memory.signals.find((signal) => signal.id === dormant.id)?.status, 'reopened');

  markResurfacingDone(memory);
  assert.equal(shouldResurface(memory), false);
});
