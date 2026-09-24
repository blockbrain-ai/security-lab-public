import test from 'node:test';
import assert from 'node:assert/strict';
import { createEmptyMemory } from './contracts.js';
import { synthesizeHypotheses } from './chain-synthesizer.js';

test('synthesizeHypotheses promotes strong dormant boundary-crossing chains', () => {
  const memory = createEmptyMemory('campaign-chain');
  memory.iteration = 5;
  memory.signals.push(
    {
      id: 'ws-1',
      discoveredAt: new Date().toISOString(),
      iteration: 1,
      description: 'Prompt-smuggle clue',
      surface: 'prompt',
      confidence: 0.8,
      novelty: 0.8,
      relatedAssets: ['invoice.description'],
      potentialCapabilities: ['prompt injection'],
      suggestedFollowUps: ['inject invoice.description'],
      status: 'reopened',
      correlatedWith: [],
      unresolvedCorrelations: [],
    },
    {
      id: 'ws-2',
      discoveredAt: new Date().toISOString(),
      iteration: 4,
      description: 'Public proof route lacks auth',
      surface: 'http',
      confidence: 0.85,
      novelty: 0.7,
      relatedAssets: ['/public/proof'],
      potentialCapabilities: ['public proof leak'],
      suggestedFollowUps: ['request /public/proof as outsider'],
      status: 'active',
      correlatedWith: [],
      unresolvedCorrelations: [],
    },
  );

  const created = synthesizeHypotheses(memory, [
    {
      signalIds: ['ws-1', 'ws-2'],
      path: ['signal:ws-1', 'capability:prompt injection', 'trust_boundary:public'],
      totalWeight: 1.8,
      crossesBoundary: true,
      involvesDormant: true,
    },
  ]);

  assert.equal(created.length, 1);
  assert.equal(created[0]?.severity, 'critical');
  assert.match(created[0]?.description ?? '', /crossing a trust boundary/i);
  assert.match(created[0]?.description ?? '', /reactivated dormant signals/i);
});

test('synthesizeHypotheses deduplicates existing signal combinations', () => {
  const memory = createEmptyMemory('campaign-chain-dedupe');
  memory.iteration = 3;
  memory.signals.push(
    {
      id: 'ws-1',
      discoveredAt: new Date().toISOString(),
      iteration: 1,
      description: 'First signal',
      surface: 'code',
      confidence: 0.6,
      novelty: 0.7,
      relatedAssets: ['src/app.ts'],
      potentialCapabilities: ['bypass'],
      suggestedFollowUps: ['read src/app.ts'],
      status: 'active',
      correlatedWith: [],
      unresolvedCorrelations: [],
    },
    {
      id: 'ws-2',
      discoveredAt: new Date().toISOString(),
      iteration: 2,
      description: 'Second signal',
      surface: 'code',
      confidence: 0.6,
      novelty: 0.7,
      relatedAssets: ['src/app.ts'],
      potentialCapabilities: ['bypass'],
      suggestedFollowUps: ['trace authz path'],
      status: 'active',
      correlatedWith: [],
      unresolvedCorrelations: [],
    },
  );
  memory.hypotheses.push({
    id: 'existing',
    synthesizedAt: new Date().toISOString(),
    iteration: 2,
    description: 'Existing chain',
    severity: 'medium',
    signalIds: ['ws-1', 'ws-2'],
    prerequisites: [],
    status: 'proposed',
    attempts: [],
  });

  const created = synthesizeHypotheses(memory, [
    {
      signalIds: ['ws-2', 'ws-1'],
      path: ['signal:ws-1', 'signal:ws-2'],
      totalWeight: 1,
      crossesBoundary: false,
      involvesDormant: false,
    },
  ]);

  assert.equal(created.length, 0);
  assert.equal(memory.hypotheses.length, 1);
});
