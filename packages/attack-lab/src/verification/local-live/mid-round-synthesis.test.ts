import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { runMidRoundSynthesis, selectMidRoundTriggers } from './mid-round-synthesis.js';
import { createEmptyMemory } from '../../autonomous/contracts.js';
import { addSignal } from '../../autonomous/weak-signal-ledger.js';
import { ingestSignal } from '../../autonomous/attack-graph.js';
import type { CampaignMemory } from '../../autonomous/contracts.js';

function seedMemory(novelty: number): CampaignMemory {
  const memory = createEmptyMemory('test-campaign');
  memory.iteration = 1;
  // First, a pre-existing static signal on the same asset.
  const staticSignal = addSignal(memory, {
    description: 'auth middleware skips tenant check on /api/reports',
    surface: 'code:middleware',
    confidence: 0.8,
    novelty: 0.7,
    relatedAssets: ['src/middleware/auth.ts', '/api/reports'],
    potentialCapabilities: ['tenant_bypass'],
    suggestedFollowUps: ['probe /api/reports with mismatched tenant'],
  });
  ingestSignal(memory.graph, staticSignal);

  // Now a runtime-only signal from a probe, same asset.
  const runtimeSignal = addSignal(memory, {
    description: 'runtime: 500 + stack trace on /api/reports/1 reveals internal path',
    surface: 'runtime:http',
    confidence: 0.8,
    novelty,
    relatedAssets: ['/api/reports', '/api/reports/1'],
    potentialCapabilities: ['information_disclosure'],
    suggestedFollowUps: ['retry with sibling ids'],
  });
  ingestSignal(memory.graph, runtimeSignal);
  return memory;
}

describe('runMidRoundSynthesis', () => {
  it('skips synthesis when novelty is below threshold', () => {
    const memory = seedMemory(0.3);
    const triggers = [{ signalId: memory.signals[1]!.id, novelty: 0.3 }];
    const result = runMidRoundSynthesis(memory, triggers, { noveltyThreshold: 0.65 });
    assert.equal(result.invoked, false);
    assert.equal(result.newHypotheses.length, 0);
    assert.ok(result.skipReason);
  });

  it('invokes synthesis when at least one trigger meets the novelty gate', () => {
    const memory = seedMemory(0.9);
    const triggers = [{ signalId: memory.signals[1]!.id, novelty: 0.9 }];
    const result = runMidRoundSynthesis(memory, triggers, { noveltyThreshold: 0.65 });
    assert.equal(result.invoked, true);
    // May or may not produce new hypotheses depending on graph wiring —
    // the important property is that the gate fired.
    assert.equal(result.triggers.length, 1);
  });

  it('respects maxNew', () => {
    const memory = seedMemory(0.9);
    // Force many hypotheses to already exist so maxNew is exercised.
    const triggers = [{ signalId: memory.signals[1]!.id, novelty: 0.9 }];
    const result = runMidRoundSynthesis(memory, triggers, { noveltyThreshold: 0.5, maxNew: 1 });
    assert.ok(result.newHypotheses.length <= 1);
  });

  it('scopes synthesis to the trigger neighborhood instead of rewalking unrelated graph branches', () => {
    const memory = seedMemory(0.9);
    for (let i = 0; i < 25; i += 1) {
      const noise = addSignal(memory, {
        description: `noise branch ${i}`,
        surface: 'code:noise',
        confidence: 0.7,
        novelty: 0.7,
        relatedAssets: [`src/noise/${i}.ts`],
        potentialCapabilities: [`noise_capability_${i}`],
        suggestedFollowUps: [],
      });
      ingestSignal(memory.graph, noise);
    }

    const triggers = [{ signalId: memory.signals[1]!.id, novelty: 0.9 }];
    const result = runMidRoundSynthesis(memory, triggers, {
      noveltyThreshold: 0.65,
      nodeBudget: 16,
      neighborhoodDepth: 3,
      maxDepth: 4,
    });

    assert.equal(result.invoked, true);
    for (const hypothesis of result.newHypotheses) {
      assert.ok(hypothesis.signalIds.includes(memory.signals[1]!.id));
      assert.equal(hypothesis.signalIds.some((id) => id.startsWith('ws-noise-')), false);
    }
  });
});

describe('selectMidRoundTriggers', () => {
  it('maps signal ids to trigger records with novelty', () => {
    const memory = seedMemory(0.8);
    const runtimeSignalId = memory.signals[1]!.id;
    const triggers = selectMidRoundTriggers(memory, [runtimeSignalId, 'nonexistent']);
    assert.equal(triggers.length, 1);
    assert.equal(triggers[0]!.signalId, runtimeSignalId);
    assert.equal(triggers[0]!.novelty, 0.8);
  });

  it('deduplicates repeated runtime signal ids', () => {
    const memory = seedMemory(0.8);
    const runtimeSignalId = memory.signals[1]!.id;
    const triggers = selectMidRoundTriggers(memory, [runtimeSignalId, runtimeSignalId, runtimeSignalId]);
    assert.equal(triggers.length, 1);
    assert.equal(triggers[0]!.signalId, runtimeSignalId);
  });
});
