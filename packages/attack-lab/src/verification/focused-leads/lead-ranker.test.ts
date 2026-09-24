/**
 * Section 11.5 — Lead ranking tests.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  rankLeads,
  computeRankingFactors,
  computeCompositeScore,
  DEFAULT_RANKING_CONFIG,
  type LeadRankingConfig,
} from './lead-ranker.js';
import type { ChainHypothesis, WeakSignal } from '../../autonomous/contracts.js';

function makeSignal(overrides: Partial<WeakSignal> & { id: string }): WeakSignal {
  return {
    discoveredAt: '2026-01-01T00:00:00Z',
    iteration: 1,
    description: 'test signal',
    surface: '/api/test',
    confidence: 0.8,
    novelty: 0.6,
    relatedAssets: [],
    potentialCapabilities: [],
    suggestedFollowUps: [],
    status: 'active',
    correlatedWith: [],
    unresolvedCorrelations: [],
    ...overrides,
  };
}

function makeHypothesis(overrides: Partial<ChainHypothesis> & { id: string }): ChainHypothesis {
  return {
    synthesizedAt: '2026-01-01T00:00:00Z',
    iteration: 1,
    description: 'test hypothesis',
    severity: 'high',
    signalIds: ['ws-1'],
    prerequisites: [],
    status: 'proposed',
    attempts: [],
    ...overrides,
  };
}

test('rankLeads returns empty for empty input', () => {
  const result = rankLeads([], []);
  assert.equal(result.length, 0);
});

test('rankLeads filters out confirmed/refuted/dormant hypotheses', () => {
  const signals = [makeSignal({ id: 'ws-1' })];
  const hypotheses = [
    makeHypothesis({ id: 'h-1', status: 'confirmed' }),
    makeHypothesis({ id: 'h-2', status: 'refuted' }),
    makeHypothesis({ id: 'h-3', status: 'dormant' }),
  ];
  const result = rankLeads(hypotheses, signals);
  assert.equal(result.length, 0);
});

test('rankLeads includes proposed and testing hypotheses', () => {
  const signals = [makeSignal({ id: 'ws-1', confidence: 0.9, novelty: 0.8 })];
  const hypotheses = [
    makeHypothesis({ id: 'h-1', status: 'proposed', severity: 'critical' }),
    makeHypothesis({ id: 'h-2', status: 'testing', severity: 'high' }),
  ];
  const result = rankLeads(hypotheses, signals);
  assert.ok(result.length > 0);
  assert.ok(result.every((r) => r.rank > 0));
});

test('rankLeads includes needs_more_data hypotheses', () => {
  const signals = [makeSignal({ id: 'ws-1', confidence: 0.9 })];
  const hypotheses = [
    makeHypothesis({ id: 'h-1', status: 'needs_more_data', severity: 'high' }),
  ];
  const result = rankLeads(hypotheses, signals);
  assert.ok(result.length > 0);
});

test('critical severity ranks higher than low severity', () => {
  const signals = [makeSignal({ id: 'ws-1', confidence: 0.7, novelty: 0.5 })];
  const hypotheses = [
    makeHypothesis({ id: 'h-low', severity: 'low', status: 'proposed' }),
    makeHypothesis({ id: 'h-critical', severity: 'critical', status: 'proposed' }),
  ];
  const result = rankLeads(hypotheses, signals);
  assert.ok(result.length >= 2);
  assert.equal(result[0]!.hypothesis.id, 'h-critical');
});

test('boundary crossing boosts ranking', () => {
  const signals = [makeSignal({ id: 'ws-1', confidence: 0.5, novelty: 0.5 })];
  const base = { status: 'proposed' as const, severity: 'medium' as const, signalIds: ['ws-1'] };
  const hypotheses = [
    makeHypothesis({ id: 'h-no-boundary', ...base }),
    makeHypothesis({
      id: 'h-boundary',
      ...base,
      boundaryCrossing: { from: 'user', to: 'admin', mechanism: 'jwt' },
    }),
  ];
  const result = rankLeads(hypotheses, signals);
  assert.equal(result[0]!.hypothesis.id, 'h-boundary');
});

test('maxLeads config caps results', () => {
  const signals = [makeSignal({ id: 'ws-1', confidence: 0.9, novelty: 0.9 })];
  const hypotheses = Array.from({ length: 10 }, (_, i) =>
    makeHypothesis({ id: `h-${i}`, status: 'proposed', severity: 'critical' }),
  );
  const config: LeadRankingConfig = { ...DEFAULT_RANKING_CONFIG, maxLeads: 3 };
  const result = rankLeads(hypotheses, signals, config);
  assert.equal(result.length, 3);
});

test('minScore config filters low-scoring leads', () => {
  const signals = [makeSignal({ id: 'ws-1', confidence: 0.1, novelty: 0.1 })];
  const hypotheses = [
    makeHypothesis({ id: 'h-1', status: 'proposed', severity: 'low' }),
  ];
  const config: LeadRankingConfig = { ...DEFAULT_RANKING_CONFIG, minScore: 0.99 };
  const result = rankLeads(hypotheses, signals, config);
  assert.equal(result.length, 0);
});

test('computeRankingFactors returns bounded values', () => {
  const signals = new Map([['ws-1', makeSignal({ id: 'ws-1' })]]);
  const h = makeHypothesis({ id: 'h-1' });
  const factors = computeRankingFactors(h, signals);
  assert.ok(factors.severity >= 0 && factors.severity <= 1);
  assert.ok(factors.confidence >= 0 && factors.confidence <= 1);
  assert.ok(factors.confirmability >= 0 && factors.confirmability <= 1);
  assert.ok(factors.novelty >= 0 && factors.novelty <= 1);
  assert.ok(factors.boundaryCrossingPotential >= 0 && factors.boundaryCrossingPotential <= 1);
});

test('computeCompositeScore produces weighted sum', () => {
  const factors = {
    severity: 1.0,
    confidence: 1.0,
    confirmability: 1.0,
    novelty: 1.0,
    boundaryCrossingPotential: 1.0,
  };
  const weights = DEFAULT_RANKING_CONFIG.weights;
  const score = computeCompositeScore(factors, weights);
  const expectedSum = weights.severity + weights.confidence + weights.confirmability + weights.novelty + weights.boundaryCrossing;
  assert.ok(Math.abs(score - expectedSum) < 0.001);
});

test('ranks are assigned sequentially from 1', () => {
  const signals = [makeSignal({ id: 'ws-1', confidence: 0.9, novelty: 0.9 })];
  const hypotheses = [
    makeHypothesis({ id: 'h-1', status: 'proposed', severity: 'critical' }),
    makeHypothesis({ id: 'h-2', status: 'proposed', severity: 'high' }),
    makeHypothesis({ id: 'h-3', status: 'proposed', severity: 'medium' }),
  ];
  const result = rankLeads(hypotheses, signals);
  for (let i = 0; i < result.length; i++) {
    assert.equal(result[i]!.rank, i + 1);
  }
});

test('probe family is classified from hypothesis description', () => {
  const signals = [makeSignal({ id: 'ws-1', confidence: 0.9 })];
  const hypotheses = [
    makeHypothesis({
      id: 'h-1',
      status: 'proposed',
      severity: 'high',
      description: 'IDOR via cross-tenant access to user resources',
    }),
  ];
  const result = rankLeads(hypotheses, signals);
  assert.ok(result.length > 0);
  assert.equal(result[0]!.probeFamily, 'identity_differential');
});
