import test from 'node:test';
import assert from 'node:assert/strict';
import { findChainCandidates, findChainCandidatesNearSignals, ingestSignal } from './attack-graph.js';
import type { AttackGraph, WeakSignal } from './contracts.js';

function makeSignal(overrides: Partial<WeakSignal> & Pick<WeakSignal, 'id' | 'description'>): WeakSignal {
  return {
    id: overrides.id,
    discoveredAt: overrides.discoveredAt ?? new Date().toISOString(),
    iteration: overrides.iteration ?? 0,
    description: overrides.description,
    surface: overrides.surface ?? 'code',
    confidence: overrides.confidence ?? 0.8,
    novelty: overrides.novelty ?? 0.8,
    relatedAssets: overrides.relatedAssets ?? [],
    potentialCapabilities: overrides.potentialCapabilities ?? [],
    suggestedFollowUps: overrides.suggestedFollowUps ?? [],
    status: overrides.status ?? 'active',
    correlatedWith: overrides.correlatedWith ?? [],
    unresolvedCorrelations: overrides.unresolvedCorrelations ?? [],
    dormantSince: overrides.dormantSince,
    reactivationReason: overrides.reactivationReason,
    sourceProbeId: overrides.sourceProbeId,
  };
}

test('findChainCandidates can chain signals through shared assets and inferred trust boundaries', () => {
  const graph: AttackGraph = { nodes: [], edges: [] };

  ingestSignal(graph, makeSignal({
    id: 'ws-1',
    description: 'Public route without local auth markers',
    surface: 'http',
    relatedAssets: ['src/routes/admin.ts'],
    potentialCapabilities: ['public proof leak'],
  }));
  ingestSignal(graph, makeSignal({
    id: 'ws-2',
    description: 'Raw SQL in compliance export service',
    surface: 'code',
    relatedAssets: ['src/routes/admin.ts'],
    potentialCapabilities: ['database read', 'cross-tenant pii'],
  }));

  const candidates = findChainCandidates(graph, 5);
  const sharedAssetChain = candidates.find((candidate) =>
    candidate.signalIds.includes('ws-1') && candidate.signalIds.includes('ws-2'),
  );

  assert.ok(sharedAssetChain);
  assert.equal(sharedAssetChain?.crossesBoundary, true);
});

test('findChainCandidatesNearSignals stays focused on the trigger neighborhood', () => {
  const graph: AttackGraph = { nodes: [], edges: [] };

  ingestSignal(graph, makeSignal({
    id: 'ws-trigger-1',
    description: 'Runtime signal on /api/reports reveals stack trace',
    surface: 'runtime:http',
    relatedAssets: ['src/routes/reports.ts', '/api/reports'],
    potentialCapabilities: ['information_disclosure'],
  }));
  ingestSignal(graph, makeSignal({
    id: 'ws-trigger-2',
    description: 'Follow-up route read shows report handler reuses tenant context',
    surface: 'code',
    relatedAssets: ['src/routes/reports.ts', 'src/services/report-service.ts'],
    potentialCapabilities: ['tenant_bypass'],
  }));

  for (let i = 0; i < 40; i += 1) {
    ingestSignal(graph, makeSignal({
      id: `ws-noise-${i}`,
      description: `Unrelated noise signal ${i}`,
      surface: 'code',
      relatedAssets: [`src/noise/${i}.ts`],
      potentialCapabilities: [`noise_cap_${i}`],
    }));
  }

  const focused = findChainCandidatesNearSignals(graph, ['ws-trigger-1'], {
    neighborhoodDepth: 3,
    nodeBudget: 16,
    maxDepth: 4,
  });

  assert.ok(focused.length > 0);
  assert.ok(focused.every((candidate) => candidate.signalIds.includes('ws-trigger-1')));
  assert.ok(focused.every((candidate) => !candidate.signalIds.some((signalId) => signalId.startsWith('ws-noise-'))));
});
