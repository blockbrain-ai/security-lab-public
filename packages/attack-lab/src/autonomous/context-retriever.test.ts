import test from 'node:test';
import assert from 'node:assert/strict';
import { createEmptyMemory } from './contracts.js';
import { ingestSignal } from './attack-graph.js';
import { plannerContextPack, judgeContextPack } from './context-retriever.js';

test('plannerContextPack includes retrieved frontier evidence and unresolved correlations', () => {
  const memory = createEmptyMemory('campaign-ctx');
  memory.signals.push(
    {
      id: 'ws-1',
      discoveredAt: new Date().toISOString(),
      iteration: 0,
      description: 'Auth middleware factory exists but may be opt-in',
      surface: 'code',
      confidence: 0.7,
      novelty: 0.6,
      relatedAssets: ['src/api/middleware/jwt-auth.ts'],
      potentialCapabilities: ['auth_gap'],
      suggestedFollowUps: ['read middleware'],
      status: 'active',
      correlatedWith: ['ws-2'],
      unresolvedCorrelations: ['ws-2'],
    },
    {
      id: 'ws-2',
      discoveredAt: new Date().toISOString(),
      iteration: 1,
      description: 'Sensitive approval route shows auth=not_observed',
      surface: 'code',
      confidence: 0.8,
      novelty: 0.7,
      relatedAssets: ['src/api/routes/approvals.ts'],
      potentialCapabilities: ['unauthorized_approval'],
      suggestedFollowUps: ['read route file'],
      status: 'reopened',
      reactivationReason: 'shared auth boundary',
      correlatedWith: ['ws-1'],
      unresolvedCorrelations: [],
    },
    {
      id: 'ws-3',
      discoveredAt: new Date().toISOString(),
      iteration: 1,
      description: 'Dormant public-proof clue',
      surface: 'code',
      confidence: 0.4,
      novelty: 0.5,
      relatedAssets: ['frontend/src/app/public-proof/page.tsx'],
      potentialCapabilities: ['public_leak'],
      suggestedFollowUps: ['revisit if auth gaps widen'],
      status: 'dormant',
      dormantSince: new Date().toISOString(),
      correlatedWith: [],
      unresolvedCorrelations: [],
    },
  );
  for (const signal of memory.signals) {
    ingestSignal(memory.graph, signal);
  }
  memory.hypotheses.push({
    id: 'ph-1',
    synthesizedAt: new Date().toISOString(),
    iteration: 1,
    description: 'Opt-in auth plus approval route gap could allow unauthorized approvals',
    severity: 'high',
    signalIds: ['ws-1', 'ws-2'],
    prerequisites: [],
    status: 'testing',
    attempts: [],
  });

  const plannerPack = plannerContextPack(memory, '# Target\nBOS auth architecture', 12000);
  assert.ok(plannerPack.content.includes('## Retrieved Frontier Evidence'));
  assert.ok(plannerPack.content.includes('[ws-1]'));
  assert.ok(plannerPack.content.includes('## Unresolved Correlations'));
  assert.ok(plannerPack.includedIds.includes('ws-2'));

  const judgePack = judgeContextPack(memory, memory.hypotheses[0]!, 'Observed missing route auth markers.');
  assert.ok(judgePack.content.includes('## Related Signals (graph-adjacent)'));
  assert.ok(judgePack.content.includes('## Dormant Signals Sharing Assets') === false);
  assert.ok(judgePack.includedIds.includes('ws-1'));
  assert.ok(judgePack.includedIds.includes('ws-2'));
});
