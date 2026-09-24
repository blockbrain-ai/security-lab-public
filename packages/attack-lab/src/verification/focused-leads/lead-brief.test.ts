/**
 * Section 11.5 — Lead brief manifest tests.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import {
  buildLeadBrief,
  writeBriefManifests,
  renderBriefForWorker,
  type LeadBrief,
} from './lead-brief.js';
import type { RankedLead } from './lead-ranker.js';
import type { ChainHypothesis, WeakSignal } from '../../autonomous/contracts.js';

function makeSignal(overrides: Partial<WeakSignal> & { id: string }): WeakSignal {
  return {
    discoveredAt: '2026-01-01T00:00:00Z',
    iteration: 1,
    description: 'test signal',
    surface: '/api/test',
    confidence: 0.8,
    novelty: 0.6,
    relatedAssets: ['src/handler.ts'],
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
    description: 'IDOR via cross-tenant resource access',
    severity: 'high',
    signalIds: ['ws-1'],
    prerequisites: [],
    status: 'proposed',
    attempts: [],
    ...overrides,
  };
}

function makeRankedLead(hypothesis: ChainHypothesis): RankedLead {
  return {
    hypothesis,
    factors: {
      severity: 0.75,
      confidence: 0.8,
      confirmability: 0.6,
      novelty: 0.5,
      boundaryCrossingPotential: 0,
    },
    score: 0.65,
    probeFamily: 'identity_differential',
    rank: 1,
  };
}

test('buildLeadBrief populates all fields from hypothesis and signals', () => {
  const signal = makeSignal({
    id: 'ws-1',
    description: 'Tenant ID leaks in API response',
    surface: '/api/companies',
    confidence: 0.85,
  });
  const hypothesis = makeHypothesis({
    id: 'h-1',
    signalIds: ['ws-1'],
    sourceLocationRefs: [{ path: 'src/routes.ts', startLine: 10, endLine: 20 }],
  });
  const ranked = makeRankedLead(hypothesis);

  const brief = buildLeadBrief(ranked, [signal]);

  assert.equal(brief.hypothesisId, 'h-1');
  assert.equal(brief.rank, 1);
  assert.equal(brief.severity, 'high');
  assert.equal(brief.decisiveSignals.length, 1);
  assert.equal(brief.decisiveSignals[0]!.id, 'ws-1');
  assert.equal(brief.sourceRefs.length, 1);
  assert.ok(brief.relatedAssets.includes('src/handler.ts'));
  assert.ok(brief.relevantSurfaces.includes('/api/companies'));
  assert.equal(brief.suggestedProbeFamily, 'identity_differential');
});

test('buildLeadBrief identifies evidence gaps for hypothesis without source refs', () => {
  const signal = makeSignal({ id: 'ws-1' });
  const hypothesis = makeHypothesis({ id: 'h-1' });
  const ranked = makeRankedLead(hypothesis);

  const brief = buildLeadBrief(ranked, [signal]);

  assert.ok(brief.evidenceGaps.some((g) => g.includes('source location refs')));
  assert.ok(brief.evidenceGaps.some((g) => g.includes('No prior probe attempts')));
});

test('buildLeadBrief includes prior attempt summaries', () => {
  const signal = makeSignal({ id: 'ws-1' });
  const hypothesis = makeHypothesis({
    id: 'h-1',
    attempts: [
      {
        at: '2026-01-02T00:00:00Z',
        iteration: 2,
        probeIds: ['p-1'],
        observation: 'Got 403',
        verdict: 'dead_end',
        reasoning: 'Access denied',
      },
    ],
  });
  const ranked = makeRankedLead(hypothesis);

  const brief = buildLeadBrief(ranked, [signal]);

  assert.equal(brief.priorAttempts.length, 1);
  assert.equal(brief.priorAttempts[0]!.verdict, 'dead_end');
});

test('buildLeadBrief extracts required identities from privilege delta', () => {
  const signal = makeSignal({ id: 'ws-1' });
  const hypothesis = makeHypothesis({
    id: 'h-1',
    privilegeDelta: { before: 'user', after: 'admin', escalationType: 'vertical' },
  });
  const ranked = makeRankedLead(hypothesis);

  const brief = buildLeadBrief(ranked, [signal]);

  assert.ok(brief.requiredIdentities.includes('user'));
  assert.ok(brief.requiredIdentities.includes('admin'));
});

test('writeBriefManifests writes JSON files to disk', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'brief-test-'));
  try {
    const brief: LeadBrief = {
      hypothesisId: 'h-test',
      rank: 1,
      score: 0.65,
      hypothesis: 'Test hypothesis',
      severity: 'high',
      decisiveSignals: [],
      sourceRefs: [],
      relatedAssets: [],
      relevantSurfaces: [],
      requiredIdentities: [],
      suggestedProbeFamily: 'generic',
      evidenceGaps: ['gap-1'],
      priorAttempts: [],
    };

    const result = await writeBriefManifests([brief], dir);

    assert.equal(result.length, 1);
    assert.ok(result[0]!.briefPath);
    const content = JSON.parse(await readFile(result[0]!.briefPath!, 'utf-8'));
    assert.equal(content.hypothesisId, 'h-test');
    assert.equal(content.rank, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('renderBriefForWorker produces compact markdown without giant prompts', () => {
  const brief: LeadBrief = {
    hypothesisId: 'h-render',
    rank: 2,
    score: 0.72,
    hypothesis: 'SSRF via URL fetch parameter',
    severity: 'critical',
    decisiveSignals: [{ id: 'ws-1', description: 'URL param accepted', surface: '/api/fetch', confidence: 0.9 }],
    sourceRefs: [{ path: 'src/fetcher.ts', startLine: 15, endLine: 25 }],
    relatedAssets: ['src/fetcher.ts', 'src/proxy.ts'],
    relevantSurfaces: ['/api/fetch'],
    requiredIdentities: ['user'],
    suggestedProbeFamily: 'ssrf',
    evidenceGaps: ['No live confirmation yet'],
    priorAttempts: [{ at: '2026-01-01', verdict: 'partial', observation: 'Got redirect' }],
  };

  const md = renderBriefForWorker(brief);

  assert.ok(md.includes('Lead Brief: h-render'));
  assert.ok(md.includes('SSRF'));
  assert.ok(md.includes('src/fetcher.ts:15-25'));
  assert.ok(md.includes('Evidence Gaps'));
  assert.ok(md.includes('Prior Attempts'));
  assert.ok(md.includes('Do not execute live probes directly'));
  // Should be compact — under 2000 chars for this brief.
  assert.ok(md.length < 2000, `Brief too large: ${md.length} chars`);
});

test('buildLeadBrief identifies low-confidence gap', () => {
  const signal = makeSignal({ id: 'ws-1', confidence: 0.3 });
  const hypothesis = makeHypothesis({ id: 'h-1' });
  const ranked = makeRankedLead(hypothesis);

  const brief = buildLeadBrief(ranked, [signal]);

  assert.ok(brief.evidenceGaps.some((g) => g.includes('below 50% confidence')));
});
