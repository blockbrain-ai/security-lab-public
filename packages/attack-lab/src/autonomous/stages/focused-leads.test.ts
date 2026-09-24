/**
 * Section 11.5 — Focused lead confirmation stage integration test.
 *
 * Proves the end-to-end flow: static leads are ranked, briefs are written,
 * a worker inspects and requests a probe, the orchestrator executes it,
 * and a structured outcome is recorded.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdtemp, rm, readdir, readFile } from 'node:fs/promises';
import { rankLeads } from '../../verification/focused-leads/lead-ranker.js';
import { buildLeadBrief, writeBriefManifests, renderBriefForWorker } from '../../verification/focused-leads/lead-brief.js';
import {
  runFocusedConfirmation,
  mapConfirmationToHypothesisStatus,
  buildConfirmationSummary,
  isConfirmationStatus,
  type FocusedConfirmationConfig,
  type ProbeExecutor,
  type WorkerSession,
} from '../../verification/focused-leads/focused-confirmation.js';
import { DEFAULT_RANKING_CONFIG } from '../../verification/focused-leads/lead-ranker.js';
import type { CampaignMemory } from '../contracts.js';
import type { EvidenceStore } from '../../../../evidence-plane/src/store.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEvidenceStore() {
  const events: Array<{ name: string; payload: Record<string, unknown> }> = [];
  return {
    appendEvent: async (name: string, payload: Record<string, unknown>) => {
      events.push({ name, payload });
    },
    get events() { return events; },
  } as unknown as EvidenceStore;
}

function makeMemoryWithLeads(): CampaignMemory {
  return {
    campaignId: 'integration-test',
    iteration: 5,
    signals: [
      {
        id: 'ws-idor',
        discoveredAt: '2026-01-01T00:00:00Z',
        iteration: 1,
        description: 'Tenant ID visible in response body',
        surface: '/api/companies/:companyId',
        confidence: 0.85,
        novelty: 0.7,
        relatedAssets: ['src/routes/companies.ts', 'src/middleware/auth.ts'],
        potentialCapabilities: ['cross-tenant read'],
        suggestedFollowUps: ['try with user_b token'],
        status: 'active',
        correlatedWith: [],
        unresolvedCorrelations: [],
      },
      {
        id: 'ws-ssrf',
        discoveredAt: '2026-01-02T00:00:00Z',
        iteration: 2,
        description: 'URL parameter passed to fetch without validation',
        surface: '/api/proxy',
        confidence: 0.6,
        novelty: 0.8,
        relatedAssets: ['src/routes/proxy.ts'],
        potentialCapabilities: ['internal network access'],
        suggestedFollowUps: ['probe loopback'],
        status: 'active',
        correlatedWith: [],
        unresolvedCorrelations: [],
      },
    ],
    hypotheses: [
      {
        id: 'hyp-idor',
        synthesizedAt: '2026-01-03T00:00:00Z',
        iteration: 3,
        description: 'IDOR via cross-tenant company data access',
        severity: 'high',
        signalIds: ['ws-idor'],
        prerequisites: ['Two distinct tenant tokens'],
        boundaryCrossing: { from: 'tenant_a', to: 'tenant_b', mechanism: 'direct_id_substitution' },
        status: 'proposed',
        attempts: [],
        sourceLocationRefs: [{ path: 'src/routes/companies.ts', startLine: 42, endLine: 58 }],
      },
      {
        id: 'hyp-ssrf',
        synthesizedAt: '2026-01-03T00:00:00Z',
        iteration: 3,
        description: 'SSRF via URL fetch parameter in proxy endpoint',
        severity: 'critical',
        signalIds: ['ws-ssrf'],
        prerequisites: ['Proxy endpoint accessible'],
        status: 'proposed',
        attempts: [],
      },
    ],
    findings: [],
    graph: { nodes: [], edges: [] },
    probeFingerprints: new Set(),
    totalCostUsd: 0.5,
    totalProbes: 12,
    duplicateProbesSuppressed: 3,
    dormantSignalIds: [],
    lastResurfacingIteration: 0,
  };
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

test('integration: static leads flow through ranking → briefs → worker → outcome', async () => {
  const memory = makeMemoryWithLeads();
  const evidenceStore = makeEvidenceStore();
  const dir = await mkdtemp(join(tmpdir(), 'integration-test-'));

  try {
    // Step 1: Rank leads.
    const ranked = rankLeads(memory.hypotheses, memory.signals);
    assert.ok(ranked.length >= 2, 'Both hypotheses should rank');
    assert.ok(ranked[0]!.rank === 1);

    // Step 2: Build briefs.
    const briefs = ranked.map((r) => buildLeadBrief(r, memory.signals));
    assert.equal(briefs.length, ranked.length);

    // Verify brief content — no target-specific hardcoding.
    for (const brief of briefs) {
      assert.ok(brief.hypothesisId);
      assert.ok(brief.hypothesis.length > 0);
      assert.ok(brief.suggestedProbeFamily !== '');
    }

    // Step 3: Write briefs to disk.
    const writtenBriefs = await writeBriefManifests(briefs, dir);
    const briefDir = join(dir, 'focused-lead-briefs');
    const files = await readdir(briefDir);
    assert.equal(files.length, briefs.length);

    // Verify JSON is readable.
    for (const brief of writtenBriefs) {
      assert.ok(brief.briefPath);
      const content = JSON.parse(await readFile(brief.briefPath!, 'utf-8'));
      assert.equal(content.hypothesisId, brief.hypothesisId);
    }

    // Step 4: Render brief for worker — compact, not giant.
    const rendered = renderBriefForWorker(writtenBriefs[0]!);
    assert.ok(rendered.length < 3000, 'Brief should be compact');
    assert.ok(rendered.includes('Do not execute live probes directly'));

    // Step 5: Run full orchestration.
    const config: FocusedConfirmationConfig = {
      ranking: DEFAULT_RANKING_CONFIG,
      maxProbesPerSession: 5,
      useCounterWorker: false,
      campaignDir: dir,
    };

    let probeExecutorCalled = 0;
    const executor: ProbeExecutor = async (request) => {
      probeExecutorCalled++;
      // Verify probe goes through orchestrator.
      assert.ok(request.workerSessionId.startsWith('fcs-'));
      return {
        probeId: `probe-${probeExecutorCalled}`,
        verdict: probeExecutorCalled === 1 ? 'confirmed' as const : 'inconclusive' as const,
        observation: 'Test observation',
        confidence: 0.85,
        evidenceRefs: [`ev-${probeExecutorCalled}`],
        rollbackExecuted: false,
      };
    };

    const workerFactory = (hypothesisId: string): WorkerSession => {
      return async (brief, requestProbe, role) => {
        assert.equal(role, 'primary');
        // Worker inspects the brief and requests a probe.
        const result = await requestProbe({
          hypothesisId: brief.hypothesisId,
          rationale: `Confirming ${brief.hypothesis}`,
          probe: {
            findingId: brief.hypothesisId,
            hypothesis: brief.hypothesis,
            probeKind: 'http',
            identityId: 'user_b',
            probeFamily: brief.suggestedProbeFamily,
            http: { method: 'GET', path: '/api/test' },
          },
          isFollowUp: false,
        });
        return {
          status: result.verdict === 'confirmed' ? 'confirmed' as const : 'insufficient_evidence' as const,
          reasoning: `Worker conclusion for ${hypothesisId}`,
        };
      };
    };

    const result = await runFocusedConfirmation(
      memory, workerFactory, executor, config, evidenceStore,
    );

    // Step 6: Verify structured outcomes.
    assert.ok(result.sessions.length > 0);
    assert.ok(result.totalProbesExecuted > 0);
    assert.equal(probeExecutorCalled, result.totalProbesExecuted);

    // Every session has a valid confirmation status.
    for (const session of result.sessions) {
      assert.ok(isConfirmationStatus(session.status));
      assert.ok(session.reasoning.length > 0);
      assert.ok(session.startedAt);
      assert.ok(session.completedAt);
    }

    // Step 7: Verify hypothesis status mapping.
    for (const session of result.sessions) {
      const newStatus = mapConfirmationToHypothesisStatus(session.status);
      assert.ok(['confirmed', 'refuted', 'needs_more_data'].includes(newStatus));
    }

    // Step 8: Verify report summary.
    const summary = buildConfirmationSummary(result);
    assert.equal(summary.sessionsRun, result.sessions.length);
    assert.ok(summary.leads.length > 0);
    for (const lead of summary.leads) {
      assert.ok(lead.hypothesisId);
      assert.ok(lead.rank > 0);
      assert.ok(lead.severity);
      assert.ok(isConfirmationStatus(lead.status));
    }

    // Step 9: Verify evidence events were emitted.
    const events = (evidenceStore as unknown as { events: Array<{ name: string }> }).events;
    const eventNames = events.map((e) => e.name);
    assert.ok(eventNames.includes('focused_confirmation_leads_ranked'));
    assert.ok(eventNames.includes('focused_confirmation_session_started'));
    assert.ok(eventNames.includes('focused_confirmation_probe_executed'));
    assert.ok(eventNames.includes('focused_confirmation_session_completed'));
    assert.ok(eventNames.includes('focused_confirmation_completed'));

  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('integration: no leads qualify when all hypotheses are confirmed', async () => {
  const memory = makeMemoryWithLeads();
  memory.hypotheses.forEach((h) => { h.status = 'confirmed'; });
  const evidenceStore = makeEvidenceStore();

  const config: FocusedConfirmationConfig = {
    ranking: DEFAULT_RANKING_CONFIG,
    maxProbesPerSession: 5,
    useCounterWorker: false,
    campaignDir: '/tmp/no-leads',
  };

  const result = await runFocusedConfirmation(
    memory,
    () => { throw new Error('Should not be called'); },
    async () => { throw new Error('Should not be called'); },
    config,
    evidenceStore,
  );

  assert.equal(result.sessions.length, 0);
  assert.equal(result.confirmed, 0);
});

test('integration: lead ranking is not hardcoded to target-specific names', () => {
  // Verify no target-specific strings appear in ranking logic.
  const memory = makeMemoryWithLeads();
  // Replace hypotheses with generic descriptions.
  memory.hypotheses = [
    {
      id: 'hyp-generic',
      synthesizedAt: '2026-01-01T00:00:00Z',
      iteration: 1,
      description: 'Generic authentication bypass via token reuse',
      severity: 'high',
      signalIds: ['ws-idor'],
      prerequisites: [],
      status: 'proposed',
      attempts: [],
    },
  ];

  const ranked = rankLeads(memory.hypotheses, memory.signals);
  assert.ok(ranked.length > 0, 'Generic hypotheses should still rank');
});
