/**
 * Section 11.5 — Focused confirmation session tests.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  runFocusedSession,
  runFocusedConfirmation,
  mapConfirmationToHypothesisStatus,
  buildConfirmationSummary,
  isConfirmationStatus,
  CONFIRMATION_STATUSES,
  type FocusedConfirmationConfig,
  type ProbeExecutor,
  type WorkerSession,
  type ProbeExecutionResult,
  type LeadBrief,
} from './focused-confirmation.js';
import { DEFAULT_RANKING_CONFIG } from './lead-ranker.js';
import type { CampaignMemory } from '../../autonomous/contracts.js';
import type { EvidenceStore } from '../../../../evidence-plane/src/store.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeBrief(overrides?: Partial<LeadBrief>): LeadBrief {
  return {
    hypothesisId: 'h-1',
    rank: 1,
    score: 0.7,
    hypothesis: 'IDOR via cross-tenant access',
    severity: 'high',
    decisiveSignals: [],
    sourceRefs: [],
    relatedAssets: [],
    relevantSurfaces: [],
    requiredIdentities: [],
    suggestedProbeFamily: 'identity_differential',
    evidenceGaps: [],
    priorAttempts: [],
    ...overrides,
  };
}

function makeProbeResult(overrides?: Partial<ProbeExecutionResult>): ProbeExecutionResult {
  return {
    probeId: 'probe-1',
    verdict: 'confirmed',
    observation: 'Got 200 with other tenant data',
    confidence: 0.9,
    evidenceRefs: ['ev-1'],
    rollbackExecuted: false,
    ...overrides,
  };
}

function makeEvidenceStore(): EvidenceStore {
  const events: Array<{ name: string; payload: Record<string, unknown> }> = [];
  return {
    appendEvent: async (name: string, payload: Record<string, unknown>) => {
      events.push({ name, payload });
    },
    get events() {
      return events;
    },
  } as unknown as EvidenceStore;
}

function makeConfig(campaignDir: string): FocusedConfirmationConfig {
  return {
    ranking: DEFAULT_RANKING_CONFIG,
    maxProbesPerSession: 10,
    useCounterWorker: false,
    campaignDir,
  };
}

function makeMemory(): CampaignMemory {
  return {
    campaignId: 'test-campaign',
    iteration: 3,
    signals: [
      {
        id: 'ws-1',
        discoveredAt: '2026-01-01T00:00:00Z',
        iteration: 1,
        description: 'Tenant ID in response',
        surface: '/api/data',
        confidence: 0.9,
        novelty: 0.7,
        relatedAssets: ['src/handler.ts'],
        potentialCapabilities: [],
        suggestedFollowUps: [],
        status: 'active',
        correlatedWith: [],
        unresolvedCorrelations: [],
      },
    ],
    hypotheses: [
      {
        id: 'h-1',
        synthesizedAt: '2026-01-01T00:00:00Z',
        iteration: 2,
        description: 'IDOR via cross-tenant access',
        severity: 'high',
        signalIds: ['ws-1'],
        prerequisites: [],
        status: 'proposed',
        attempts: [],
      },
    ],
    findings: [],
    graph: { nodes: [], edges: [] },
    probeFingerprints: new Set(),
    totalCostUsd: 0,
    totalProbes: 0,
    duplicateProbesSuppressed: 0,
    dormantSignalIds: [],
    lastResurfacingIteration: 0,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test('isConfirmationStatus validates all statuses', () => {
  for (const s of CONFIRMATION_STATUSES) {
    assert.ok(isConfirmationStatus(s));
  }
  assert.ok(!isConfirmationStatus('unknown'));
  assert.ok(!isConfirmationStatus(''));
});

test('mapConfirmationToHypothesisStatus maps correctly', () => {
  assert.equal(mapConfirmationToHypothesisStatus('confirmed'), 'confirmed');
  assert.equal(mapConfirmationToHypothesisStatus('refuted'), 'refuted');
  assert.equal(mapConfirmationToHypothesisStatus('narrowed'), 'needs_more_data');
  assert.equal(mapConfirmationToHypothesisStatus('needs_browser'), 'needs_more_data');
  assert.equal(mapConfirmationToHypothesisStatus('needs_human_setup'), 'needs_more_data');
  assert.equal(mapConfirmationToHypothesisStatus('insufficient_evidence'), 'needs_more_data');
});

test('runFocusedSession executes worker and collects outcomes', async () => {
  const brief = makeBrief();
  const evidenceStore = makeEvidenceStore();

  const worker: WorkerSession = async (_brief, requestProbe, _role) => {
    const result = await requestProbe({
      hypothesisId: 'h-1',
      rationale: 'Testing IDOR',
      probe: {
        findingId: 'h-1',
        hypothesis: 'IDOR test',
        probeKind: 'http',
        identityId: 'user_b',
        http: { method: 'GET', path: '/api/data/123' },
      },
      isFollowUp: false,
    });
    return {
      status: result.verdict === 'confirmed' ? 'confirmed' as const : 'insufficient_evidence' as const,
      reasoning: 'Cross-tenant data returned',
    };
  };

  const executor: ProbeExecutor = async (_request) => makeProbeResult();

  const config = makeConfig('/tmp/test-campaign');
  const session = await runFocusedSession(brief, worker, executor, config, evidenceStore);

  assert.equal(session.hypothesisId, 'h-1');
  assert.equal(session.status, 'confirmed');
  assert.equal(session.totalProbes, 1);
  assert.equal(session.probeRequests.length, 1);
  assert.equal(session.probeResults.length, 1);
  assert.ok(session.startedAt);
  assert.ok(session.completedAt);
});

test('runFocusedSession enforces probe limit', async () => {
  const brief = makeBrief();
  const evidenceStore = makeEvidenceStore();
  const config = makeConfig('/tmp/test-campaign');
  config.maxProbesPerSession = 2;

  let rateLimited = false;

  const worker: WorkerSession = async (_brief, requestProbe, _role) => {
    await requestProbe({
      hypothesisId: 'h-1',
      rationale: 'Probe 1',
      probe: { findingId: 'h-1', hypothesis: 'test', probeKind: 'http', identityId: 'user_a' },
      isFollowUp: false,
    });
    await requestProbe({
      hypothesisId: 'h-1',
      rationale: 'Probe 2',
      probe: { findingId: 'h-1', hypothesis: 'test', probeKind: 'http', identityId: 'user_a' },
      isFollowUp: true,
    });
    const result = await requestProbe({
      hypothesisId: 'h-1',
      rationale: 'Probe 3 — should be rate limited',
      probe: { findingId: 'h-1', hypothesis: 'test', probeKind: 'http', identityId: 'user_a' },
      isFollowUp: true,
    });
    if (result.verdict === 'rate_limited') rateLimited = true;
    return { status: 'insufficient_evidence', reasoning: 'Hit limit' };
  };

  const executor: ProbeExecutor = async () => makeProbeResult({ verdict: 'inconclusive' });
  await runFocusedSession(brief, worker, executor, config, evidenceStore);

  assert.ok(rateLimited, 'Third probe should have been rate-limited');
});

test('runFocusedSession emits evidence events', async () => {
  const brief = makeBrief();
  const evidenceStore = makeEvidenceStore();
  const config = makeConfig('/tmp/test-campaign');

  const worker: WorkerSession = async (_brief, requestProbe, _role) => {
    await requestProbe({
      hypothesisId: 'h-1',
      rationale: 'test',
      probe: { findingId: 'h-1', hypothesis: 'test', probeKind: 'http', identityId: 'anon' },
      isFollowUp: false,
    });
    return { status: 'refuted', reasoning: 'Got 403' };
  };

  const executor: ProbeExecutor = async () => makeProbeResult({ verdict: 'refuted' });
  await runFocusedSession(brief, worker, executor, config, evidenceStore);

  const events = (evidenceStore as unknown as { events: Array<{ name: string }> }).events;
  const eventNames = events.map((e) => e.name);
  assert.ok(eventNames.includes('focused_confirmation_session_started'));
  assert.ok(eventNames.includes('focused_confirmation_probe_executed'));
  assert.ok(eventNames.includes('focused_confirmation_session_completed'));
});

test('runFocusedConfirmation runs full workflow', async () => {
  const memory = makeMemory();
  const evidenceStore = makeEvidenceStore();
  const { tmpdir } = await import('node:os');
  const { mkdtemp, rm } = await import('node:fs/promises');
  const { join } = await import('node:path');
  const dir = await mkdtemp(join(tmpdir(), 'focused-confirm-'));

  try {
    const config = makeConfig(dir);

    const workerFactory = (_hypothesisId: string): WorkerSession => {
      return async (_brief, requestProbe, _role) => {
        await requestProbe({
          hypothesisId: _brief.hypothesisId,
          rationale: 'Automated test',
          probe: {
            findingId: _brief.hypothesisId,
            hypothesis: _brief.hypothesis,
            probeKind: 'http',
            identityId: 'user_b',
            http: { method: 'GET', path: '/api/data/123' },
          },
          isFollowUp: false,
        });
        return { status: 'confirmed', reasoning: 'Cross-tenant data confirmed' };
      };
    };

    const executor: ProbeExecutor = async () => makeProbeResult();

    const result = await runFocusedConfirmation(memory, workerFactory, executor, config, evidenceStore);

    assert.ok(result.sessions.length > 0);
    assert.equal(result.confirmed, 1);
    assert.ok(result.totalProbesExecuted > 0);
    assert.ok(result.briefPaths.length > 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('runFocusedConfirmation runs counter worker when primary remains non-terminal', async () => {
  const memory = makeMemory();
  const evidenceStore = makeEvidenceStore();
  const { tmpdir } = await import('node:os');
  const { mkdtemp, rm } = await import('node:fs/promises');
  const { join } = await import('node:path');
  const dir = await mkdtemp(join(tmpdir(), 'focused-counter-'));

  try {
    const config = makeConfig(dir);
    config.useCounterWorker = true;

    const rolesSeen: string[] = [];
    const workerFactory = (): WorkerSession => {
      return async (_brief, requestProbe, role) => {
        rolesSeen.push(role);
        if (role === 'primary') {
          await requestProbe({
            hypothesisId: _brief.hypothesisId,
            rationale: 'Primary check',
            probe: {
              findingId: _brief.hypothesisId,
              hypothesis: _brief.hypothesis,
              probeKind: 'http',
              identityId: 'guest',
              http: { method: 'GET', path: '/api/test' },
            },
            isFollowUp: false,
          });
          return { status: 'insufficient_evidence', reasoning: 'Primary needs a second opinion.' };
        }

        return { status: 'refuted', reasoning: 'Counter worker refuted the lead.' };
      };
    };

    const executor: ProbeExecutor = async () => makeProbeResult({ verdict: 'inconclusive' });

    const result = await runFocusedConfirmation(
      memory,
      workerFactory,
      executor,
      config,
      evidenceStore,
    );

    assert.deepEqual(rolesSeen, ['primary', 'counter']);
    assert.equal(result.sessions.length, 1);
    assert.equal(result.refuted, 1);
    assert.equal(result.totalProbesExecuted, 1);
    assert.equal(result.sessions[0]?.status, 'refuted');
    assert.match(result.sessions[0]?.reasoning ?? '', /Counter review:/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('runFocusedConfirmation returns empty result when no leads qualify', async () => {
  const memory = makeMemory();
  // Mark all hypotheses as confirmed so none qualify for ranking.
  memory.hypotheses[0]!.status = 'confirmed';

  const evidenceStore = makeEvidenceStore();
  const config = makeConfig('/tmp/empty-test');

  const workerFactory = () => { throw new Error('Should not be called'); };
  const executor: ProbeExecutor = async () => { throw new Error('Should not be called'); };

  const result = await runFocusedConfirmation(memory, workerFactory as never, executor, config, evidenceStore);

  assert.equal(result.sessions.length, 0);
  assert.equal(result.confirmed, 0);
  assert.equal(result.totalProbesExecuted, 0);
});

test('buildConfirmationSummary produces report-ready data', async () => {
  const memory = makeMemory();
  const evidenceStore = makeEvidenceStore();
  const { tmpdir } = await import('node:os');
  const { mkdtemp, rm } = await import('node:fs/promises');
  const { join } = await import('node:path');
  const dir = await mkdtemp(join(tmpdir(), 'summary-test-'));

  try {
    const config = makeConfig(dir);
    const workerFactory = (): WorkerSession => {
      return async (_brief, _requestProbe, _role) => {
        return { status: 'narrowed', reasoning: 'Partial evidence' };
      };
    };
    const executor: ProbeExecutor = async () => makeProbeResult();

    const result = await runFocusedConfirmation(memory, workerFactory, executor, config, evidenceStore);
    const summary = buildConfirmationSummary(result);

    assert.equal(summary.sessionsRun, result.sessions.length);
    assert.equal(summary.narrowed, 1);
    assert.ok(summary.leads.length > 0);
    assert.equal(summary.leads[0]!.status, 'narrowed');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('no worker-requested probe bypasses orchestrator execution', async () => {
  const brief = makeBrief();
  const evidenceStore = makeEvidenceStore();
  const config = makeConfig('/tmp/test-campaign');
  let executorCalled = false;

  const worker: WorkerSession = async (_brief, requestProbe, _role) => {
    await requestProbe({
      hypothesisId: 'h-1',
      rationale: 'must go through orchestrator',
      probe: { findingId: 'h-1', hypothesis: 'test', probeKind: 'http', identityId: 'anon' },
      isFollowUp: false,
    });
    return { status: 'confirmed', reasoning: 'Verified' };
  };

  const executor: ProbeExecutor = async (request) => {
    executorCalled = true;
    // Verify the request came through properly.
    assert.equal(request.workerSessionId.startsWith('fcs-'), true);
    assert.equal(request.workerRole, 'primary');
    return makeProbeResult();
  };

  await runFocusedSession(brief, worker, executor, config, evidenceStore);
  assert.ok(executorCalled, 'Probe executor must be called for every worker probe request');
});
