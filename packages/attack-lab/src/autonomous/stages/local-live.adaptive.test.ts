/**
 * Section 6.1 — Response-driven adaptive exploration integration test.
 *
 * Drives the full local-live adaptive chain end-to-end against the
 * runner's public seams (no closure peeking, no fabricated runtime
 * signal text):
 *
 *   1. `runAdaptiveExploration` classifies a surprising round-1 response
 *      and, via the capturing planner adapter, generates + executes an
 *      adaptive probe that is appended to `roundResults` with
 *      `origin: 'adaptive'`.
 *   2. `collectRuntimeSignalsFromLiveResults` ingests the round results
 *      into `memory.signals`, producing real runtime-only signals with
 *      deterministic IDs the rest of the chain can reference.
 *   3. `selectMidRoundTriggers` + `runMidRoundSynthesis` operate over
 *      those signal IDs and invoke the synthesizer (novelty gate met).
 *   4. `translateHypothesisToLiveProbes` consumes the real signal
 *      summaries from `memory.signals` and the round-2 planner prompt
 *      echoes the signal ID discovered in round 1.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { InvestigationRunner } from '../investigation-runner.js';
import type {
  InvokeOptions,
  ModelAdapter,
  ModelResponse,
} from '../../providers/contracts.js';
import type { InvestigationTarget } from '../target-profile.js';
import type {
  VerificationPacket,
  VerificationLaneSummary,
} from '../investigation-runner-internals.js';
import type {
  CanarySpec,
  IdentitySpec,
  LiveExecutionResult,
  LiveProbeRequest,
} from '../../verification/local-live/index.js';
import {
  IdentityLadder,
  RateLimiter,
  MutationJournal,
  translateHypothesisToLiveProbes,
} from '../../verification/local-live/index.js';
import {
  runMidRoundSynthesis,
  selectMidRoundTriggers,
} from '../../verification/local-live/mid-round-synthesis.js';
import { EvidenceStore } from '../../../../evidence-plane/src/store.js';
import {
  createEmptyMemory,
  type CampaignMemory,
  type ChainHypothesis,
} from '../contracts.js';
import { addSignal } from '../weak-signal-ledger.js';
import { ingestSignal } from '../attack-graph.js';

class CapturingAdapter implements ModelAdapter {
  readonly provider = 'test';
  readonly model = 'capturing-adapter';
  public lastPrompt: string | null = null;
  public readonly prompts: string[] = [];
  private readonly response: string;

  constructor(response: string) {
    this.response = response;
  }

  async invoke<T = unknown>(options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    this.lastPrompt = options.prompt;
    this.prompts.push(options.prompt);
    return {
      content: this.response,
      usage: { inputTokens: 0, outputTokens: 0, costUsd: 0 },
      durationMs: 0,
      provider: this.provider,
      model: this.model,
    };
  }
}

function buildLiveTarget(): InvestigationTarget {
  return {
    id: 'adaptive-test',
    kind: 'http',
    environment: 'local',
    baseUrl: 'http://localhost:9999',
    supportedProbeKinds: ['http_request'],
    identities: [{ id: 'anonymous', kind: 'anonymous' }],
    hints: {},
  } as unknown as InvestigationTarget;
}

function seedMemoryWithHypothesis(): { memory: CampaignMemory; hypothesis: ChainHypothesis } {
  const memory = createEmptyMemory('adaptive-integration');
  memory.iteration = 1;

  // Pre-existing static signal on the same asset so the synthesizer
  // has something to correlate the runtime signal against.
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

  const hypothesis: ChainHypothesis = {
    id: 'hyp-reports',
    description: 'Tenant isolation bypass on /api/reports/:id',
    severity: 'high',
    signalIds: [staticSignal.id],
    status: 'open',
    boundaryCrossing: { from: 'public', to: 'tenant', mechanism: 'auth' },
    createdAtIteration: 1,
  } as unknown as ChainHypothesis;
  memory.hypotheses.push(hypothesis);

  return { memory, hypothesis };
}

function buildSurprisingResult(): LiveExecutionResult {
  return {
    probeId: 'live-hyp-reports-1',
    findingId: 'hyp-reports',
    identityId: 'anonymous',
    origin: 'hypothesis',
    request: {
      method: 'GET',
      url: 'http://localhost:9999/api/reports/1',
      headers: {},
      body: undefined,
    },
    response: {
      status: 500,
      headers: {},
      body:
        'Traceback (most recent call last):\n  File "/Users/app/server.py", line 42, in handler\nKeyError: tenant_id',
      durationMs: 42,
    },
    rollbackExecuted: false,
    verdict: 'inconclusive',
    reasoning: 'round 1 probe hit a 500 with a leaked stack trace',
  } as LiveExecutionResult;
}

function buildOriginalProbe(): LiveProbeRequest {
  return {
    findingId: 'hyp-reports',
    hypothesis: 'Tenant isolation bypass on /api/reports/:id',
    probeKind: 'http',
    identityId: 'anonymous',
    rationale: 'round 1 replay',
    http: { method: 'GET', path: '/api/reports/1' },
  };
}

function emptyLaneSummary(): VerificationLaneSummary {
  return {
    attempted: 0,
    meaningfulAttempts: 0,
    confirmed: 0,
    refuted: 0,
    inconclusive: 0,
    blocked: 0,
    skipped: 0,
    authFailed: 0,
    notApplicable: 0,
    notAuthorized: 0,
    rateLimited: 0,
    autoStopped: 0,
    timeout: 0,
    runtimeError: 0,
    compileError: 0,
    dryRunSimulated: 0,
    coverageGapCount: 0,
    costUsd: 0,
    durationMs: 0,
    status: 'complete',
    required: false,
    coverageGaps: [],
    adaptiveProbes: {
      hypothesis: { attempted: 0, confirmed: 0, refuted: 0, inconclusive: 0 },
      adaptive: { attempted: 0, confirmed: 0, refuted: 0, inconclusive: 0 },
      canary: { attempted: 0, matchedSafe: 0, matchedExploitable: 0 },
      surprisesDetected: 0,
      followupsGenerated: 0,
      midRoundHypothesesSynthesized: 0,
    },
  };
}

test('Section 6.1 — adaptive exploration drives real memory.signals + mid-round synthesis + round-2 prompt', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-adaptive-'));
  try {
    // ----- 1. Runner with a capturing planner adapter. -----
    const plannerResponse = JSON.stringify({
      probes: [
        {
          probeKind: 'http',
          identityId: 'anonymous',
          http: { method: 'GET', path: '/api/reports/2' },
          rationale: 'explore neighboring id after stack-trace surprise',
        },
      ],
      reasoning: 'chase the disclosed internal path with a sibling id',
    });
    const plannerAdapter = new CapturingAdapter(plannerResponse);
    const judgeAdapter = new CapturingAdapter('{}');

    const runner = new InvestigationRunner({
      targetRef: 'unused',
      mode: 'declared',
      plannerAdapter,
      judgeAdapter,
      maxIterations: 0,
      maxCostUsd: 1,
      campaignDir: join(root, 'campaigns'),
      runMode: 'smoke',
    });

    // ----- 2. Seed a real CampaignMemory + ChainHypothesis. -----
    const { memory, hypothesis } = seedMemoryWithHypothesis();
    const signalsBefore = memory.signals.length;

    // ----- 3. Live lane fixture state. -----
    const liveTarget = buildLiveTarget();
    const identities: IdentitySpec[] = [{ id: 'anonymous', kind: 'anonymous' }];
    const identityLadder = new IdentityLadder(identities);
    const rateLimiter = new RateLimiter({
      requestsPerSecond: 100,
      maxRequestsPerCampaign: 100,
      autoStopOn5xxStreak: 100,
      autoStopOnLatencyDoubling: false,
    });
    const mutationJournal = new MutationJournal();
    const canaries: CanarySpec[] = [];
    const evidenceStore = new EvidenceStore(`adaptive-${Date.now()}`, join(root, 'runs'));

    const surprising = buildSurprisingResult();
    const roundResults: LiveExecutionResult[] = [surprising];
    const originalProbe = buildOriginalProbe();
    const summary = emptyLaneSummary();

    const packet: VerificationPacket = {
      id: 'pkt-reports',
      hypothesis,
      signalDescriptions: ['auth middleware skips tenant check on /api/reports'],
      relatedAssets: ['/api/reports', 'src/api/routes/reports.ts'],
    };

    // ----- 4. Stub global.fetch so the adaptive probe can run. -----
    const originalFetch = globalThis.fetch;
    const calledUrls: string[] = [];
    globalThis.fetch = (async (input: unknown) => {
      calledUrls.push(typeof input === 'string' ? input : String(input));
      return new Response('{"id":2,"tenant":"other"}', {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as typeof fetch;

    try {
      await runner.runAdaptiveExploration({
        roundResults,
        executableHttpProbes: [originalProbe],
        packet,
        round: 1,
        liveTarget,
        rateLimiter,
        identityLadder,
        mutationJournal,
        canaries,
        allowMutations: false,
        liveReplayEventHandler: () => undefined,
        summary,
        adaptiveConfig: { enabled: true, maxFollowupsPerSurprise: 3, maxMidRoundHypotheses: 5 },
        evidenceStore,
        identities,
      });
    } finally {
      globalThis.fetch = originalFetch;
    }

    // ----- 5. Adaptive exploration fired and appended an adaptive probe. -----
    assert.equal(summary.adaptiveProbes!.surprisesDetected, 1, 'surprising response detected');
    assert.ok(
      summary.adaptiveProbes!.followupsGenerated >= 1,
      'at least one follow-up probe was generated',
    );
    assert.ok(
      calledUrls.some((url) => url.includes('/api/reports/2')),
      'follow-up probe targeted the planner-suggested sibling id',
    );
    const adaptiveResults = roundResults.filter((result) => result.origin === 'adaptive');
    assert.equal(adaptiveResults.length, 1, 'round results now contain an adaptive probe');
    assert.ok(
      plannerAdapter.prompts.some((p) => p.includes('Surprising Response')),
      'planner adapter was asked for follow-ups',
    );

    // ----- 6. Drive the real recordResults path via collectRuntimeSignalsFromLiveResults. -----
    const runtime = runner.collectRuntimeSignalsFromLiveResults(
      memory,
      liveTarget,
      packet,
      roundResults,
    );

    assert.ok(
      memory.signals.length > signalsBefore,
      'runtime probe results added new signals to memory.signals',
    );
    assert.ok(runtime.signalIds.length >= 1, 'collect returned at least one new signal id');
    const newSignalId = runtime.signalIds[0]!;
    const newSignal = memory.signals.find((s) => s.id === newSignalId);
    assert.ok(newSignal, 'new signal id corresponds to a real memory signal');
    assert.match(
      newSignal!.surface,
      /^runtime:/,
      'new signal is a runtime-surface signal (not static)',
    );
    assert.ok(
      runtime.summaries.some((summaryLine) => summaryLine.includes(`[${newSignalId}]`)),
      'summary line references the new signal by id',
    );

    // ----- 7. Mid-round synthesis actually runs (novelty gate met). -----
    const triggers = selectMidRoundTriggers(memory, runtime.signalIds);
    assert.ok(triggers.length >= 1, 'triggers mapped to real memory signals');
    const midRound = runMidRoundSynthesis(memory, triggers, {
      noveltyThreshold: 0.65,
      maxNew: 5,
    });
    assert.equal(midRound.invoked, true, 'mid-round synthesis was invoked');
    assert.equal(midRound.triggers.length, triggers.length, 'all triggers were retained');

    // ----- 8. Round 2 translator prompt consumes the real runtime signal summary. -----
    const round2Adapter = new CapturingAdapter(
      JSON.stringify({
        probes: [
          {
            probeKind: 'http',
            identityId: 'anonymous',
            http: { method: 'GET', path: '/api/reports/3' },
            rationale: 'round 2 exploration',
          },
        ],
        reasoning: 'round 2',
      }),
    );
    await translateHypothesisToLiveProbes(
      {
        findingId: hypothesis.id,
        hypothesis: hypothesis.description,
        availableIdentities: ['anonymous'],
        round: 2,
        // Feed the *real* summary lines produced by the runner — no
        // fabricated literal text.
        runtimeSignals: runtime.summaries,
        priorProbeResults: [
          {
            verdict: 'inconclusive',
            reasoning: surprising.reasoning,
            method: 'GET',
            path: '/api/reports/1',
            status: 500,
          },
        ],
      },
      round2Adapter,
    );

    assert.ok(round2Adapter.lastPrompt, 'round 2 adapter was invoked');
    assert.match(
      round2Adapter.lastPrompt!,
      /## Runtime Signals/,
      'round 2 prompt includes the Runtime Signals section',
    );
    assert.ok(
      round2Adapter.lastPrompt!.includes(`[${newSignalId}]`),
      'round 2 prompt echoes the specific runtime signal id discovered in round 1',
    );
    assert.match(round2Adapter.lastPrompt!, /Local-Live Round\n2/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('collectRuntimeSignalsFromLiveResults deduplicates repeated matching results', () => {
  const runner = new InvestigationRunner({
    targetRef: 'unused',
    mode: 'declared',
    plannerAdapter: new CapturingAdapter('{}'),
    judgeAdapter: new CapturingAdapter('{}'),
    maxIterations: 0,
    maxCostUsd: 1,
    campaignDir: join(tmpdir(), 'campaigns'),
    runMode: 'smoke',
  });
  const { memory, hypothesis } = seedMemoryWithHypothesis();
  const packet: VerificationPacket = {
    id: 'pkt-dedup',
    hypothesis,
    signalDescriptions: [],
    relatedAssets: ['/api/reports', 'src/api/routes/reports.ts'],
  };
  const liveTarget = buildLiveTarget();
  const repeated: LiveExecutionResult = {
    probeId: 'probe-dedup-1',
    findingId: hypothesis.id,
    identityId: 'anonymous',
    request: { method: 'GET', url: `${liveTarget.baseUrl}/api/reports/1`, headers: {} },
    response: { status: 401, headers: {}, body: '', durationMs: 25 },
    rollbackExecuted: false,
    verdict: 'refuted',
    reasoning: 'No canary or expectation match. Status 401.',
  };

  const runtime = runner.collectRuntimeSignalsFromLiveResults(
    memory,
    liveTarget,
    packet,
    [
      repeated,
      { ...repeated, probeId: 'probe-dedup-2' },
      { ...repeated, probeId: 'probe-dedup-3' },
    ],
  );

  assert.equal(runtime.signalIds.length, 1);
  assert.equal(runtime.summaries.length, 1);
  assert.equal(new Set(runtime.signalIds).size, runtime.signalIds.length);
});

test('collectRuntimeSignalsFromLiveResults does not synthesize unrelated global chains', () => {
  const runner = new InvestigationRunner({
    targetRef: 'unused',
    mode: 'declared',
    plannerAdapter: new CapturingAdapter('{}'),
    judgeAdapter: new CapturingAdapter('{}'),
    maxIterations: 0,
    maxCostUsd: 1,
    campaignDir: join(tmpdir(), 'campaigns'),
    runMode: 'smoke',
  });
  const { memory, hypothesis } = seedMemoryWithHypothesis();
  const packet: VerificationPacket = {
    id: 'pkt-focused-runtime',
    hypothesis,
    signalDescriptions: [],
    relatedAssets: ['/api/reports', 'src/api/routes/reports.ts'],
  };
  const liveTarget = buildLiveTarget();

  const unrelatedOne = addSignal(memory, {
    description: 'legacy export route leaks verbose debug metadata',
    surface: 'code:route',
    confidence: 0.66,
    novelty: 0.4,
    relatedAssets: ['/api/unrelated', 'src/routes/unrelated.ts'],
    potentialCapabilities: ['debug_leak'],
    suggestedFollowUps: ['inspect unrelated export path'],
  });
  ingestSignal(memory.graph, unrelatedOne);
  const unrelatedTwo = addSignal(memory, {
    description: 'legacy export admin flag toggles broad data scope',
    surface: 'code:config',
    confidence: 0.68,
    novelty: 0.42,
    relatedAssets: ['/api/unrelated', 'src/routes/unrelated.ts'],
    potentialCapabilities: ['debug_leak'],
    suggestedFollowUps: ['check scope on unrelated export path'],
  });
  ingestSignal(memory.graph, unrelatedTwo);

  const hypothesesBefore = memory.hypotheses.length;
  const runtime = runner.collectRuntimeSignalsFromLiveResults(
    memory,
    liveTarget,
    packet,
    [
      {
        probeId: 'probe-runtime-focused',
        findingId: hypothesis.id,
        identityId: 'anonymous',
        request: { method: 'GET', url: `${liveTarget.baseUrl}/api/reports/1`, headers: {} },
        response: { status: 500, headers: {}, body: 'stack trace', durationMs: 12 },
        rollbackExecuted: false,
        verdict: 'inconclusive',
        reasoning: 'No canary or expectation match. Status 500.',
      },
    ],
  );

  const newHypotheses = memory.hypotheses.slice(hypothesesBefore);
  assert.ok(runtime.signalIds.length >= 1, 'runtime ingest should produce at least one new signal');
  assert.ok(newHypotheses.length >= 1, 'runtime ingest should still synthesize at least one focused hypothesis');
  for (const candidate of newHypotheses) {
    assert.ok(
      candidate.signalIds.some((id) => runtime.signalIds.includes(id)),
      'synthesized runtime follow-up must stay attached to the triggering runtime signal set',
    );
  }
  assert.ok(
    !newHypotheses.some((candidate) =>
      candidate.signalIds.includes(unrelatedOne.id) && candidate.signalIds.includes(unrelatedTwo.id),
    ),
    'unrelated pre-existing graph branches should not be promoted during focused runtime synthesis',
  );
});
