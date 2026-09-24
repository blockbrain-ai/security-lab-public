/**
 * Section 6.2 — Mythos creativity sub-lane integration test.
 *
 * Exercises the runner seam end-to-end:
 *
 *   1. Build an InvestigationRunner with a ModelAdapter that returns a
 *      `submitProbe` tool call for a path that is NOT on the initial
 *      hypothesis list.
 *   2. Build a Mythos orchestrator via `runner.buildMythosOrchestrator`
 *      using real RateLimiter / IdentityLadder / MutationJournal / canaries.
 *   3. Run `MythosExplorationSubLane.run()` through that orchestrator with
 *      global.fetch stubbed.
 *   4. Assert that the probe was executed through the orchestrator, the
 *      `onNonHypothesisProbe` counter incremented (probe path was not in
 *      the initial hypothesis set), and the rate limiter was charged.
 *
 * This is a deliberately narrow integration test: the Mythos prompt,
 * orchestrator binding, worker-tool parser, and live-replay batch are all
 * exercised end-to-end, but no real model or network is involved.
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
import {
  IdentityLadder,
  RateLimiter,
  MutationJournal,
  MythosExplorationSubLane,
  DEFAULT_MYTHOS_CONFIG,
  type CanarySpec,
  type IdentitySpec,
} from '../../verification/local-live/index.js';
import { EvidenceStore } from '../../../../evidence-plane/src/store.js';
import { createEmptyMemory } from '../contracts.js';

class ScriptedAdapter implements ModelAdapter {
  readonly provider = 'test';
  readonly model = 'mythos-scripted';
  public prompts: string[] = [];
  constructor(private readonly response: string) {}
  async invoke<T = unknown>(options: InvokeOptions<T>): Promise<ModelResponse<T>> {
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

function buildLiveTarget(repoRoot: string): InvestigationTarget {
  return {
    id: 'mythos-test',
    kind: 'http',
    environment: 'local',
    baseUrl: 'http://localhost:9999',
    repoRoot,
    supportedProbeKinds: ['http_request'],
    identities: [{ id: 'anonymous', kind: 'anonymous' }],
    hints: {},
  } as unknown as InvestigationTarget;
}

test('Section 6.2 — Mythos sub-lane invents non-hypothesis probes via worker orchestrator', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-mythos-'));
  try {
    // The scripted worker returns a submitProbe tool call hitting a path
    // that is NOT in the initial hypothesis set (which only knows
    // /api/reports/1). The orchestrator must therefore count this as a
    // non-hypothesis probe.
    const workerResponse = JSON.stringify({
      reasoning: 'chase the admin surface the hypothesis list missed',
      toolCalls: [
        {
          kind: 'submitProbe',
          findingId: 'mythos-invented',
          hypothesis: 'admin surface may be reachable anonymously',
          identityId: 'anonymous',
          rationale: 'admin routes are usually worth a look',
          http: { method: 'GET', path: '/admin/users' },
        },
        {
          kind: 'submitHypothesis',
          description: 'Admin surface exposed without auth',
          severity: 'high',
          sourceRefs: ['src/handlers/admin.ts:10-40'],
        },
      ],
    });
    const adapter = new ScriptedAdapter(workerResponse);

    const runner = new InvestigationRunner({
      targetRef: 'unused',
      mode: 'declared',
      plannerAdapter: adapter,
      judgeAdapter: adapter,
      maxIterations: 0,
      maxCostUsd: 1,
      campaignDir: join(root, 'campaigns'),
      runMode: 'smoke',
    });

    const liveTarget = buildLiveTarget(root);
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
    const evidenceStore = new EvidenceStore(`mythos-${Date.now()}`, join(root, 'runs'));
    const memory = createEmptyMemory('mythos-integration');

    // Only /api/reports/1 is in the hypothesis set so /admin/users
    // must be classified as a non-hypothesis probe.
    const initialHypothesisPaths = new Set<string>(['GET /api/reports/1']);
    let nonHypothesisCount = 0;

    const orchestrator = runner.buildMythosOrchestrator({
      campaignId: 'mythos-integration',
      liveTarget,
      rateLimiter,
      identityLadder,
      mutationJournal,
      canaries,
      allowMutations: false,
      liveReplayEventHandler: () => undefined,
      evidenceStore,
      probeBudget: 5,
      timeDeadline: Date.now() + 60_000,
      memory,
      initialHypothesisPaths,
      onNonHypothesisProbe: () => {
        nonHypothesisCount += 1;
      },
    });

    // Stub fetch so the worker-driven probe lands on a deterministic response.
    const originalFetch = globalThis.fetch;
    const calledUrls: string[] = [];
    globalThis.fetch = (async (input: unknown) => {
      calledUrls.push(typeof input === 'string' ? input : String(input));
      return new Response('{"users":[{"id":1}]}', {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as typeof fetch;

    const remainingBefore = rateLimiter.getRemainingBudget();
    try {
      const subLane = new MythosExplorationSubLane(adapter, () => orchestrator);
      const result = await subLane.run({
        campaignId: 'mythos-integration',
        hypotheses: [
          {
            id: 'hyp-reports',
            description: 'Tenant isolation bypass on /api/reports/:id',
            status: 'proposed',
            severity: 'high',
          },
        ],
        probeHistory: [
          {
            probeId: 'live-1',
            method: 'GET',
            path: '/api/reports/1',
            status: 200,
            verdict: 'inconclusive',
            origin: 'hypothesis',
          },
        ],
        repoRoot: root,
        baseUrl: liveTarget.baseUrl!,
        config: { ...DEFAULT_MYTHOS_CONFIG, enabled: true, probeBudget: 5 },
      });

      // Assertions:
      assert.equal(result.invoked, true, 'sub-lane was invoked');
      assert.equal(
        result.probesExecuted.length,
        1,
        'one worker-driven probe was executed',
      );
      assert.equal(
        result.hypothesesProposed.length,
        1,
        'worker-proposed hypothesis recorded',
      );
      assert.equal(nonHypothesisCount, 1, 'probe was counted as non-hypothesis');
      assert.equal(calledUrls.length, 1, 'fetch was called once for the invented probe');
      assert.ok(
        calledUrls[0]!.includes('/admin/users'),
        'orchestrator routed the probe to the worker-chosen path',
      );
      assert.equal(
        rateLimiter.getRemainingBudget(),
        remainingBefore - 1,
        'rate limiter budget was charged for the Mythos probe',
      );
      assert.equal(memory.hypotheses.length, 1, 'submitHypothesis wrote into memory.hypotheses');
      assert.equal(memory.hypotheses[0]!.description, 'Admin surface exposed without auth');
      // Worker prompt should carry the hypothesis snapshot and probe
      // history so the creative lane has context beyond the system prompt.
      const prompt = adapter.prompts.at(-1) ?? '';
      assert.ok(
        prompt.includes('hyp-reports'),
        'worker prompt surfaces existing hypotheses',
      );
      assert.ok(
        prompt.includes('/api/reports/1'),
        'worker prompt surfaces probe history',
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
