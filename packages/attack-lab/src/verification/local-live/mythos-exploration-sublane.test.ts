/**
 * Section 6.2 — MythosExplorationSubLane tests.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  MythosExplorationSubLane,
  DEFAULT_MYTHOS_CONFIG,
  buildMythosPrompt,
  type MythosSubLaneContext,
} from './mythos-exploration-sublane.js';
import type { ModelAdapter, ModelResponse, InvokeOptions } from '../../providers/contracts.js';
import type { LiveExecutionResult, LiveProbeRequest } from './contracts.js';
import type { WorkerToolOrchestrator } from './worker-tools.js';

function buildResult(path: string): LiveExecutionResult {
  return {
    probeId: `mythos-${path}`,
    findingId: 'mythos',
    identityId: 'anonymous',
    origin: 'adaptive',
    request: { method: 'GET', url: `http://localhost${path}`, headers: {} },
    response: { status: 200, headers: {}, body: '', durationMs: 1 },
    rollbackExecuted: false,
    verdict: 'inconclusive',
    reasoning: 'mock',
  };
}

class RecordingOrchestrator implements WorkerToolOrchestrator {
  public executed: LiveProbeRequest[] = [];
  public hypotheses: unknown[] = [];
  public findings: unknown[] = [];
  public budget = 20;
  constructor(private readonly deadline = Number.POSITIVE_INFINITY) {}
  async executeProbe(probe: LiveProbeRequest): Promise<LiveExecutionResult> {
    this.executed.push(probe);
    this.budget -= 1;
    return buildResult(probe.http?.path ?? '/');
  }
  async submitHypothesis(h: unknown): Promise<void> {
    this.hypotheses.push(h);
  }
  async submitFinding(f: unknown): Promise<{ accepted: boolean; reason?: string }> {
    this.findings.push(f);
    return { accepted: true };
  }
  getRemainingProbeBudget(): number {
    return this.budget;
  }
  isTimeExhausted(): boolean {
    return Date.now() > this.deadline;
  }
}

class StubAdapter implements ModelAdapter {
  readonly provider = 'test';
  readonly model = 'mythos-stub';
  public lastPrompt: string | null = null;
  constructor(private readonly response: string) {}
  async invoke<T = unknown>(options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    this.lastPrompt = options.prompt;
    return {
      content: this.response,
      usage: { inputTokens: 0, outputTokens: 0, costUsd: 0 },
      durationMs: 0,
      provider: this.provider,
      model: this.model,
    };
  }
}

function buildContext(overrides: Partial<MythosSubLaneContext> = {}): MythosSubLaneContext {
  return {
    campaignId: 'camp-1',
    hypotheses: [
      { id: 'hyp-1', description: 'tenant bypass on /api/reports', status: 'tested' },
    ],
    probeHistory: [
      { probeId: 'p-1', method: 'GET', path: '/api/reports/1', status: 500, verdict: 'inconclusive' },
    ],
    repoRoot: '/tmp/repo',
    baseUrl: 'http://localhost:9999',
    config: { ...DEFAULT_MYTHOS_CONFIG, enabled: true, probeBudget: 20, timeBudgetMs: 60_000 },
    ...overrides,
  };
}

test('Section 6.2 — Mythos sub-lane invents a non-hypothesis probe and runs it', async () => {
  const adapter = new StubAdapter(
    JSON.stringify({
      reasoning: 'inventing a new angle',
      toolCalls: [
        {
          kind: 'submitProbe',
          findingId: 'mythos-invented',
          hypothesis: 'debug endpoint exposed',
          identityId: 'anonymous',
          http: { method: 'GET', path: '/internal/debug' },
          rationale: 'nothing in the hypothesis list covers /internal/*',
        },
        {
          kind: 'submitHypothesis',
          description: 'debug endpoints under /internal are unauthenticated',
          severity: 'high',
          sourceRefs: ['src/routes/internal.ts:10-80'],
        },
      ],
    }),
  );
  const orchestrator = new RecordingOrchestrator();
  const lane = new MythosExplorationSubLane(adapter, () => orchestrator);
  const result = await lane.run(buildContext());
  assert.equal(result.invoked, true);
  assert.equal(result.probesExecuted.length, 1);
  assert.equal(orchestrator.executed.length, 1);
  assert.equal(orchestrator.executed[0]!.http!.path, '/internal/debug');
  assert.equal(result.hypothesesProposed.length, 1);
  assert.ok(result.hypothesesProposed[0]!.sourceRefs.includes('src/routes/internal.ts:10-80'));
});

test('Section 6.2 — disabled sub-lane exits early', async () => {
  const adapter = new StubAdapter('{}');
  const lane = new MythosExplorationSubLane(adapter, () => new RecordingOrchestrator());
  const result = await lane.run(
    buildContext({ config: { ...DEFAULT_MYTHOS_CONFIG, enabled: false } }),
  );
  assert.equal(result.invoked, false);
  assert.equal(result.reason, 'mythos disabled');
});

test('Section 6.2 — absent adapter exits early', async () => {
  const lane = new MythosExplorationSubLane(undefined, () => new RecordingOrchestrator());
  const result = await lane.run(buildContext());
  assert.equal(result.invoked, false);
  assert.equal(result.reason, 'no worker adapter available');
});

test('Section 6.2 — probe budget cut off produces budget_exhausted result', async () => {
  const adapter = new StubAdapter(
    JSON.stringify({
      toolCalls: [
        { kind: 'submitProbe', findingId: 'f', hypothesis: 'h', identityId: 'anonymous', http: { method: 'GET', path: '/a' } },
        { kind: 'submitProbe', findingId: 'f', hypothesis: 'h', identityId: 'anonymous', http: { method: 'GET', path: '/b' } },
      ],
    }),
  );
  const orchestrator = new RecordingOrchestrator();
  orchestrator.budget = 1;
  const lane = new MythosExplorationSubLane(adapter, () => orchestrator);
  const result = await lane.run(buildContext({ config: { ...DEFAULT_MYTHOS_CONFIG, enabled: true, probeBudget: 1, timeBudgetMs: 60_000 } }));
  assert.equal(result.probesExecuted.length, 1);
  assert.equal(result.budgetExhausted, 'probe_budget_exhausted');
});

test('Section 6.2 — prompt surfaces hypotheses, probe history, and budgets', () => {
  const prompt = buildMythosPrompt(buildContext());
  assert.match(prompt, /hyp-1/);
  assert.match(prompt, /\/api\/reports\/1/);
  assert.match(prompt, /Time budget/);
  assert.match(prompt, /http:\/\/localhost:9999/);
});
