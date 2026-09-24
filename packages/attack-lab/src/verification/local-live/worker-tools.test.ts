/**
 * Section 6.2 — Tests for the worker tool bindings.
 *
 * Verifies that the three submit tools route correctly through a mock
 * orchestrator, that probe/time budgets cut the loop off cleanly, and that
 * the finding evidence-ref validator mirrors the focused-closure rule.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  bindWorkerTools,
  parseMythosWorkerOutput,
  validateFindingEvidenceRefs,
  type WorkerToolOrchestrator,
  type MythosWorkerOutput,
  type SubmittedFinding,
} from './worker-tools.js';
import type { LiveExecutionResult, LiveProbeRequest } from './contracts.js';

function buildExecutionResult(path: string): LiveExecutionResult {
  return {
    probeId: `mythos-${path}`,
    findingId: 'mythos-finding',
    identityId: 'anonymous',
    origin: 'adaptive',
    request: { method: 'GET', url: `http://localhost${path}`, headers: {} },
    response: { status: 200, headers: {}, body: '', durationMs: 1 },
    rollbackExecuted: false,
    verdict: 'inconclusive',
    reasoning: 'mock',
  };
}

class MockOrchestrator implements WorkerToolOrchestrator {
  public executed: LiveProbeRequest[] = [];
  public hypotheses: unknown[] = [];
  public findings: unknown[] = [];
  public probeBudget: number;
  public timeExhausted = false;
  public findingDecisions: Array<{ accepted: boolean; reason?: string }> = [];

  constructor(probeBudget = 10) {
    this.probeBudget = probeBudget;
  }

  async executeProbe(probe: LiveProbeRequest): Promise<LiveExecutionResult> {
    this.executed.push(probe);
    this.probeBudget -= 1;
    return buildExecutionResult(probe.http?.path ?? '/');
  }

  async submitHypothesis(h: unknown): Promise<void> {
    this.hypotheses.push(h);
  }

  async submitFinding(f: unknown): Promise<{ accepted: boolean; reason?: string }> {
    this.findings.push(f);
    return this.findingDecisions.shift() ?? { accepted: true };
  }

  getRemainingProbeBudget(): number {
    return this.probeBudget;
  }

  isTimeExhausted(): boolean {
    return this.timeExhausted;
  }
}

test('Section 6.2 — bindWorkerTools routes probe calls through the orchestrator', async () => {
  const orchestrator = new MockOrchestrator(5);
  const output: MythosWorkerOutput = {
    toolCalls: [
      {
        kind: 'submitProbe',
        findingId: 'f1',
        hypothesis: 'h',
        identityId: 'anonymous',
        http: { method: 'GET', path: '/invented' },
      },
    ],
  };
  const res = await bindWorkerTools(output, orchestrator, { campaignId: 'c1' });
  assert.equal(orchestrator.executed.length, 1);
  assert.equal(orchestrator.executed[0]!.http!.path, '/invented');
  assert.equal(res.probesExecuted.length, 1);
  assert.equal(res.budgetExhausted, null);
});

test('Section 6.2 — probe budget exhaustion ends the loop cleanly', async () => {
  const orchestrator = new MockOrchestrator(1);
  const output: MythosWorkerOutput = {
    toolCalls: [
      {
        kind: 'submitProbe',
        findingId: 'f1',
        hypothesis: 'h',
        identityId: 'anonymous',
        http: { method: 'GET', path: '/a' },
      },
      {
        kind: 'submitProbe',
        findingId: 'f1',
        hypothesis: 'h',
        identityId: 'anonymous',
        http: { method: 'GET', path: '/b' },
      },
    ],
  };
  const res = await bindWorkerTools(output, orchestrator, { campaignId: 'c1' });
  assert.equal(res.probesExecuted.length, 1);
  assert.equal(res.budgetExhausted, 'probe_budget_exhausted');
});

test('Section 6.2 — time exhaustion halts before the next call', async () => {
  const orchestrator = new MockOrchestrator(5);
  orchestrator.timeExhausted = true;
  const output: MythosWorkerOutput = {
    toolCalls: [
      {
        kind: 'submitProbe',
        findingId: 'f1',
        hypothesis: 'h',
        identityId: 'anonymous',
        http: { method: 'GET', path: '/a' },
      },
    ],
  };
  const res = await bindWorkerTools(output, orchestrator, { campaignId: 'c1' });
  assert.equal(res.probesExecuted.length, 0);
  assert.equal(res.budgetExhausted, 'time_budget_exhausted');
});

test('Section 6.2 — submitHypothesis + submitFinding route to orchestrator', async () => {
  const orchestrator = new MockOrchestrator(5);
  const output: MythosWorkerOutput = {
    toolCalls: [
      {
        kind: 'submitHypothesis',
        description: 'new angle',
        severity: 'high',
      },
      {
        kind: 'submitFinding',
        description: 'finding',
        severity: 'medium',
        reproductionSteps: ['step'],
        remediationSuggestion: 'fix',
        evidenceRefs: ['artifact:src/handler.ts:10-20'],
      },
    ],
  };
  const res = await bindWorkerTools(output, orchestrator, { campaignId: 'campaign-1234' });
  assert.equal(res.hypothesesSubmitted.length, 1);
  assert.match(res.hypothesesSubmitted[0]!.id, /^hyp-mythos-/);
  assert.equal(res.findingsAccepted.length, 1);
});

test('Section 6.2 — parseMythosWorkerOutput handles fenced JSON and malformed input', () => {
  const good = parseMythosWorkerOutput('```json\n{"toolCalls":[]}\n```');
  assert.equal(good.error, undefined);
  assert.equal(good.output.toolCalls.length, 0);

  const bad = parseMythosWorkerOutput('no json here');
  assert.ok(bad.error);
  assert.equal(bad.output.toolCalls.length, 0);
});

test('Section 6.2 — parseMythosWorkerOutput tolerates prose and lower-case HTTP methods', () => {
  const parsed = parseMythosWorkerOutput([
    'One useful action follows.',
    '```json',
    JSON.stringify({
      toolCalls: [
        {
          kind: 'submitProbe',
          findingId: 'f1',
          hypothesis: 'h',
          identityId: 'anonymous',
          http: {
            method: 'get',
            path: '/invented',
            headers: { 'x-retry': 1 },
          },
        },
      ],
      reasoning: 'try the undocumented route',
    }),
    '```',
  ].join('\n'));

  assert.equal(parsed.error, undefined);
  assert.equal(parsed.output.toolCalls.length, 1);
  const firstCall = parsed.output.toolCalls[0];
  assert.equal(firstCall?.kind, 'submitProbe');
  assert.equal(firstCall && 'http' in firstCall ? firstCall.http.method : undefined, 'GET');
  assert.deepEqual(firstCall && 'http' in firstCall ? firstCall.http.headers : undefined, { 'x-retry': '1' });
});

test('Section 6.2 — validateFindingEvidenceRefs enforces the focused-closure rule', () => {
  const finding: SubmittedFinding = {
    description: 'x',
    severity: 'high',
    reproductionSteps: ['s'],
    remediationSuggestion: 'r',
    evidenceRefs: ['unknown'],
    sourceRefs: [],
  };
  const bad = validateFindingEvidenceRefs(finding, new Set());
  assert.ok(bad);

  const ok = validateFindingEvidenceRefs(
    { ...finding, evidenceRefs: ['artifact:foo'] },
    new Set(),
  );
  assert.equal(ok, null);

  const viaProbeSet = validateFindingEvidenceRefs(
    { ...finding, evidenceRefs: ['mythos-abc'] },
    new Set(['mythos-abc']),
  );
  assert.equal(viaProbeSet, null);
});
