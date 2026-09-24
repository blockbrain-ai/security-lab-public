/**
 * Section 6.2 — SourceCorrelationWorker tests.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  SourceCorrelationBudget,
  SourceCorrelationWorker,
  buildSourceCorrelationPrompt,
} from './source-correlation-worker.js';
import type { ModelAdapter, ModelResponse, InvokeOptions } from '../../providers/contracts.js';
import type { LiveExecutionResult } from './contracts.js';

class StubAdapter implements ModelAdapter {
  readonly provider = 'test';
  readonly model = 'stub';
  public lastOptions: InvokeOptions<unknown> | null = null;

  constructor(private readonly response: string) {}

  async invoke<T = unknown>(options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    this.lastOptions = options;
    return {
      content: this.response,
      usage: { inputTokens: 0, outputTokens: 0, costUsd: 0 },
      durationMs: 0,
      provider: this.provider,
      model: this.model,
    };
  }
}

function buildProbeResult(): LiveExecutionResult {
  return {
    probeId: 'p1',
    findingId: 'f1',
    identityId: 'anonymous',
    origin: 'hypothesis',
    request: { method: 'GET', url: 'http://localhost/api/reports/1', headers: {} },
    response: { status: 500, headers: {}, body: 'Traceback', durationMs: 10 },
    rollbackExecuted: false,
    verdict: 'confirmed',
    reasoning: 'ok',
  };
}

test('Section 6.2 — SourceCorrelationWorker passes repoRoot to the adapter', async () => {
  const adapter = new StubAdapter(
    '```json\n{"sourceRefs":["src/api/reports.ts:10-30"],"analysis":"handler reads reports","consistencyVerdict":"inconsistent","consistencyReasoning":"500 not expected"}\n```',
  );
  const worker = new SourceCorrelationWorker(adapter, new SourceCorrelationBudget(10));
  const result = await worker.correlate({
    probeResult: buildProbeResult(),
    repoRoot: '/tmp/repo',
    hypothesis: 'tenant bypass',
    findingId: 'f1',
  });
  assert.equal(result.source, 'worker');
  assert.deepEqual(result.sourceRefs, ['src/api/reports.ts:10-30']);
  assert.equal(result.consistencyVerdict, 'inconsistent');
  assert.equal(adapter.lastOptions?.workingDirectory, '/tmp/repo');
});

test('Section 6.2 — SourceCorrelationWorker normalizes local-model verdict casing', async () => {
  const adapter = new StubAdapter([
    'The handler lookup is below.',
    '```json',
    '{"sourceRefs":["src/api/reports.ts:10-30"],"analysis":"handler reads reports","consistencyVerdict":"CONSISTENT","consistencyReasoning":"response matches code"}',
    '```',
  ].join('\n'));
  const worker = new SourceCorrelationWorker(adapter, new SourceCorrelationBudget(10));
  const result = await worker.correlate({
    probeResult: buildProbeResult(),
    repoRoot: '/tmp/repo',
    hypothesis: 'tenant bypass',
    findingId: 'f1',
  });

  assert.equal(result.source, 'worker');
  assert.equal(result.consistencyVerdict, 'consistent');
  assert.equal(result.analysis, 'handler reads reports');
});

test('Section 6.2 — budget exhaustion returns disabled result', async () => {
  const adapter = new StubAdapter('{}');
  const worker = new SourceCorrelationWorker(adapter, new SourceCorrelationBudget(1));
  await worker.correlate({
    probeResult: buildProbeResult(),
    repoRoot: '/tmp/repo',
    hypothesis: 'h',
    findingId: 'f',
  });
  const second = await worker.correlate({
    probeResult: buildProbeResult(),
    repoRoot: '/tmp/repo',
    hypothesis: 'h',
    findingId: 'f',
  });
  assert.equal(second.source, 'disabled');
  assert.equal(second.fallbackReason, 'source correlation budget exhausted');
});

test('Section 6.2 — absent adapter returns disabled result', async () => {
  const worker = new SourceCorrelationWorker(undefined, new SourceCorrelationBudget(10));
  const result = await worker.correlate({
    probeResult: buildProbeResult(),
    repoRoot: '/tmp',
    hypothesis: 'h',
    findingId: 'f',
  });
  assert.equal(result.source, 'disabled');
});

test('Section 6.2 — prompt includes request URL and repoRoot', () => {
  const prompt = buildSourceCorrelationPrompt({
    probeResult: buildProbeResult(),
    repoRoot: '/tmp/repo',
    hypothesis: 'tenant bypass',
    findingId: 'f1',
  });
  assert.match(prompt, /GET http:\/\/localhost\/api\/reports\/1/);
  assert.match(prompt, /\/tmp\/repo/);
});

test('Section 6.2 — parse failure falls back with reason', async () => {
  const adapter = new StubAdapter('no json whatsoever');
  const worker = new SourceCorrelationWorker(adapter, new SourceCorrelationBudget(10));
  const result = await worker.correlate({
    probeResult: buildProbeResult(),
    repoRoot: '/tmp',
    hypothesis: 'h',
    findingId: 'f',
  });
  assert.equal(result.source, 'worker');
  assert.ok(result.fallbackReason);
});

// ---------------------------------------------------------------------------
// Section 7.1 — typed SourceLocationRef in CorrelationResult
// ---------------------------------------------------------------------------

test('Section 7.1 — correlation result includes typed sourceLocationRefs', async () => {
  const adapter = new StubAdapter(
    '```json\n{"sourceRefs":["src/api/reports.ts:10-30","src/db/queries.ts:5"],"analysis":"handler reads reports","consistencyVerdict":"consistent","consistencyReasoning":"ok"}\n```',
  );
  const worker = new SourceCorrelationWorker(adapter, new SourceCorrelationBudget(10));
  const result = await worker.correlate({
    probeResult: buildProbeResult(),
    repoRoot: '/tmp/repo',
    hypothesis: 'tenant bypass',
    findingId: 'f1',
  });
  assert.equal(result.sourceLocationRefs.length, 2);
  assert.deepEqual(result.sourceLocationRefs[0], {
    path: 'src/api/reports.ts',
    startLine: 10,
    endLine: 30,
  });
  assert.deepEqual(result.sourceLocationRefs[1], {
    path: 'src/db/queries.ts',
    startLine: 5,
    endLine: undefined,
  });
});

test('Section 7.1 — disabled result has empty sourceLocationRefs', async () => {
  const worker = new SourceCorrelationWorker(undefined, new SourceCorrelationBudget(10));
  const result = await worker.correlate({
    probeResult: buildProbeResult(),
    repoRoot: '/tmp',
    hypothesis: 'h',
    findingId: 'f',
  });
  assert.deepEqual(result.sourceLocationRefs, []);
});

test('Section 7.1 — absolute paths are converted to workspace-relative', async () => {
  const adapter = new StubAdapter(
    '```json\n{"sourceRefs":["/tmp/repo/src/handler.ts:1-10"],"analysis":"ok","consistencyVerdict":"consistent","consistencyReasoning":"ok"}\n```',
  );
  const worker = new SourceCorrelationWorker(adapter, new SourceCorrelationBudget(10));
  const result = await worker.correlate({
    probeResult: buildProbeResult(),
    repoRoot: '/tmp/repo',
    hypothesis: 'h',
    findingId: 'f',
  });
  assert.equal(result.sourceLocationRefs.length, 1);
  assert.equal(result.sourceLocationRefs[0]!.path, 'src/handler.ts');
});
