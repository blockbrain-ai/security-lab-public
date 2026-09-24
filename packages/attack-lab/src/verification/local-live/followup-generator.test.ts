import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { generateFollowupProbes, type FollowupGenerationContext } from './followup-generator.js';
import type { ModelAdapter, InvokeOptions, ModelResponse } from '../../providers/contracts.js';
import type { LiveExecutionResult, LiveProbeRequest } from './contracts.js';
import type { ResponseSurpriseClassification } from './response-surprise.js';

function buildAdapter(content: string): ModelAdapter {
  return {
    provider: 'test',
    model: 'mock',
    async invoke<T = unknown>(_options: InvokeOptions<T>): Promise<ModelResponse<T>> {
      return {
        content,
        usage: { inputTokens: 10, outputTokens: 10, costUsd: 0 },
        durationMs: 1,
        provider: 'test',
        model: 'mock',
      };
    },
  };
}

function buildContext(): FollowupGenerationContext {
  const originalProbe: LiveProbeRequest = {
    findingId: 'f-1',
    hypothesis: 'potential IDOR on /api/reports/{id}',
    probeKind: 'http',
    identityId: 'user_a_low',
    http: { method: 'GET', path: '/api/reports/1' },
  };
  const result: LiveExecutionResult = {
    probeId: 'live-f-1-1',
    findingId: 'f-1',
    identityId: 'user_a_low',
    request: {
      method: 'GET',
      url: 'http://localhost/api/reports/1',
      headers: {},
    },
    response: {
      status: 500,
      headers: {},
      body: 'Traceback (most recent call last):\n  File "/home/app/reports.py", line 11',
      durationMs: 120,
    },
    rollbackExecuted: false,
    verdict: 'inconclusive',
    reasoning: 'surprising',
  };
  const classification: ResponseSurpriseClassification = {
    verdict: 'surprising',
    reasons: ['stack trace'],
    indicators: {
      statusMismatch: true,
      errorLeakage: true,
      anomalousLatency: false,
      canaryMatched: 'unknown',
    },
  };
  return {
    originalProbe,
    result,
    classification,
    hypothesis: originalProbe.hypothesis,
    findingId: originalProbe.findingId,
    availableIdentities: ['anonymous', 'user_a_low', 'user_b_low'],
    relatedAssets: ['/api/reports'],
    maxFollowups: 3,
  };
}

describe('generateFollowupProbes', () => {
  it('parses a model-produced JSON envelope into probe specs', async () => {
    const adapter = buildAdapter(
      '```json\n' + JSON.stringify({
        probes: [
          {
            probeKind: 'http',
            identityId: 'user_b_low',
            http: { method: 'GET', path: '/api/reports/2' },
            rationale: 'sibling id probe',
          },
          {
            probeKind: 'http',
            identityId: 'anonymous',
            http: { method: 'GET', path: '/api/reports' },
            rationale: 'list endpoint probe',
          },
        ],
        reasoning: 'explore neighbour ids',
      }) + '\n```',
    );

    const result = await generateFollowupProbes(buildContext(), adapter);

    assert.equal(result.source, 'model');
    assert.equal(result.probes.length, 2);
    assert.equal(result.probes[0]!.http!.path, '/api/reports/2');
    assert.equal(result.probes[0]!.identityId, 'user_b_low');
    assert.equal(result.probes[0]!.findingId, 'f-1');
  });

  it('keeps valid follow-ups when a local-model response mixes malformed and executable probes', async () => {
    const adapter = buildAdapter([
      'I found one concrete path worth testing.',
      '```json',
      JSON.stringify({
        probes: [
          {
            probeKind: 'http',
            identityId: 'anonymous',
            http: { method: 'GET' },
          },
          {
            probeKind: 'http',
            identityId: 'user_b_low',
            http: {
              method: 'post',
              path: '/api/reports/2/share',
              headers: { 'x-retry': 1 },
              body: { id: 2 },
            },
            rationale: 'exercise the sharing path',
          },
        ],
        reasoning: 'ignore the incomplete probe and fire the second one.',
      }),
      '```',
    ].join('\n'));

    const result = await generateFollowupProbes(buildContext(), adapter);

    assert.equal(result.source, 'model');
    assert.equal(result.probes.length, 1);
    assert.equal(result.probes[0]!.http!.method, 'POST');
    assert.equal(result.probes[0]!.http!.path, '/api/reports/2/share');
    assert.deepEqual(result.probes[0]!.http!.headers, { 'x-retry': '1' });
    assert.equal(result.probes[0]!.http!.body, '{"id":2}');
  });

  it('falls back to deterministic probes when adapter is missing', async () => {
    const result = await generateFollowupProbes(buildContext(), undefined);
    assert.equal(result.source, 'deterministic');
    assert.ok(result.probes.length >= 1);
    assert.ok(result.probes.every((probe) => probe.findingId === 'f-1'));
    assert.ok(result.probes.some((probe) => probe.http?.method === 'HEAD'));
  });

  it('falls back when the adapter returns a non-JSON response', async () => {
    const adapter = buildAdapter('no JSON here — sorry');
    const result = await generateFollowupProbes(buildContext(), adapter);
    assert.equal(result.source, 'deterministic');
    assert.ok(result.probes.length >= 1);
  });

  it('respects the maxFollowups budget', async () => {
    const adapter = buildAdapter(
      '```json\n' + JSON.stringify({
        probes: [
          { probeKind: 'http', identityId: 'anonymous', http: { method: 'GET', path: '/a' } },
          { probeKind: 'http', identityId: 'anonymous', http: { method: 'GET', path: '/b' } },
          { probeKind: 'http', identityId: 'anonymous', http: { method: 'GET', path: '/c' } },
          { probeKind: 'http', identityId: 'anonymous', http: { method: 'GET', path: '/d' } },
        ],
      }) + '\n```',
    );
    const ctx = { ...buildContext(), maxFollowups: 2 };
    const result = await generateFollowupProbes(ctx, adapter);
    assert.equal(result.probes.length, 2);
  });

  it('redacts bearer tokens in the prompt body input', async () => {
    let observedPrompt = '';
    const adapter: ModelAdapter = {
      provider: 'test',
      model: 'mock',
      async invoke<T = unknown>(options: InvokeOptions<T>): Promise<ModelResponse<T>> {
        observedPrompt = options.prompt;
        return {
          content: '{"probes":[]}',
          usage: { inputTokens: 1, outputTokens: 1, costUsd: 0 },
          durationMs: 1,
          provider: 'test',
          model: 'mock',
        };
      },
    };
    const ctx = buildContext();
    ctx.result.response.body = 'Authorization: Bearer ABC.DEF.GHI-token-xyz';
    await generateFollowupProbes(ctx, adapter);
    assert.ok(!observedPrompt.includes('ABC.DEF.GHI-token-xyz'), 'token should be redacted');
    assert.ok(observedPrompt.includes('[redacted-token]'));
  });
});
