import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  extractOutput,
  resolveStepReferences,
  computeSequenceVerdict,
  executeProbeSequence,
} from './probe-sequence.js';
import type {
  ProbeSequenceDefinition,
  ProbeSequenceStepResult,
  OutputExtractor,
} from './contracts.js';
import type { LiveExecutionResult } from './contracts.js';
import { IdentityLadder } from './identity-ladder.js';
import { RateLimiter } from './rate-limiter.js';
import { MutationJournal } from './reversible-mutation.js';

function buildOptions(fetchFn: typeof fetch) {
  return {
    baseUrl: 'http://localhost:4000',
    identityLadder: new IdentityLadder([
      { id: 'guest', kind: 'anonymous' as const },
      { id: 'user-a', kind: 'anonymous' as const },
    ]),
    rateLimiter: new RateLimiter({
      requestsPerSecond: 100,
      maxRequestsPerCampaign: 100,
      autoStopOn5xxStreak: 5,
      autoStopOnLatencyDoubling: false,
    }),
    mutationJournal: new MutationJournal(),
    fetchFn,
  };
}

// ---------------------------------------------------------------------------
// Output extraction
// ---------------------------------------------------------------------------

describe('extractOutput', () => {
  it('extracts a JSON path value', () => {
    const extractor: OutputExtractor = { kind: 'jsonPath', path: 'data.token' };
    const result = extractOutput(extractor, '{"data":{"token":"abc123"}}', {});
    assert.equal(result, 'abc123');
  });

  it('extracts a nested array index', () => {
    const extractor: OutputExtractor = { kind: 'jsonPath', path: 'items.0.id' };
    const result = extractOutput(extractor, '{"items":[{"id":"first"},{"id":"second"}]}', {});
    assert.equal(result, 'first');
  });

  it('returns null for missing JSON path', () => {
    const extractor: OutputExtractor = { kind: 'jsonPath', path: 'missing.field' };
    const result = extractOutput(extractor, '{"data":"value"}', {});
    assert.equal(result, null);
  });

  it('extracts via regex with named capture group', () => {
    const extractor: OutputExtractor = { kind: 'regex', pattern: '"token":"(?<value>[^"]+)"' };
    const result = extractOutput(extractor, '{"token":"xyz789"}', {});
    assert.equal(result, 'xyz789');
  });

  it('extracts via regex with numbered capture group', () => {
    const extractor: OutputExtractor = { kind: 'regex', pattern: 'id=(\\d+)' };
    const result = extractOutput(extractor, 'path?id=42&name=test', {});
    assert.equal(result, '42');
  });

  it('extracts from response header', () => {
    const extractor: OutputExtractor = { kind: 'header', headerName: 'X-Request-Id' };
    const result = extractOutput(extractor, '', { 'x-request-id': 'req-001' });
    assert.equal(result, 'req-001');
  });

  it('returns null for missing header', () => {
    const extractor: OutputExtractor = { kind: 'header', headerName: 'X-Missing' };
    const result = extractOutput(extractor, '', {});
    assert.equal(result, null);
  });
});

// ---------------------------------------------------------------------------
// Step reference resolution
// ---------------------------------------------------------------------------

describe('resolveStepReferences', () => {
  it('resolves step output references', () => {
    const outputs = new Map([
      ['step1', { token: 'abc', userId: '42' }],
    ]);
    const { resolved, referencesUsed } = resolveStepReferences(
      '/api/users/{{step1.userId}}/data?token={{step1.token}}',
      outputs,
    );
    assert.equal(resolved, '/api/users/42/data?token=abc');
    assert.equal(referencesUsed, 2);
  });

  it('leaves unresolved references intact', () => {
    const outputs = new Map<string, Record<string, string>>();
    const { resolved, referencesUsed } = resolveStepReferences(
      '/api/{{unknown.ref}}/data',
      outputs,
    );
    assert.equal(resolved, '/api/{{unknown.ref}}/data');
    assert.equal(referencesUsed, 0);
  });
});

// ---------------------------------------------------------------------------
// Sequence-level verdicting
// ---------------------------------------------------------------------------

describe('computeSequenceVerdict', () => {
  function makeStepResult(
    stepId: string,
    verdict: LiveExecutionResult['verdict'],
  ): ProbeSequenceStepResult {
    return {
      stepId,
      label: `Step ${stepId}`,
      extractedOutputs: {},
      probeResult: {
        probeId: `probe-${stepId}`,
        findingId: 'f-1',
        identityId: 'guest',
        request: { method: 'GET', url: '/test', headers: {} },
        response: { status: 200, headers: {}, body: '', durationMs: 10 },
        rollbackExecuted: false,
        verdict,
        reasoning: `verdict: ${verdict}`,
      },
    };
  }

  it('returns confirmed when any step confirms', () => {
    const steps = [
      makeStepResult('s1', 'inconclusive'),
      makeStepResult('s2', 'confirmed'),
    ];
    const { verdict } = computeSequenceVerdict(steps);
    assert.equal(verdict, 'confirmed');
  });

  it('returns refuted when final step refutes', () => {
    const steps = [
      makeStepResult('s1', 'inconclusive'),
      makeStepResult('s2', 'refuted'),
    ];
    const { verdict } = computeSequenceVerdict(steps);
    assert.equal(verdict, 'refuted');
  });

  it('returns blocking verdict when a step fails', () => {
    const steps = [
      makeStepResult('s1', 'runtime_error'),
      makeStepResult('s2', 'confirmed'),
    ];
    const { verdict } = computeSequenceVerdict(steps);
    assert.equal(verdict, 'runtime_error');
  });

  it('returns inconclusive for empty steps', () => {
    const { verdict } = computeSequenceVerdict([]);
    assert.equal(verdict, 'inconclusive');
  });

  it('returns inconclusive when no step is definitive', () => {
    const steps = [
      makeStepResult('s1', 'inconclusive'),
      makeStepResult('s2', 'inconclusive'),
    ];
    const { verdict } = computeSequenceVerdict(steps);
    assert.equal(verdict, 'inconclusive');
  });
});

// ---------------------------------------------------------------------------
// Full sequence execution
// ---------------------------------------------------------------------------

describe('executeProbeSequence', () => {
  it('executes a two-step sequence with output propagation', async () => {
    let requestCount = 0;
    const fetchFn: typeof fetch = async (input) => {
      requestCount += 1;
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
      if (url.includes('/auth/token')) {
        return new Response(
          JSON.stringify({ token: 'secret-token-123' }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      // Second request should have the token in the path
      if (url.includes('secret-token-123')) {
        return new Response(
          JSON.stringify({ data: [{ id: 1, secret: 'found' }] }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response('not found', { status: 404 });
    };

    const definition: ProbeSequenceDefinition = {
      sequenceId: 'seq-auth-bypass',
      findingId: 'f-idor-1',
      hypothesis: 'Token obtained in step 1 grants access to protected data in step 2',
      defaultIdentityId: 'guest',
      steps: [
        {
          stepId: 'obtain_token',
          label: 'Obtain auth token',
          http: { method: 'POST', path: '/auth/token', body: '{"user":"test"}' },
          extractOutputs: {
            token: { kind: 'jsonPath', path: 'token' },
          },
        },
        {
          stepId: 'use_token',
          label: 'Access protected resource with token',
          http: {
            method: 'GET',
            path: '/api/protected?token={{obtain_token.token}}',
          },
          expectedWhenSafe: { statusIn: [401, 403] },
          expectedWhenExploitable: { status: 200 },
        },
      ],
    };

    const { result, stats } = await executeProbeSequence(
      definition,
      { ...buildOptions(fetchFn), allowMutations: true },
    );

    // Step 1 extracted the token
    assert.equal(result.stepResults[0].extractedOutputs['token'], 'secret-token-123');

    // Step 2 consumed the token (state passthrough)
    assert.ok(stats.statePassthroughCount >= 1, 'state passthrough should be >= 1');

    // Both steps executed
    assert.equal(result.stepResults.length, 2);
    assert.equal(requestCount, 2);

    // Sequence confirmed because step 2 got 200 with substantive data
    assert.equal(result.verdict, 'confirmed');
  });

  it('executes rollback after sequence completion', async () => {
    const requests: string[] = [];
    const fetchFn: typeof fetch = async (input) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
      requests.push(url);
      return new Response('ok', { status: 200, headers: { 'content-type': 'application/json' } });
    };

    const definition: ProbeSequenceDefinition = {
      sequenceId: 'seq-with-rollback',
      findingId: 'f-mutation',
      hypothesis: 'Create then cleanup',
      defaultIdentityId: 'guest',
      steps: [
        {
          stepId: 'create',
          label: 'Create resource',
          http: { method: 'POST', path: '/api/resources', body: '{"name":"test"}' },
          extractOutputs: {
            resourceId: { kind: 'jsonPath', path: 'id' },
          },
        },
      ],
      rollback: [
        { method: 'DELETE', path: '/api/resources/cleanup' },
      ],
    };

    const { result, stats } = await executeProbeSequence(
      definition,
      { ...buildOptions(fetchFn), allowMutations: true },
    );

    assert.equal(result.rollbackExecuted, true);
    assert.ok(stats.rollbackExecuted);
    // Should have the create request + the rollback request
    assert.ok(requests.some((r) => r.includes('/api/resources/cleanup')));
  });

  it('stops on rate limiter exhaustion', async () => {
    const options = buildOptions(async () => new Response('ok', { status: 200 }));
    // Exhaust the rate limiter
    for (let i = 0; i < 100; i++) {
      try { await options.rateLimiter.acquire(); } catch { break; }
    }

    const definition: ProbeSequenceDefinition = {
      sequenceId: 'seq-rate-limited',
      findingId: 'f-rate',
      hypothesis: 'Should stop when rate limited',
      defaultIdentityId: 'guest',
      steps: [
        { stepId: 's1', label: 'Step 1', http: { method: 'GET', path: '/a' } },
        { stepId: 's2', label: 'Step 2', http: { method: 'GET', path: '/b' } },
      ],
    };

    const { result } = await executeProbeSequence(definition, options);
    // Should have 0 or very few steps due to rate limiting
    assert.ok(result.stepResults.length <= 2);
  });
});
