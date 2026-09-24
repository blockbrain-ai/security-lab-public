import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { executeLiveProbe } from './live-replay.js';
import { IdentityLadder } from './identity-ladder.js';
import { RateLimiter } from './rate-limiter.js';
import { MutationJournal } from './reversible-mutation.js';

function buildOptions(fetchFn: typeof fetch) {
  return {
    baseUrl: 'http://localhost:4000',
    identityLadder: new IdentityLadder([{ id: 'guest', kind: 'anonymous' }]),
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

test('executeLiveProbe refutes a translated probe when the safe expectation matches', async () => {
  const result = await executeLiveProbe({
    findingId: 'finding-safe',
    hypothesis: 'Guest should not read the admin route.',
    probeKind: 'http',
    identityId: 'guest',
    http: {
      method: 'GET',
      path: '/api/v1/admin/agents',
    },
    expectedWhenSafe: { statusIn: [401, 403] },
    expectedWhenExploitable: { status: 200 },
  }, buildOptions(async () => new Response('forbidden', { status: 403 })));

  assert.equal(result.verdict, 'refuted');
  assert.equal(result.canaryMatched, 'safe');
});

test('executeLiveProbe confirms a translated probe when the exploitable expectation matches', async () => {
  const result = await executeLiveProbe({
    findingId: 'finding-confirmed',
    hypothesis: 'Guest should not read the admin route.',
    probeKind: 'http',
    identityId: 'guest',
    http: {
      method: 'GET',
      path: '/api/v1/admin/agents',
    },
    expectedWhenSafe: { statusIn: [401, 403] },
    expectedWhenExploitable: { status: 200 },
  }, buildOptions(async () => new Response(
    JSON.stringify({ agents: [{ id: 'a1', name: 'admin-agent' }] }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  )));

  assert.equal(result.verdict, 'confirmed');
  assert.equal(result.canaryMatched, 'exploitable');
  // Section 11.3 — classification details attached
  assert.equal(result.classification?.reason, 'response_shape_match');
  assert.equal(result.classification?.routeKind, 'json_api');
});

test('executeLiveProbe degrades missing identity to coverage_gap verdict (Section 3.1)', async () => {
  const events: Array<{ stage: string; payload: Record<string, unknown> }> = [];
  const options = buildOptions(async () => new Response('ok', { status: 200 }));
  const result = await executeLiveProbe(
    {
      findingId: 'finding-missing-id',
      hypothesis: 'Probe needs a tenant_a identity that is not configured.',
      probeKind: 'http',
      identityId: 'tenant_a',
      http: { method: 'GET', path: '/api/v1/resource' },
    },
    {
      ...options,
      onEvent: (stage, payload) =>
        events.push({ stage, payload: payload as unknown as Record<string, unknown> }),
    },
  );

  assert.equal(result.verdict, 'coverage_gap');
  assert.match(result.reasoning, /coverage gap/);
  const gap = events.find((e) => e.stage === 'coverage_gap');
  assert.ok(gap, 'coverage_gap event emitted');
  assert.equal(gap?.payload.code, 'identity_missing');
});

test('executeLiveProbe returns auth_failed on missing identity when strictProbes is set (legacy)', async () => {
  const result = await executeLiveProbe(
    {
      findingId: 'finding-missing-strict',
      hypothesis: 'strict mode reverts to pre-3.1 behavior.',
      probeKind: 'http',
      identityId: 'tenant_a',
      http: { method: 'GET', path: '/api/v1/resource' },
    },
    { ...buildOptions(async () => new Response()), strictProbes: true },
  );

  assert.equal(result.verdict, 'auth_failed');
});

test('executeLiveProbe simulates mutation as dry_run_simulated when allowMutations is false (Section 3.1)', async () => {
  const events: Array<{ stage: string; payload: Record<string, unknown> }> = [];
  let fetchCalled = false;
  const fetchFn: typeof fetch = async () => {
    fetchCalled = true;
    return new Response('ok', { status: 200 });
  };
  const result = await executeLiveProbe(
    {
      findingId: 'finding-mutation',
      hypothesis: 'Mutation probe should be simulated, not sent.',
      probeKind: 'http',
      identityId: 'guest',
      http: {
        method: 'POST',
        path: '/api/v1/resource',
        body: '{"name":"x"}',
      },
    },
    {
      ...buildOptions(fetchFn),
      allowMutations: false,
      onEvent: (stage, payload) =>
        events.push({ stage, payload: payload as unknown as Record<string, unknown> }),
    },
  );

  assert.equal(result.verdict, 'dry_run_simulated');
  assert.equal(fetchCalled, false, 'fetch must not be invoked in dry-run mode');
  assert.equal(result.request.method, 'POST');
  assert.ok(result.request.url.includes('/api/v1/resource'));
  const dryRun = events.find((e) => e.stage === 'dry_run_probe');
  assert.ok(dryRun, 'dry_run_probe event emitted');
  const gap = events.find(
    (e) => e.stage === 'coverage_gap' && e.payload.code === 'mutation_rollback_missing',
  );
  assert.ok(gap, 'mutation_rollback_missing coverage_gap event emitted');
});

test('executeLiveProbe rejects mutation as not_authorized when strictProbes + !allowMutations (legacy)', async () => {
  const result = await executeLiveProbe(
    {
      findingId: 'finding-mutation-strict',
      hypothesis: 'strict mode reverts to pre-3.1 behavior.',
      probeKind: 'http',
      identityId: 'guest',
      http: { method: 'POST', path: '/api/v1/resource', body: '{}' },
    },
    {
      ...buildOptions(async () => new Response()),
      allowMutations: false,
      strictProbes: true,
    },
  );

  assert.equal(result.verdict, 'not_authorized');
});

test('executeLiveProbe strips bodies from GET probes before issuing the request', async () => {
  let capturedInit: RequestInit | undefined;
  const result = await executeLiveProbe({
    findingId: 'finding-get-body',
    hypothesis: 'Guest should probe GET /health without a request body.',
    probeKind: 'http',
    identityId: 'guest',
    http: {
      method: 'GET',
      path: '/api/v1/health',
      body: '{"unexpected":true}',
    },
    expectedWhenSafe: { status: 200 },
    expectedWhenExploitable: { status: 500 },
  }, buildOptions(async (_input, init) => {
    capturedInit = init;
    return new Response('ok', { status: 200 });
  }));

  assert.equal(capturedInit?.body, undefined);
  assert.equal(result.request.body, undefined);
  assert.equal(result.verdict, 'refuted');
});

test('executeLiveProbe refuses to fire when the policy runtime blocks it', async () => {
  let fetched = 0;
  const gaps: Array<{ code: string; reason: string }> = [];
  const base = buildOptions(async () => {
    fetched += 1;
    return new Response('should not happen', { status: 200 });
  });

  const result = await executeLiveProbe(
    {
      findingId: 'f-gate',
      hypothesis: 'tenant isolation bypass',
      probeKind: 'http',
      identityId: 'guest',
      http: { method: 'GET', path: '/api/records/1' },
      expectedWhenExploitable: { statusIn: [200] },
    },
    {
      ...base,
      onEvent: (stage: string, payload: unknown) => {
        if (stage === 'coverage_gap') {
          const p = payload as { code: string; reason: string };
          gaps.push({ code: p.code, reason: p.reason });
        }
      },
      runtime: {
        authorizeProbe: () => ({
          allowed: false,
          observedSafetyState: 'blocked',
          reason: 'Kill switch is active',
          mode: 'declared',
        }),
      },
      runtimeTargetContext: {
        id: 'fixture',
        kind: 'http',
        environment: 'sandbox',
        baseUrl: 'http://localhost:4000',
      },
    } as never,
  );

  assert.equal(result.verdict, 'not_authorized');
  assert.match(result.reasoning, /Kill switch is active/);
  assert.equal(fetched, 0, 'a blocked probe must not reach the network');
  assert.equal(gaps.length, 1);
  assert.equal(gaps[0]!.code, 'probe_blocked_by_policy');
});

test('executeLiveProbe refuses when a runtime is supplied without a target context', async () => {
  const base = buildOptions(async () => new Response('nope', { status: 200 }));

  const result = await executeLiveProbe(
    {
      findingId: 'f-gate-2',
      hypothesis: 'x',
      probeKind: 'http',
      identityId: 'guest',
      http: { method: 'GET', path: '/api/records/1' },
      expectedWhenExploitable: { statusIn: [200] },
    },
    {
      ...base,
      runtime: { authorizeProbe: () => ({ allowed: true }) },
    } as never,
  );

  assert.equal(result.verdict, 'not_authorized');
  assert.match(result.reasoning, /environment tier unknown/);
});
