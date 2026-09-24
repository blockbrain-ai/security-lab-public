import test from 'node:test';
import assert from 'node:assert/strict';
import type { InvokeOptions, ModelAdapter, ModelResponse } from '../../providers/contracts.js';
import type { RouteSurface } from '../../intelligence/contracts.js';
import { translateHypothesisToLiveProbes } from './hypothesis-translator.js';

class StaticAdapter implements ModelAdapter {
  readonly provider = 'test';
  readonly model = 'static-adapter';

  constructor(private readonly content: string) {}

  async invoke<T = unknown>(_options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    return {
      content: this.content,
      usage: { inputTokens: 1, outputTokens: 1, costUsd: 0 },
      durationMs: 1,
      provider: this.provider,
      model: this.model,
    };
  }
}

class CapturingAdapter implements ModelAdapter {
  readonly provider = 'test';
  readonly model = 'capturing-adapter';
  lastOptions?: InvokeOptions<unknown>;

  async invoke<T = unknown>(options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    this.lastOptions = options;
    return {
      content: JSON.stringify({ probes: [], reasoning: 'captured' }),
      usage: { inputTokens: 1, outputTokens: 1, costUsd: 0 },
      durationMs: 1,
      provider: this.provider,
      model: this.model,
    };
  }
}

class CliCapturingAdapter implements ModelAdapter {
  readonly provider = 'codex_cli';
  readonly model = 'gpt-5.4';
  lastOptions?: InvokeOptions<unknown>;

  async invoke<T = unknown>(options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    this.lastOptions = options;
    return {
      content: JSON.stringify({ probes: [], reasoning: 'captured' }),
      usage: { inputTokens: 1, outputTokens: 1, costUsd: 0 },
      durationMs: 1,
      provider: this.provider,
      model: this.model,
    };
  }
}

function makeBosRoutes(): RouteSurface[] {
  return [
    { method: 'POST', path: '/api/v1/actions/execute', file: 'src/api/routes/actions.ts', hasAuth: true, authObservation: 'handler_local', authEvidence: [], hasValidation: true, provenance: 'static' as never },
    { method: 'POST', path: '/api/v1/approvals/:id/approve', file: 'src/api/routes/approvals.ts', hasAuth: true, authObservation: 'handler_local', authEvidence: [], hasValidation: true, provenance: 'static' as never },
    { method: 'POST', path: '/api/v1/approvals/:id/reject', file: 'src/api/routes/approvals.ts', hasAuth: true, authObservation: 'handler_local', authEvidence: [], hasValidation: true, provenance: 'static' as never },
    { method: 'GET', path: '/api/v1/approvals/:id', file: 'src/api/routes/approvals.ts', hasAuth: true, authObservation: 'handler_local', authEvidence: [], hasValidation: false, provenance: 'static' as never },
    { method: 'GET', path: '/api/v1/decisions/:id', file: 'src/api/routes/decisions.ts', hasAuth: true, authObservation: 'handler_local', authEvidence: [], hasValidation: false, provenance: 'static' as never },
    { method: 'POST', path: '/api/v1/api-keys', file: 'src/api/routes/api-keys.ts', hasAuth: true, authObservation: 'handler_local', authEvidence: [], hasValidation: true, provenance: 'static' as never },
    { method: 'GET', path: '/buyer-room', file: 'src/api/routes/buyer-room.ts', hasAuth: false, authObservation: 'not_observed', authEvidence: [], hasValidation: false, provenance: 'static' as never },
    { method: 'GET', path: '/api/v1/admin/agents', file: 'src/api/routes/admin.ts', hasAuth: true, authObservation: 'handler_local', authEvidence: [], hasValidation: false, provenance: 'static' as never },
  ];
}

test('translateHypothesisToLiveProbes deterministically derives live probes from surface map', async () => {
  const result = await translateHypothesisToLiveProbes({
    findingId: 'finding-1',
    hypothesis: 'If auth is missing, an attacker could call POST /execute without authentication and trigger the action runtime.',
    availableIdentities: ['guest', 'user_a_low'],
    targetHints: { apiPrefix: '/api/v1' },
    surfaceRoutes: makeBosRoutes(),
    maxProbes: 3,
  });

  assert.equal(result.source, 'deterministic');
  assert.ok(result.probes.length > 0);
  assert.equal(result.probes[0]?.http?.path, '/api/v1/actions/execute');
  assert.ok(result.probes.every((probe) => probe.identityId === 'guest'));
  assert.ok(result.probes.every((probe) => probe.expectedWhenSafe?.statusIn?.includes(401)));
});

test('translateHypothesisToLiveProbes falls back to hypothesis text routes without surface map', async () => {
  const result = await translateHypothesisToLiveProbes({
    findingId: 'finding-fallback',
    hypothesis: 'If auth is missing, an attacker could call POST /execute without authentication.',
    availableIdentities: ['guest', 'user_a_low'],
    targetHints: { apiPrefix: '/api/v1' },
    maxProbes: 3,
  });

  assert.equal(result.source, 'deterministic');
  assert.ok(result.probes.length > 0);
  // Without surface map, the path is derived from the hypothesis text
  assert.ok(result.probes[0]?.http?.path?.includes('/execute'));
});

test('translateHypothesisToLiveProbes treats authenticated success as non-exploit for auth-bypass-only hypotheses', async () => {
  const result = await translateHypothesisToLiveProbes({
    findingId: 'finding-auth-only',
    hypothesis: 'If global auth middleware has a gap, an attacker could call POST /execute without authentication.',
    availableIdentities: ['guest', 'user_a_low', 'admin_canary'],
    targetHints: { apiPrefix: '/api/v1' },
    surfaceRoutes: makeBosRoutes(),
    maxProbes: 4,
  });

  assert.deepEqual(result.probes.map((probe) => probe.identityId), ['guest']);
  assert.deepEqual(result.probes[0]?.expectedWhenExploitable?.statusIn, [200, 201, 202, 204, 400, 409, 422]);
});

test('translateHypothesisToLiveProbes requires stronger success for authenticated privilege escalation hypotheses', async () => {
  const result = await translateHypothesisToLiveProbes({
    findingId: 'finding-tenant',
    hypothesis: 'An authenticated user from Org A may set x-tenant-header to Org B and POST /approvals/:id/approve to cross a tenant boundary.',
    availableIdentities: ['guest', 'user_a_low', 'user_b_low'],
    targetHints: {
      apiPrefix: '/api/v1',
      seedData: {
        records: [{ id: 'approval_canary_b', type: 'approval' }],
      },
    },
    surfaceRoutes: makeBosRoutes(),
    maxProbes: 4,
  });

  assert.ok(result.probes.some((probe) => probe.identityId === 'user_a_low'));
  assert.ok(result.probes.every((probe) => probe.identityId !== 'guest'));
  assert.equal(result.probes[0]?.http?.path, '/api/v1/approvals/approval_canary_b/approve');
  assert.deepEqual(result.probes[0]?.expectedWhenSafe?.statusIn, [401, 403, 404]);
  assert.deepEqual(result.probes[0]?.expectedWhenExploitable?.statusIn, [200, 201, 202, 204]);
});

test('translateHypothesisToLiveProbes normalizes anonymous identities and expectations from model output', async () => {
  const adapter = new StaticAdapter(JSON.stringify({
    probes: [
      {
        probeKind: 'http',
        identityId: 'anonymous',
        http: {
          method: 'GET',
          path: '/api/v1/admin/agents',
        },
        expectedWhenSafe: { statusIn: [401, 403] },
        expectedWhenExploitable: { status: 200 },
        rationale: 'Probe admin route as guest',
      },
    ],
    reasoning: 'Probe the protected admin route as an anonymous caller.',
  }));

  const result = await translateHypothesisToLiveProbes({
    findingId: 'finding-2',
    hypothesis: 'Anonymous users may be able to read GET /api/v1/admin/agents.',
    availableIdentities: ['guest', 'user_a_low'],
    maxProbes: 2,
  }, adapter);

  assert.equal(result.source, 'model');
  assert.equal(result.probes[0]?.identityId, 'guest');
  assert.deepEqual(result.probes[0]?.expectedWhenSafe, { status: undefined, statusIn: [401, 403], bodyContains: undefined, bodyNotContains: undefined });
  assert.deepEqual(result.probes[0]?.expectedWhenExploitable, { status: 200, statusIn: undefined, bodyContains: undefined, bodyNotContains: undefined });
});

test('translateHypothesisToLiveProbes drops invalid model probes and normalizes local-model payloads', async () => {
  const adapter = new StaticAdapter([
    'Here is the next probe sequence.',
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
          identityId: 'anonymous',
          http: {
            method: 'get',
            path: '/api/v1/admin/agents',
            headers: { 'x-retry': 2 },
            body: { tenant: 'tenant-b' },
          },
          rationale: 'retry with a concrete admin route',
        },
      ],
      reasoning: 'ignore the incomplete probe and keep the executable one.',
    }),
    '```',
  ].join('\n'));

  const result = await translateHypothesisToLiveProbes({
    findingId: 'finding-qwen-translation',
    hypothesis: 'Anonymous users may be able to read GET /api/v1/admin/agents.',
    availableIdentities: ['guest', 'user_a_low'],
    maxProbes: 3,
  }, adapter);

  assert.equal(result.source, 'model');
  assert.equal(result.probes.length, 1);
  assert.equal(result.probes[0]?.identityId, 'guest');
  assert.equal(result.probes[0]?.http?.method, 'GET');
  assert.deepEqual(result.probes[0]?.http?.headers, { 'x-retry': '2' });
  assert.equal(result.probes[0]?.http?.body, '{"tenant":"tenant-b"}');
});

test('translateHypothesisToLiveProbes compacts target hints and uses a continuation prompt for resumed sessions', async () => {
  const adapter = new CapturingAdapter();
  const longHypothesis = 'Continue verifying a cross-tenant approval path. '.repeat(40);

  await translateHypothesisToLiveProbes({
    findingId: 'finding-continued',
    hypothesis: longHypothesis,
    availableIdentities: ['guest', 'user_a_low'],
    targetHints: {
      stack: 'express-prisma-nextjs',
      apiPrefix: '/api/v1',
      entryPoints: ['src/api/server.ts', 'src/api/app.ts', 'src/api/routes'],
      seedData: {
        tenants: [{ id: 'tenant-a' }, { id: 'tenant-b' }],
        records: [
          { id: 'approval_canary_a', type: 'approval', tenantId: 'tenant-a' },
          { id: 'approval_canary_b', type: 'approval', tenantId: 'tenant-b' },
        ],
      },
    },
    relatedAssets: ['src/api/app.ts', 'src/api/app.ts', 'src/api/routes/approval.routes.ts'],
    runtimeSignals: ['runtime signal a', 'runtime signal a', 'runtime signal b'],
    maxProbes: 3,
  }, adapter, {
    invokeOptions: { sessionId: 'sess-1' },
  });

  assert.ok(adapter.lastOptions);
  assert.match(adapter.lastOptions!.prompt, /Continue the same local-live investigation/);
  assert.match(adapter.lastOptions!.prompt, /approval:approval_canary_a@tenant-a/);
  assert.doesNotMatch(adapter.lastOptions!.prompt, /entryPoints/);
  assert.ok(adapter.lastOptions!.prompt.length < longHypothesis.length + 900, 'continuation prompt should stay compact');
  const relatedAssetsSection = adapter.lastOptions!.prompt
    .split('## Related Assets\n')[1]
    ?.split('\n\n## Local-Live Round')[0] ?? '';
  assert.equal((relatedAssetsSection.match(/src\/api\/app\.ts/g) ?? []).length, 1);
});

test('translateHypothesisToLiveProbes keeps first-round target hints lean', async () => {
  const adapter = new CapturingAdapter();

  await translateHypothesisToLiveProbes({
    findingId: 'finding-first-round',
    hypothesis: 'If auth is missing, an attacker could call POST /execute without authentication.',
    availableIdentities: ['guest', 'user_a_low'],
    targetHints: {
      stack: 'express-prisma-nextjs',
      framework: 'Express + Prisma + Next.js',
      apiPrefix: '/api/v1',
      healthEndpoint: '/api/v1/health',
      authMechanism: 'bearer-token',
      tenantHeader: 'x-organization-id',
      entryPoints: ['src/api/server.ts', 'src/api/app.ts', 'src/api/routes'],
      authSurfaces: ['src/api/middleware', 'src/services/auth'],
      governanceSurfaces: ['src/services/governance'],
      publicSurfaces: ['src/api/public'],
      persistenceSurfaces: ['src/db'],
      highValuePatterns: ['$queryRaw', '$executeRaw', 'child_process'],
      seedData: {
        tenants: [{ id: 'tenant-a' }, { id: 'tenant-b' }],
        records: [
          { id: 'approval_canary_a', type: 'approval', tenantId: 'tenant-a' },
          { id: 'approval_canary_b', type: 'approval', tenantId: 'tenant-b' },
        ],
      },
    },
    relatedAssets: ['src/api/app.ts', 'src/api/routes/action.routes.ts'],
    maxProbes: 3,
  }, adapter);

  assert.ok(adapter.lastOptions);
  assert.match(adapter.lastOptions!.prompt, /highValuePatterns/);
  assert.doesNotMatch(adapter.lastOptions!.prompt, /entryPoints/);
  assert.doesNotMatch(adapter.lastOptions!.prompt, /authSurfaces/);
  assert.doesNotMatch(adapter.lastOptions!.prompt, /governanceSurfaces/);
  assert.doesNotMatch(adapter.lastOptions!.prompt, /publicSurfaces/);
  assert.doesNotMatch(adapter.lastOptions!.prompt, /persistenceSurfaces/);
});

test('translateHypothesisToLiveProbes uses packet context files for CLI-backed adapters', async () => {
  const adapter = new CliCapturingAdapter();

  await translateHypothesisToLiveProbes({
    findingId: 'finding-cli-context',
    hypothesis: 'If auth is missing, an attacker could call POST /execute without authentication.',
    availableIdentities: ['guest', 'user_a_low'],
    contextFilePath: '/tmp/security-lab/local-live-packets/finding-cli-context-round-1.json',
    targetHints: {
      apiPrefix: '/api/v1',
      entryPoints: ['src/api/server.ts', 'src/api/app.ts', 'src/api/routes'],
      authSurfaces: ['src/api/middleware', 'src/services/auth'],
      governanceSurfaces: ['src/services/governance'],
      highValuePatterns: ['$queryRaw', '$executeRaw', 'child_process'],
    },
    relatedAssets: ['src/api/app.ts', 'src/api/routes/action.routes.ts'],
    dormantSignals: ['[ws-1] dormant signal a', '[ws-2] dormant signal b'],
    runtimeSignals: ['[ws-3] runtime signal a'],
    maxProbes: 4,
  }, adapter);

  assert.ok(adapter.lastOptions);
  assert.match(adapter.lastOptions!.prompt, /## Packet Context File/);
  assert.match(adapter.lastOptions!.prompt, /finding-cli-context-round-1\.json/);
  assert.match(adapter.lastOptions!.prompt, /Read that JSON file directly with your tools/);
  assert.match(adapter.lastOptions!.prompt, /Only inspect additional source files if the packet evidence is insufficient/);
  assert.match(adapter.lastOptions!.prompt, /Return exactly one JSON object and nothing else/);
  assert.doesNotMatch(adapter.lastOptions!.prompt, /## Target Hints/);
  assert.doesNotMatch(adapter.lastOptions!.prompt, /entryPoints/);
  assert.doesNotMatch(adapter.lastOptions!.prompt, /Dormant Signals/);
  assert.doesNotMatch(adapter.lastOptions!.prompt, /Runtime Signals/);
});

test('translateHypothesisToLiveProbes uses surface map to rank routes for IDOR hypotheses', async () => {
  const result = await translateHypothesisToLiveProbes({
    findingId: 'finding-idor',
    hypothesis: 'Cross-tenant IDOR via the decisions endpoint — user A can read decisions owned by Org B.',
    availableIdentities: ['guest', 'user_a_low', 'user_b_low'],
    targetHints: {
      apiPrefix: '/api/v1',
      seedData: {
        records: [{ id: 'decision_canary_b', type: 'decision' }],
      },
    },
    surfaceRoutes: makeBosRoutes(),
    maxProbes: 3,
  });

  assert.equal(result.source, 'deterministic');
  assert.ok(result.probes.length > 0);
  // Surface map should rank the decisions route highest
  assert.ok(result.probes[0]?.http?.path?.includes('/decisions/'));
});
