import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  executeIdentityDifferentialProbe,
  executeIdentityDifferentialSequence,
} from './identity-differential.js';
import type { LiveProbeRequest, ProbeSequenceDefinition } from './contracts.js';
import { IdentityLadder } from './identity-ladder.js';
import { RateLimiter } from './rate-limiter.js';
import { MutationJournal } from './reversible-mutation.js';

function buildOptions(fetchFn: typeof fetch) {
  return {
    baseUrl: 'http://localhost:4000',
    identityLadder: new IdentityLadder([
      { id: 'guest', kind: 'anonymous' as const },
      { id: 'user-a', kind: 'anonymous' as const },
      { id: 'admin', kind: 'anonymous' as const },
    ]),
    rateLimiter: new RateLimiter({
      requestsPerSecond: 100,
      maxRequestsPerCampaign: 200,
      autoStopOn5xxStreak: 5,
      autoStopOnLatencyDoubling: false,
    }),
    mutationJournal: new MutationJournal(),
    fetchFn,
  };
}

// ---------------------------------------------------------------------------
// Single-probe identity differential
// ---------------------------------------------------------------------------

describe('executeIdentityDifferentialProbe', () => {
  it('detects privilege escalation when guest gets 200 but admin gets 403', async () => {
    let callCount = 0;
    const fetchFn: typeof fetch = async () => {
      // Rotate responses: first call for guest → 200, second for admin → 403
      return callCount++ === 0
        ? new Response(JSON.stringify({ data: [{ id: 1 }] }), { status: 200, headers: { 'content-type': 'application/json' } })
        : new Response('forbidden', { status: 403 });
    };

    const probe: LiveProbeRequest = {
      findingId: 'f-privesc',
      hypothesis: 'Guest can access admin data',
      probeKind: 'http',
      identityId: 'guest',
      http: { method: 'GET', path: '/api/admin/data' },
      expectedWhenSafe: { statusIn: [401, 403] },
      expectedWhenExploitable: { status: 200 },
    };

    const result = await executeIdentityDifferentialProbe(
      probe,
      { identityIds: ['guest', 'admin'] },
      buildOptions(fetchFn),
    );

    assert.equal(result.entries.length, 2);
    assert.equal(result.deltas.length, 1);
    assert.equal(result.deltas[0].privilegeEscalationDetected, true);
    assert.equal(result.verdict, 'confirmed');
    assert.ok(result.reasoning.includes('Privilege escalation'));
  });

  it('returns refuted when all identities are denied', async () => {
    const fetchFn: typeof fetch = async () => {
      return new Response('unauthorized', { status: 403 });
    };

    const probe: LiveProbeRequest = {
      findingId: 'f-denied',
      hypothesis: 'No identity can access this',
      probeKind: 'http',
      identityId: 'guest',
      http: { method: 'GET', path: '/api/secret' },
      expectedWhenSafe: { statusIn: [401, 403] },
      expectedWhenExploitable: { status: 200 },
    };

    const result = await executeIdentityDifferentialProbe(
      probe,
      { identityIds: ['guest', 'user-a', 'admin'] },
      buildOptions(fetchFn),
    );

    assert.equal(result.entries.length, 3);
    assert.equal(result.verdict, 'refuted');
    // No privilege escalation detected
    assert.ok(result.deltas.every((d) => !d.privilegeEscalationDetected));
  });

  it('returns inconclusive when responses are identical 200s', async () => {
    const fetchFn: typeof fetch = async () => {
      return new Response(
        JSON.stringify({ public: true }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    };

    const probe: LiveProbeRequest = {
      findingId: 'f-same',
      hypothesis: 'All identities see the same thing',
      probeKind: 'http',
      identityId: 'guest',
      http: { method: 'GET', path: '/api/public' },
    };

    const result = await executeIdentityDifferentialProbe(
      probe,
      { identityIds: ['guest', 'user-a'] },
      buildOptions(fetchFn),
    );

    assert.equal(result.entries.length, 2);
    // No escalation since both got 200 with same data
    assert.ok(result.deltas.every((d) => !d.privilegeEscalationDetected));
  });
});

// ---------------------------------------------------------------------------
// Sequence identity differential
// ---------------------------------------------------------------------------

describe('executeIdentityDifferentialSequence', () => {
  it('runs a sequence across two identities and compares', async () => {
    let callCount = 0;
    const fetchFn: typeof fetch = async (input) => {
      callCount += 1;
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;

      if (url.includes('/auth/token')) {
        return new Response(
          JSON.stringify({ token: `tok-${callCount}` }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      // For the guest, access is denied; for admin, access is granted
      if (callCount <= 2) {
        // Guest's second step
        return new Response('forbidden', { status: 403 });
      }
      // Admin's second step
      return new Response(
        JSON.stringify({ secrets: ['admin-data'] }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    };

    const definition: ProbeSequenceDefinition = {
      sequenceId: 'seq-diff-test',
      findingId: 'f-seq-diff',
      hypothesis: 'Token scope differs by identity',
      defaultIdentityId: 'guest',
      steps: [
        {
          stepId: 'get_token',
          label: 'Obtain token',
          http: { method: 'POST', path: '/auth/token' },
          extractOutputs: {
            token: { kind: 'jsonPath', path: 'token' },
          },
        },
        {
          stepId: 'use_token',
          label: 'Access protected data',
          http: { method: 'GET', path: '/api/data?token={{get_token.token}}' },
          expectedWhenSafe: { statusIn: [401, 403] },
          expectedWhenExploitable: { status: 200 },
        },
      ],
    };

    const { result } = await executeIdentityDifferentialSequence(
      definition,
      { identityIds: ['guest', 'admin'] },
      { ...buildOptions(fetchFn), allowMutations: true },
    );

    assert.equal(result.entries.length, 2);
    // Both entries should have sequence results
    assert.ok(result.entries[0].sequenceResult);
    assert.ok(result.entries[1].sequenceResult);
    // Should detect the differential
    assert.equal(result.deltas.length, 1);
    assert.equal(result.deltas[0].privilegeEscalationDetected, true);
    assert.equal(result.verdict, 'confirmed');
  });
});
