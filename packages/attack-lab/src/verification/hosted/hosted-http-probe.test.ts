import test from 'node:test';
import assert from 'node:assert/strict';
import { rm } from 'node:fs/promises';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditTrail } from './audit-trail.js';
import { executeHostedProbe } from './hosted-http-probe.js';
import { RateLimiter } from '../local-live/rate-limiter.js';
import type { HostedProbeRequest, HostedTargetMeta } from './contracts.js';

const baseProbe: HostedProbeRequest = {
  findingId: 'finding-1',
  hypothesis: 'guest can cross trust boundary',
  identityId: 'guest',
  http: {
    method: 'GET',
    path: '/private',
  },
  boundary: 'guest -> private',
};

function makeTarget(): HostedTargetMeta {
  return {
    id: 'staging',
    baseUrl: 'https://example.test',
    authSources: new Map([['anon', { source: 'anonymous' }]]),
    hostedIdentities: [],
    ingressChecks: [],
    rateLimit: {
      requestsPerSecond: 5,
      requestsPerCampaign: 20,
      requestsPerDay: 100,
    },
    cooldownSeconds: 0,
  };
}

test('executeHostedProbe handles preflight stop, missing authorization, and auth failures', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-hosted-probe-'));

  try {
    const trail = new AuditTrail(root);
    const rateLimiter = new RateLimiter({
      requestsPerSecond: 100,
      maxRequestsPerCampaign: 100,
      autoStopOn5xxStreak: 1,
      autoStopOnLatencyDoubling: false,
    });

    const autoStopped = await executeHostedProbe(baseProbe, {
      campaignId: 'campaign-1',
      authorizationToken: 'CONFIRM HOSTED PROBE',
      target: makeTarget(),
      authManager: { resolve: async () => ({ headers: {}, source: 'anonymous' }) } as any,
      identityMatrix: { get: () => ({ id: 'guest', authSourceRef: 'anon' }) } as any,
      auditTrail: trail,
      autoStop: {
        preflight: () => ({ reason: 'kill_switch', detail: 'operator stop', at: new Date().toISOString() }),
        recordResult: () => null,
      } as any,
      rateLimiter,
      fetchFn: async () => new Response('ok', { status: 200 }),
    });
    assert.equal(autoStopped.verdict, 'auto_stopped');

    const unknownIdentity = await executeHostedProbe(baseProbe, {
      campaignId: 'campaign-1',
      authorizationToken: 'CONFIRM HOSTED PROBE',
      target: makeTarget(),
      authManager: { resolve: async () => null } as any,
      identityMatrix: { get: () => null } as any,
      auditTrail: trail,
      autoStop: { preflight: () => null, recordResult: () => null } as any,
      rateLimiter,
      fetchFn: async () => new Response('ok', { status: 200 }),
    });
    assert.equal(unknownIdentity.verdict, 'auth_failed');

    const authFailure = await executeHostedProbe(baseProbe, {
      campaignId: 'campaign-1',
      authorizationToken: 'CONFIRM HOSTED PROBE',
      target: makeTarget(),
      authManager: { resolve: async () => { throw new Error('bad token'); } } as any,
      identityMatrix: { get: () => ({ id: 'guest', authSourceRef: 'anon' }) } as any,
      auditTrail: trail,
      autoStop: { preflight: () => null, recordResult: () => null } as any,
      rateLimiter,
      fetchFn: async () => new Response('ok', { status: 200 }),
    });
    assert.equal(authFailure.verdict, 'auth_failed');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('executeHostedProbe records successful, mutation-blocked, auto-stopped, and runtime-error probes', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-hosted-probe-'));

  try {
    const trail = new AuditTrail(root);
    const rateLimiter = new RateLimiter({
      requestsPerSecond: 100,
      maxRequestsPerCampaign: 100,
      autoStopOn5xxStreak: 1,
      autoStopOnLatencyDoubling: false,
    });

    const success = await executeHostedProbe(baseProbe, {
      campaignId: 'campaign-2',
      authorizationToken: 'CONFIRM HOSTED PROBE',
      target: makeTarget(),
      authManager: { resolve: async () => ({ headers: { Authorization: 'Bearer canary' }, source: 'anonymous' }) } as any,
      identityMatrix: { get: () => ({ id: 'guest', authSourceRef: 'anon' }) } as any,
      auditTrail: trail,
      autoStop: { preflight: () => null, recordResult: () => null } as any,
      rateLimiter,
      fetchFn: async () => new Response('ok', { status: 200, headers: { 'content-type': 'text/plain' } }),
    });
    assert.equal(success.verdict, 'confirmed');
    assert.ok(success.auditEntryRef);
    assert.equal((await trail.readAll()).length, 1);

    const mutationBlocked = await executeHostedProbe(
      {
        ...baseProbe,
        http: { method: 'POST', path: '/private', body: '{"probe":true}' },
        mutationAllowed: false,
      },
      {
        campaignId: 'campaign-2',
        authorizationToken: 'CONFIRM HOSTED PROBE',
        target: makeTarget(),
        authManager: { resolve: async () => ({ headers: {}, source: 'anonymous' }) } as any,
        identityMatrix: { get: () => ({ id: 'guest', authSourceRef: 'anon' }) } as any,
        auditTrail: trail,
        autoStop: { preflight: () => null, recordResult: () => null } as any,
        rateLimiter,
        fetchFn: async () => new Response('ok', { status: 200 }),
      },
    );
    assert.equal(mutationBlocked.verdict, 'not_authorized');

    const responseAutoStopped = await executeHostedProbe(baseProbe, {
      campaignId: 'campaign-2',
      authorizationToken: 'CONFIRM HOSTED PROBE',
      target: makeTarget(),
      authManager: { resolve: async () => ({ headers: {}, source: 'anonymous' }) } as any,
      identityMatrix: { get: () => ({ id: 'guest', authSourceRef: 'anon' }) } as any,
      auditTrail: trail,
      autoStop: {
        preflight: () => null,
        recordResult: () => ({ reason: 'waf_block', detail: 'WAF tripped', at: new Date().toISOString() }),
      } as any,
      rateLimiter,
      fetchFn: async () => new Response('blocked', { status: 403 }),
    });
    assert.equal(responseAutoStopped.verdict, 'auto_stopped');

    const runtimeError = await executeHostedProbe(baseProbe, {
      campaignId: 'campaign-2',
      authorizationToken: 'CONFIRM HOSTED PROBE',
      target: makeTarget(),
      authManager: { resolve: async () => ({ headers: {}, source: 'anonymous' }) } as any,
      identityMatrix: { get: () => ({ id: 'guest', authSourceRef: 'anon' }) } as any,
      auditTrail: trail,
      autoStop: { preflight: () => null, recordResult: () => null } as any,
      rateLimiter,
      fetchFn: async () => {
        throw new Error('network unreachable');
      },
    });
    assert.equal(runtimeError.verdict, 'runtime_error');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
