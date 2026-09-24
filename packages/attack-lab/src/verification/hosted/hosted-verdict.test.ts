import test from 'node:test';
import assert from 'node:assert/strict';
import { deriveHostedVerdict } from './hosted-verdict.js';
import type { HostedProbeRequest } from './contracts.js';

function probe(expect?: HostedProbeRequest['expect']): HostedProbeRequest {
  return {
    findingId: 'f-1',
    hypothesis: 'a guest can read another tenant record',
    identityId: 'guest',
    http: { method: 'GET', path: '/api/records/1' },
    boundary: 'guest -> protected_route',
    ...(expect ? { expect } : {}),
  };
}

test('a 2xx with no declared assertion is inconclusive, not confirmed', () => {
  const result = deriveHostedVerdict(probe(), { status: 200, body: 'ok' });
  assert.equal(result.verdict, 'inconclusive');
  assert.match(result.reasoning, /no declared assertion/);
});

test('a satisfied assertion confirms', () => {
  const result = deriveHostedVerdict(probe({ statusIn: [200], bodyContains: 'tenant-b' }), {
    status: 200,
    body: '{"owner":"tenant-b"}',
  });
  assert.equal(result.verdict, 'confirmed');
  assert.ok(result.checks.length >= 2);
});

test('a hard denial with an unmet assertion refutes', () => {
  const result = deriveHostedVerdict(probe({ statusIn: [200], bodyContains: 'tenant-b' }), {
    status: 403,
    body: 'forbidden',
  });
  assert.equal(result.verdict, 'refuted');
  assert.match(result.reasoning, /Boundary held/);
});

test('an unexpected but non-denial status stays inconclusive', () => {
  const result = deriveHostedVerdict(probe({ statusIn: [200] }), { status: 302, body: '' });
  assert.equal(result.verdict, 'inconclusive');
});

test('bodyNotContains expresses an identity differential', () => {
  const otherTenantRecord = deriveHostedVerdict(
    probe({ statusIn: [200], bodyContains: 'record', bodyNotContains: 'tenant-a' }),
    { status: 200, body: 'record: tenant-b' },
  );
  assert.equal(otherTenantRecord.verdict, 'confirmed');

  const ownTenantRecord = deriveHostedVerdict(
    probe({ statusIn: [200], bodyContains: 'record', bodyNotContains: 'tenant-a' }),
    { status: 200, body: 'record: tenant-a' },
  );
  assert.equal(ownTenantRecord.verdict, 'inconclusive', 'seeing your own tenant record is not a crossing');
});

test('minBodyBytes distinguishes a dump from an empty collection', () => {
  const empty = deriveHostedVerdict(probe({ statusIn: [200], minBodyBytes: 50 }), { status: 200, body: '[]' });
  assert.equal(empty.verdict, 'inconclusive');

  const populated = deriveHostedVerdict(probe({ statusIn: [200], minBodyBytes: 50 }), {
    status: 200,
    body: JSON.stringify(Array.from({ length: 20 }, (_, i) => ({ id: i }))),
  });
  assert.equal(populated.verdict, 'confirmed');
});
