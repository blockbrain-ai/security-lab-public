import test from 'node:test';
import assert from 'node:assert/strict';

import {
  createEmptyInventory,
  addEntity,
} from './entity-inventory.js';

import {
  resolveProbeParameters,
  resolveForProbe,
  inferEntityKind,
  discoverEntitiesFromResponse,
} from './entity-resolution.js';

test('inferEntityKind maps well-known placeholders', () => {
  assert.equal(inferEntityKind(':companyId'), 'company_id');
  assert.equal(inferEntityKind(':userId'), 'user_id');
  assert.equal(inferEntityKind(':token'), 'claim_token');
  assert.equal(inferEntityKind(':unknownParam'), 'route_param');
});

test('resolveProbeParameters resolves placeholders from inventory', () => {
  const inv = createEmptyInventory();
  addEntity(inv, { kind: 'company_id', value: 'comp-123', provenance: 'seeded', parameterName: ':companyId' });
  addEntity(inv, { kind: 'user_id', value: 'user-456', provenance: 'minted', parameterName: ':userId' });

  const result = resolveProbeParameters(
    '/api/companies/:companyId/users/:userId',
    inv,
  );

  assert.equal(result.allCriticalResolved, true);
  assert.equal(result.anyResolved, true);
  assert.equal(result.resolved.length, 2);
  assert.equal(result.unresolved.length, 0);
  assert.ok(result.resolvedPath.includes('comp-123'));
  assert.ok(result.resolvedPath.includes('user-456'));
  assert.ok(!result.resolvedPath.includes(':companyId'));
  assert.ok(!result.resolvedPath.includes(':userId'));
});

test('resolveProbeParameters marks unresolved as critical by default', () => {
  const inv = createEmptyInventory();
  addEntity(inv, { kind: 'company_id', value: 'comp-123', provenance: 'seeded', parameterName: ':companyId' });

  const result = resolveProbeParameters(
    '/api/companies/:companyId/users/:userId',
    inv,
  );

  assert.equal(result.allCriticalResolved, false);
  assert.equal(result.resolved.length, 1);
  assert.equal(result.unresolved.length, 1);
  assert.equal(result.unresolved[0]!.placeholder, ':userId');
  assert.equal(result.unresolved[0]!.criticality, 'critical');
});

test('resolveProbeParameters handles optional parameters', () => {
  const inv = createEmptyInventory();
  addEntity(inv, { kind: 'company_id', value: 'comp-123', provenance: 'seeded', parameterName: ':companyId' });

  const result = resolveProbeParameters(
    '/api/companies/:companyId/users/:userId',
    inv,
    { optionalParameters: [':userId'] },
  );

  assert.equal(result.allCriticalResolved, true);
  assert.equal(result.unresolved.length, 1);
  assert.equal(result.unresolved[0]!.criticality, 'optional');
});

test('resolveProbeParameters falls back to kind-based lookup', () => {
  const inv = createEmptyInventory();
  // No parameterName set — should be found by kind inference
  addEntity(inv, { kind: 'company_id', value: 'comp-by-kind', provenance: 'seeded' });

  const result = resolveProbeParameters('/api/companies/:companyId', inv);

  assert.equal(result.allCriticalResolved, true);
  assert.equal(result.resolved.length, 1);
  assert.equal(result.resolved[0]!.value, 'comp-by-kind');
});

test('resolveProbeParameters prefers matching identity', () => {
  const inv = createEmptyInventory();
  addEntity(inv, { kind: 'company_id', value: 'comp-admin', provenance: 'seeded', parameterName: ':companyId', identityId: 'admin' });
  addEntity(inv, { kind: 'company_id', value: 'comp-viewer', provenance: 'seeded', parameterName: ':companyId', identityId: 'viewer' });

  const result = resolveProbeParameters(
    '/api/companies/:companyId',
    inv,
    { identityId: 'viewer' },
  );

  assert.equal(result.resolved[0]!.value, 'comp-viewer');
});

test('resolveProbeParameters leaves no-placeholder paths unchanged', () => {
  const inv = createEmptyInventory();
  const result = resolveProbeParameters('/api/health', inv);

  assert.equal(result.resolvedPath, '/api/health');
  assert.equal(result.allCriticalResolved, true);
  assert.equal(result.resolved.length, 0);
  assert.equal(result.unresolved.length, 0);
});

test('resolveForProbe returns meaningful=false for unresolved critical params', () => {
  const inv = createEmptyInventory();
  const outcome = resolveForProbe(
    'probe-1',
    'finding-1',
    '/api/companies/:companyId',
    inv,
  );

  assert.equal(outcome.meaningful, false);
  assert.equal(outcome.result.allCriticalResolved, false);
  assert.equal(outcome.probeId, 'probe-1');
  assert.equal(outcome.findingId, 'finding-1');
});

test('resolveForProbe returns meaningful=true when all critical params resolved', () => {
  const inv = createEmptyInventory();
  addEntity(inv, { kind: 'company_id', value: 'c1', provenance: 'seeded', parameterName: ':companyId' });

  const outcome = resolveForProbe(
    'probe-2',
    'finding-2',
    '/api/companies/:companyId',
    inv,
  );

  assert.equal(outcome.meaningful, true);
  assert.equal(outcome.result.allCriticalResolved, true);
});

test('runtime-discovered entity can feed a later probe', () => {
  const inv = createEmptyInventory();

  // Simulate runtime discovery
  const discovered = discoverEntitiesFromResponse(
    JSON.stringify({ companyId: 'runtime-comp-789', userId: 'runtime-user-101' }),
    'response:/api/auth/login',
  );

  assert.equal(discovered.length, 2);

  // Add discovered entities to inventory
  for (const entity of discovered) {
    addEntity(inv, {
      kind: entity.kind,
      value: entity.value,
      provenance: 'discovered_runtime',
      parameterName: entity.parameterName,
    });
  }

  // Now resolve a probe that needs these values
  const result = resolveProbeParameters(
    '/api/companies/:companyId/users/:userId',
    inv,
  );

  assert.equal(result.allCriticalResolved, true);
  assert.equal(result.resolved.length, 2);
  assert.ok(result.resolvedPath.includes('runtime-comp-789'));
  assert.ok(result.resolvedPath.includes('runtime-user-101'));
});

test('discoverEntitiesFromResponse extracts from nested JSON', () => {
  const body = JSON.stringify({
    data: {
      company: {
        companyId: 'nested-comp',
      },
      users: [
        { userId: 'nested-user-1' },
        { userId: 'nested-user-2' },
      ],
    },
  });

  const discovered = discoverEntitiesFromResponse(body, 'response:/api/data');
  assert.ok(discovered.length >= 3);
  assert.ok(discovered.some((d) => d.value === 'nested-comp'));
  assert.ok(discovered.some((d) => d.value === 'nested-user-1'));
  assert.ok(discovered.some((d) => d.value === 'nested-user-2'));
});

test('discoverEntitiesFromResponse returns empty for non-JSON', () => {
  const discovered = discoverEntitiesFromResponse('not json', 'response:/api');
  assert.equal(discovered.length, 0);
});

test('discoverEntitiesFromResponse ignores empty or long values', () => {
  const body = JSON.stringify({
    companyId: '',
    userId: 'x'.repeat(300),
    token: 'valid-token',
  });

  const discovered = discoverEntitiesFromResponse(body, 'test');
  assert.ok(discovered.some((d) => d.value === 'valid-token'));
  assert.ok(!discovered.some((d) => d.value === ''));
  assert.ok(!discovered.some((d) => d.value.length > 256));
});

test('resolveProbeParameters URL-encodes resolved values', () => {
  const inv = createEmptyInventory();
  addEntity(inv, { kind: 'resource_id', value: 'value with spaces', provenance: 'seeded', parameterName: ':id' });

  const result = resolveProbeParameters('/api/resources/:id', inv);
  assert.ok(result.resolvedPath.includes('value%20with%20spaces'));
});
