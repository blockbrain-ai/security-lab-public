import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  createEmptyInventory,
  addEntity,
  seedEntities,
  getEntitiesByKind,
  getEntitiesByParameter,
  getEntitiesByKindAndIdentity,
  extractPlaceholders,
  hasUnresolvedPlaceholders,
  serializeInventory,
  deserializeInventory,
  summarizeInventory,
  type EntityInventory,
} from './entity-inventory.js';

test('createEmptyInventory returns an empty inventory', () => {
  const inv = createEmptyInventory();
  assert.equal(inv.entries.length, 0);
  assert.ok(inv.lastModifiedAt);
});

test('addEntity adds an entry and returns its id', () => {
  const inv = createEmptyInventory();
  const id = addEntity(inv, {
    kind: 'company_id',
    value: 'comp-123',
    provenance: 'seeded',
    parameterName: ':companyId',
  });
  assert.ok(id.startsWith('entity-company_id-'));
  assert.equal(inv.entries.length, 1);
  assert.equal(inv.entries[0]!.value, 'comp-123');
  assert.equal(inv.entries[0]!.provenance, 'seeded');
});

test('addEntity deduplicates on (kind, value, parameterName)', () => {
  const inv = createEmptyInventory();
  const id1 = addEntity(inv, {
    kind: 'user_id',
    value: 'user-42',
    provenance: 'seeded',
    parameterName: ':userId',
  });
  const id2 = addEntity(inv, {
    kind: 'user_id',
    value: 'user-42',
    provenance: 'discovered_runtime',
    parameterName: ':userId',
  });
  assert.equal(id1, id2);
  assert.equal(inv.entries.length, 1);
});

test('addEntity allows same value with different parameterName', () => {
  const inv = createEmptyInventory();
  addEntity(inv, { kind: 'resource_id', value: 'abc', provenance: 'seeded', parameterName: ':id' });
  addEntity(inv, { kind: 'resource_id', value: 'abc', provenance: 'seeded', parameterName: ':resourceId' });
  assert.equal(inv.entries.length, 2);
});

test('seedEntities adds multiple entries', () => {
  const inv = createEmptyInventory();
  const ids = seedEntities(inv, [
    { kind: 'tenant_id', value: 't1', provenance: 'seeded' },
    { kind: 'tenant_id', value: 't2', provenance: 'seeded' },
    { kind: 'user_id', value: 'u1', provenance: 'minted' },
  ]);
  assert.equal(ids.length, 3);
  assert.equal(inv.entries.length, 3);
});

test('getEntitiesByKind filters correctly', () => {
  const inv = createEmptyInventory();
  addEntity(inv, { kind: 'company_id', value: 'c1', provenance: 'seeded' });
  addEntity(inv, { kind: 'user_id', value: 'u1', provenance: 'seeded' });
  addEntity(inv, { kind: 'company_id', value: 'c2', provenance: 'discovered_runtime' });
  const companies = getEntitiesByKind(inv, 'company_id');
  assert.equal(companies.length, 2);
  assert.ok(companies.every((e) => e.kind === 'company_id'));
});

test('getEntitiesByParameter filters by parameterName', () => {
  const inv = createEmptyInventory();
  addEntity(inv, { kind: 'company_id', value: 'c1', provenance: 'seeded', parameterName: ':companyId' });
  addEntity(inv, { kind: 'user_id', value: 'u1', provenance: 'seeded', parameterName: ':userId' });
  const results = getEntitiesByParameter(inv, ':companyId');
  assert.equal(results.length, 1);
  assert.equal(results[0]!.value, 'c1');
});

test('getEntitiesByKindAndIdentity filters by kind and identity', () => {
  const inv = createEmptyInventory();
  addEntity(inv, { kind: 'user_id', value: 'u1', provenance: 'minted', identityId: 'admin' });
  addEntity(inv, { kind: 'user_id', value: 'u2', provenance: 'minted', identityId: 'viewer' });
  addEntity(inv, { kind: 'company_id', value: 'c1', provenance: 'seeded', identityId: 'admin' });
  const results = getEntitiesByKindAndIdentity(inv, 'user_id', 'admin');
  assert.equal(results.length, 1);
  assert.equal(results[0]!.value, 'u1');
});

test('extractPlaceholders extracts route-style placeholders', () => {
  assert.deepEqual(
    extractPlaceholders('/api/companies/:companyId/users/:userId'),
    [':companyId', ':userId'],
  );
  assert.deepEqual(extractPlaceholders('/api/health'), []);
  assert.deepEqual(extractPlaceholders('/api/:id/sub/:id'), [':id']);
});

test('hasUnresolvedPlaceholders detects placeholders', () => {
  assert.equal(hasUnresolvedPlaceholders('/api/:companyId'), true);
  assert.equal(hasUnresolvedPlaceholders('/api/companies/123'), false);
});

test('hasUnresolvedPlaceholders is stable across repeated calls (no lastIndex drift)', () => {
  const path = '/api/companies/:companyId/users/:userId';
  for (let i = 0; i < 10; i++) {
    assert.equal(hasUnresolvedPlaceholders(path), true, `call ${i + 1} should return true`);
  }
  for (let i = 0; i < 10; i++) {
    assert.equal(hasUnresolvedPlaceholders('/api/health'), false, `call ${i + 1} should return false`);
  }
});

test('serialize/deserialize round-trips correctly', () => {
  const inv = createEmptyInventory();
  addEntity(inv, { kind: 'company_id', value: 'c1', provenance: 'seeded', parameterName: ':companyId' });
  addEntity(inv, { kind: 'user_id', value: 'u1', provenance: 'discovered_runtime', identityId: 'admin' });

  const serialized = serializeInventory(inv);
  const json = JSON.stringify(serialized);
  const parsed = JSON.parse(json);
  const restored = deserializeInventory(parsed);

  assert.equal(restored.entries.length, 2);
  assert.equal(restored.entries[0]!.kind, 'company_id');
  assert.equal(restored.entries[0]!.value, 'c1');
  assert.equal(restored.entries[1]!.kind, 'user_id');
  assert.equal(restored.entries[1]!.identityId, 'admin');
});

test('inventory survives resume via campaign memory persistence', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-inventory-resume-'));
  try {
    const inv = createEmptyInventory();
    addEntity(inv, { kind: 'company_id', value: 'c1', provenance: 'seeded', parameterName: ':companyId' });
    addEntity(inv, { kind: 'user_id', value: 'u1', provenance: 'discovered_runtime' });

    // Simulate saveMemory — serialize inventory alongside memory
    const serialized = serializeInventory(inv);
    const memoryObj = {
      campaignId: 'test-campaign',
      iteration: 1,
      signals: [],
      hypotheses: [],
      findings: [],
      graph: { nodes: [], edges: [] },
      probeFingerprints: [],
      totalCostUsd: 0,
      totalProbes: 0,
      duplicateProbesSuppressed: 0,
      dormantSignalIds: [],
      lastResurfacingIteration: 0,
      entityInventory: serialized,
    };

    const memPath = join(root, 'memory.json');
    await writeFile(memPath, JSON.stringify(memoryObj, null, 2), 'utf8');

    // Simulate loadMemory — deserialize inventory back
    const content = await readFile(memPath, 'utf8');
    const raw = JSON.parse(content);
    const restoredInventory = raw.entityInventory
      ? deserializeInventory(raw.entityInventory)
      : createEmptyInventory();

    assert.equal(restoredInventory.entries.length, 2);
    assert.equal(restoredInventory.entries[0]!.kind, 'company_id');
    assert.equal(restoredInventory.entries[0]!.value, 'c1');

    // Add a runtime-discovered entity after resume
    addEntity(restoredInventory, { kind: 'api_key', value: 'key-xyz', provenance: 'discovered_runtime' });
    assert.equal(restoredInventory.entries.length, 3);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('summarizeInventory produces correct summary', () => {
  const inv = createEmptyInventory();
  addEntity(inv, { kind: 'company_id', value: 'c1', provenance: 'seeded' });
  addEntity(inv, { kind: 'company_id', value: 'c2', provenance: 'seeded' });
  addEntity(inv, { kind: 'user_id', value: 'u1', provenance: 'discovered_runtime' });
  addEntity(inv, { kind: 'api_key', value: 'k1', provenance: 'minted' });

  const summary = summarizeInventory(inv, [':token']);
  assert.equal(summary.totalEntries, 4);
  assert.equal(summary.byKind['company_id'], 2);
  assert.equal(summary.byKind['user_id'], 1);
  assert.equal(summary.byKind['api_key'], 1);
  assert.equal(summary.byProvenance['seeded'], 2);
  assert.equal(summary.byProvenance['discovered_runtime'], 1);
  assert.equal(summary.byProvenance['minted'], 1);
  assert.deepEqual(summary.unresolvedParameters, [':token']);
});
