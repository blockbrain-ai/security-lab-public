import test from 'node:test';
import assert from 'node:assert/strict';
import { rm } from 'node:fs/promises';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditTrail } from './audit-trail.js';

test('AuditTrail appends and reads hosted audit entries', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-hosted-audit-'));

  try {
    const trail = new AuditTrail(root);
    const entryId = await trail.append({
      campaignId: 'campaign-1',
      probeId: 'probe-1',
      findingId: 'finding-1',
      identityId: 'guest',
      at: new Date().toISOString(),
      request: { method: 'GET', url: 'https://example.test/health', headers: {} },
      response: { status: 200, headers: { 'content-type': 'text/plain' }, body: 'ok', durationMs: 10 },
      authorizationToken: 'CONFIRM HOSTED PROBE',
      notes: 'note',
    });

    const entries = await trail.readAll();
    assert.equal(entries.length, 1);
    assert.equal(entries[0]?.entryId, entryId);
    assert.match(trail.path, /hosted-audit\.jsonl$/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
