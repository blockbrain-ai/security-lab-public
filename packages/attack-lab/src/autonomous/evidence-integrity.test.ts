import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EvidenceStore } from '../../../evidence-plane/src/store.js';
import { verifyCampaignEvidence } from './evidence-integrity.js';

test('a healthy campaign verifies and writes no diagnostics', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-integrity-'));
  const campaignId = 'inv-healthy';
  try {
    const store = new EvidenceStore(campaignId, join(root, 'runs'));
    await store.prepare();
    await store.appendEvent('stage_started', { stage: 'static' });
    await store.appendEvent('stage_completed', { stage: 'static' });

    const report = await verifyCampaignEvidence(store, root, campaignId);

    assert.equal(report.valid, true);
    assert.equal(report.eventCount, 2);
    assert.ok(report.headHash.length > 0);
    assert.deepEqual(report.errors, []);
    assert.equal(existsSync(join(root, campaignId, 'integrity-errors.jsonl')), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('a tampered stream fails verification and records diagnostics out-of-band', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-integrity-'));
  const campaignId = 'inv-tampered';
  try {
    const store = new EvidenceStore(campaignId, join(root, 'runs'));
    await store.prepare();
    await store.appendEvent('stage_started', { stage: 'static' });
    await store.appendEvent('stage_completed', { stage: 'static' });

    // Rewrite the first event's payload without recomputing its hash: exactly
    // the tamper the chain exists to detect.
    const eventsPath = join(root, 'runs', campaignId, 'events.jsonl');
    const lines = (await readFile(eventsPath, 'utf8')).trim().split('\n');
    const first = JSON.parse(lines[0]!) as { payload: Record<string, unknown> };
    first.payload['stage'] = 'forged';
    lines[0] = JSON.stringify(first);
    await writeFile(eventsPath, lines.join('\n') + '\n', 'utf8');

    // A fresh store reads the tampered file from disk.
    const reopened = new EvidenceStore(campaignId, join(root, 'runs'));
    const report = await verifyCampaignEvidence(reopened, root, campaignId);

    assert.equal(report.valid, false);
    assert.ok(report.errors.length > 0);
    assert.equal(existsSync(join(root, campaignId, 'integrity-errors.jsonl')), true);

    const diagnostics = (await readFile(join(root, campaignId, 'integrity-errors.jsonl'), 'utf8')).trim();
    assert.match(diagnostics, /inv-tampered/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
