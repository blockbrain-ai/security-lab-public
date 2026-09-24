import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EvidenceStore } from './store.js';
import type { RunSummary } from './contracts.js';
import type { InvestigationReportData } from './investigation-report.js';

test('EvidenceStore chains event hashes and manifests all run artifacts', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-evidence-'));

  try {
    const store = new EvidenceStore('run-1', root);
    await store.appendEvent('started', { value: 1 });
    await store.appendEvent('finished', { value: 2 });
    await store.writeTextArtifact('notes.txt', 'hello');
    await store.writeManifest('run-1');

    const events = (await readFile(join(root, 'run-1', 'events.jsonl'), 'utf8'))
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as { index: number; hash: string; previousHash: string; stage: string });

    assert.equal(events.length, 2);
    assert.equal(events[0]?.index, 0);
    assert.equal(events[1]?.index, 1);
    assert.equal(events[0]?.previousHash, '');
    assert.equal(events[1]?.previousHash, events[0]?.hash);
    assert.ok(events[0]?.hash);
    assert.ok(events[1]?.hash);

    const manifest = JSON.parse(await readFile(join(root, 'run-1', 'manifest.json'), 'utf8')) as {
      files: Record<string, string>;
    };
    assert.ok(manifest.files['events.jsonl']);
    assert.ok(manifest.files['notes.txt']);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('EvidenceStore serializes concurrent events and can round-trip a summary', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-evidence-roundtrip-'));

  try {
    const store = new EvidenceStore('run-2', root);
    await Promise.all([
      store.appendEvent('alpha', { order: 1 }),
      store.appendEvent('beta', { order: 2 }),
      store.appendEvent('gamma', { order: 3 }),
    ]);

    const summary: RunSummary = {
      runId: 'run-2',
      runfileId: 'fixture',
      runfileName: 'Fixture',
      mode: 'declared',
      startedAt: '2026-04-10T00:00:00.000Z',
      completedAt: '2026-04-10T00:01:00.000Z',
      scenarioCount: 0,
      passed: 0,
      failed: 0,
      targetEnvironments: ['sandbox'],
      orchestration: {
        planner: 'planner',
        executor: 'executor',
        judge: 'judge',
        reporter: 'reporter',
      },
      records: [],
    };

    await store.writeSummary(summary);

    const storedEvents = (await readFile(join(root, 'run-2', 'events.jsonl'), 'utf8'))
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as { index: number; previousHash: string; hash: string });

    assert.equal(storedEvents.length, 3);
    assert.equal(storedEvents[0]?.index, 0);
    assert.equal(storedEvents[1]?.index, 1);
    assert.equal(storedEvents[2]?.index, 2);
    assert.equal(storedEvents[1]?.previousHash, storedEvents[0]?.hash);
    assert.equal(storedEvents[2]?.previousHash, storedEvents[1]?.hash);

    const loaded = await EvidenceStore.readSummary(join(root, 'run-2'));
    assert.equal(loaded.runId, 'run-2');
    assert.equal(loaded.runfileId, 'fixture');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('EvidenceStore writes investigation summaries, nested artifacts, and resumes hash chains from existing events', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-evidence-investigation-'));

  try {
    const runId = 'campaign-1';
    const firstStore = new EvidenceStore(runId, root);
    await firstStore.appendEvent('seeded', { step: 1 });

    const secondStore = new EvidenceStore(runId, root);
    await secondStore.prepare();
    await secondStore.appendEvent('resumed', { step: 2 });

    const report: InvestigationReportData = {
      campaignId: runId,
      targetId: 'fixture',
      targetLabel: 'Fixture',
      targetKind: 'code',
      environment: 'sandbox',
      mode: 'declared',
      startedAt: '2026-04-10T00:00:00.000Z',
      completedAt: '2026-04-10T00:01:00.000Z',
      iterations: 1,
      totalCostUsd: 0.12,
      signalsFound: 1,
      signalsDormant: 0,
      signalsReactivated: 0,
      hypothesesTested: 1,
      chainHypothesesTested: 0,
      directHypothesesTested: 1,
      hypothesesConfirmed: 0,
      hypothesesRefuted: 1,
      maxChainLength: 0,
      chainLengthDistribution: {},
      findings: [],
      topSignals: [],
      refutedHypotheses: [],
      telemetrySummary: 'fixture',
      executionStatus: 'complete',
      runMode: 'smoke',
      coverageGaps: [],
      requiredCoverageSatisfied: true,
    };

    const nestedJsonPath = await secondStore.writeJsonArtifact('nested/data/context.json', { ok: true });
    const nestedTextPath = await secondStore.writeTextArtifact('nested/logs/output.txt', 'nested');
    await secondStore.writeInvestigationSummary(report);

    const events = (await readFile(join(root, runId, 'events.jsonl'), 'utf8'))
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as { index: number; previousHash: string; hash: string; stage: string });

    assert.equal(events.length, 2);
    assert.equal(events[1]?.index, 1);
    assert.equal(events[1]?.previousHash, events[0]?.hash);
    assert.equal(nestedJsonPath, join(root, runId, 'nested', 'data', 'context.json'));
    assert.equal(nestedTextPath, join(root, runId, 'nested', 'logs', 'output.txt'));

    const storedSummary = JSON.parse(await readFile(join(root, runId, 'summary.json'), 'utf8')) as InvestigationReportData;
    assert.equal(storedSummary.campaignId, runId);
    assert.match(await readFile(join(root, runId, 'report.md'), 'utf8'), /Security Lab Investigation Report/);

    const manifest = JSON.parse(await readFile(join(root, runId, 'manifest.json'), 'utf8')) as {
      runId: string;
      files: Record<string, string>;
    };
    assert.equal(manifest.runId, runId);
    assert.ok(manifest.files['events.jsonl']);
    assert.ok(manifest.files['nested/data/context.json']);
    assert.ok(manifest.files['nested/logs/output.txt']);
    assert.ok(manifest.files['summary.json']);
    assert.ok(manifest.files['report.md']);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
