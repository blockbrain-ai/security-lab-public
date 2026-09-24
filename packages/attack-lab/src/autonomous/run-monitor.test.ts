import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { RunMonitor } from './run-monitor.js';

// ---------------------------------------------------------------------------
// Event emission
// ---------------------------------------------------------------------------

test('RunMonitor records stage events', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'monitor-'));
  try {
    const monitor = new RunMonitor(dir);
    await monitor.prepare();

    await monitor.emitStageEnter('source');
    await monitor.emitStageExit('source', 5000);

    const events = monitor.getEvents();
    assert.equal(events.length, 2);
    assert.equal(events[0].kind, 'stage_enter');
    assert.equal(events[0].stage, 'source');
    assert.equal(events[1].kind, 'stage_exit');
    assert.equal(events[1].durationMs, 5000);
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('RunMonitor records candidate lifecycle', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'monitor-'));
  try {
    const monitor = new RunMonitor(dir);
    await monitor.prepare();

    await monitor.emitCandidateStart('c1', 'source');
    await monitor.emitCandidateEnd('c1', 'source', { status: 'supported' });

    const events = monitor.getEvents();
    assert.equal(events.length, 2);
    assert.equal(events[0].kind, 'candidate_start');
    assert.equal(events[0].candidateId, 'c1');
    assert.equal(events[1].kind, 'candidate_end');
    assert.ok(typeof events[1].durationMs === 'number');
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('RunMonitor records gate repairs', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'monitor-'));
  try {
    const monitor = new RunMonitor(dir);
    await monitor.prepare();

    await monitor.emitGateRepair('c1', 'format_truncated', true, 0);
    await monitor.emitGateRepair('c2', 'format_no_json', false, 0.01);

    const repairs = monitor.getGateRepairsByClass();
    assert.equal(repairs['format_truncated'].total, 1);
    assert.equal(repairs['format_truncated'].succeeded, 1);
    assert.equal(repairs['format_no_json'].total, 1);
    assert.equal(repairs['format_no_json'].succeeded, 0);
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('RunMonitor records validator downgrades', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'monitor-'));
  try {
    const monitor = new RunMonitor(dir);
    await monitor.prepare();

    await monitor.emitValidatorDowngrade('c1', 'supported', 'needs_runtime', ['Missing proof']);
    await monitor.emitValidatorDowngrade('c2', 'confirmed', 'not_reproducible', ['Fabricated']);

    assert.equal(monitor.getDowngradeCount(), 2);
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('RunMonitor records docker setup', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'monitor-'));
  try {
    const monitor = new RunMonitor(dir);
    await monitor.prepare();

    await monitor.emitDockerSetup(true, 3000);
    await monitor.emitDockerTeardown(500);

    const events = monitor.getEvents();
    assert.equal(events[0].kind, 'docker_setup');
    assert.equal(events[0].detail?.success, true);
    assert.equal(events[1].kind, 'docker_teardown');
  } finally {
    await rm(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// JSONL persistence
// ---------------------------------------------------------------------------

test('RunMonitor persists events to snapshots.jsonl', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'monitor-'));
  try {
    const monitor = new RunMonitor(dir);
    await monitor.prepare();

    await monitor.emitStageEnter('source');
    await monitor.emitCandidateStart('c1', 'source');
    await monitor.emitCandidateEnd('c1', 'source');

    const raw = await readFile(join(dir, 'monitoring', 'snapshots.jsonl'), 'utf8');
    const lines = raw.trim().split('\n');
    assert.equal(lines.length, 3);

    const first = JSON.parse(lines[0]);
    assert.equal(first.kind, 'stage_enter');
    assert.ok(first.at);
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('RunMonitor persists anomalies to anomalies.jsonl', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'monitor-'));
  try {
    const monitor = new RunMonitor(dir);
    await monitor.prepare();

    await monitor.recordAnomaly({
      at: new Date().toISOString(),
      kind: 'test_anomaly',
      severity: 'warning',
      detail: 'Test anomaly detail',
    });

    const raw = await readFile(join(dir, 'monitoring', 'anomalies.jsonl'), 'utf8');
    const lines = raw.trim().split('\n');
    assert.equal(lines.length, 1);
    const parsed = JSON.parse(lines[0]);
    assert.equal(parsed.kind, 'test_anomaly');
    assert.equal(parsed.severity, 'warning');
  } finally {
    await rm(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// Anomaly detection
// ---------------------------------------------------------------------------

test('RunMonitor detects excessive gate repairs', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'monitor-'));
  try {
    const monitor = new RunMonitor(dir);
    await monitor.prepare();

    await monitor.emitGateRepair('c1', 'format_truncated', true, 0);
    await monitor.emitGateRepair('c1', 'format_no_json', false, 0);
    assert.equal(monitor.getAnomalies().length, 0);

    await monitor.emitGateRepair('c1', 'format_schema_mismatch', false, 0);
    const anomalies = monitor.getAnomalies();
    assert.equal(anomalies.length, 1);
    assert.equal(anomalies[0].kind, 'excessive_gate_repairs');
    assert.equal(anomalies[0].candidateId, 'c1');
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('RunMonitor detects docker setup failure anomaly', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'monitor-'));
  try {
    const monitor = new RunMonitor(dir);
    await monitor.prepare();

    await monitor.emitDockerSetup(false, 1000);

    const anomalies = monitor.getAnomalies();
    assert.equal(anomalies.length, 1);
    assert.equal(anomalies[0].kind, 'docker_setup_failure');
    assert.equal(anomalies[0].severity, 'error');
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('RunMonitor detects high parse failure rate at run end', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'monitor-'));
  try {
    const monitor = new RunMonitor(dir);
    await monitor.prepare();

    await monitor.emitCandidateStart('c1', 'source');
    await monitor.emitGateRepair('c1', 'format_no_json', false, 0);
    await monitor.emitCandidateEnd('c1', 'source');

    await monitor.emitCandidateStart('c2', 'source');
    await monitor.emitGateRepair('c2', 'format_truncated', true, 0);
    await monitor.emitCandidateEnd('c2', 'source');

    await monitor.emitCandidateStart('c3', 'source');
    await monitor.emitCandidateEnd('c3', 'source');

    await monitor.emitRunEnd('success');

    const anomalies = monitor.getAnomalies();
    const highFailRate = anomalies.find((a) => a.kind === 'high_parse_failure_rate');
    assert.ok(highFailRate);
    assert.equal(highFailRate!.severity, 'error');
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('RunMonitor does not flag low parse failure rate', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'monitor-'));
  try {
    const monitor = new RunMonitor(dir);
    await monitor.prepare();

    await monitor.emitCandidateStart('c1', 'source');
    await monitor.emitGateRepair('c1', 'format_truncated', true, 0);
    await monitor.emitCandidateEnd('c1', 'source');

    await monitor.emitCandidateStart('c2', 'source');
    await monitor.emitCandidateEnd('c2', 'source');

    await monitor.emitCandidateStart('c3', 'source');
    await monitor.emitCandidateEnd('c3', 'source');

    await monitor.emitRunEnd('success');

    const anomalies = monitor.getAnomalies();
    const highFailRate = anomalies.find((a) => a.kind === 'high_parse_failure_rate');
    assert.equal(highFailRate, undefined);
  } finally {
    await rm(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// run start / end
// ---------------------------------------------------------------------------

test('RunMonitor run lifecycle', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'monitor-'));
  try {
    const monitor = new RunMonitor(dir);
    await monitor.prepare();

    await monitor.emitRunStart();
    await monitor.emitRunEnd('success');

    const events = monitor.getEvents();
    assert.equal(events[0].kind, 'run_start');
    assert.equal(events[1].kind, 'run_end');
    assert.equal(events[1].detail?.exitStatus, 'success');
  } finally {
    await rm(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// getCandidateGateRepairCount
// ---------------------------------------------------------------------------

test('getCandidateGateRepairCount tracks per-candidate repairs', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'monitor-'));
  try {
    const monitor = new RunMonitor(dir);
    await monitor.prepare();

    await monitor.emitGateRepair('c1', 'format_truncated', true, 0);
    await monitor.emitGateRepair('c1', 'format_no_json', false, 0);
    await monitor.emitGateRepair('c2', 'format_truncated', true, 0);

    assert.equal(monitor.getCandidateGateRepairCount('c1'), 2);
    assert.equal(monitor.getCandidateGateRepairCount('c2'), 1);
    assert.equal(monitor.getCandidateGateRepairCount('c3'), 0);
  } finally {
    await rm(dir, { recursive: true });
  }
});
