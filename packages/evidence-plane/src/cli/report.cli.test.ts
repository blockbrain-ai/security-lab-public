/**
 * CLI tests for the report entry point's `--verify` path. The CLI is spawned
 * as a child process because importing the module would run `main()`.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { EvidenceStore } from '../store.js';
import type { RunSummary } from '../contracts.js';

const PACKAGE_ROOT = fileURLToPath(new URL('../..', import.meta.url));
const CLI_PATH = fileURLToPath(new URL('./report.ts', import.meta.url));

interface CliResult {
  code: number;
  stdout: string;
  stderr: string;
}

function runCli(...args: string[]): Promise<CliResult> {
  return new Promise((resolvePromise, rejectPromise) => {
    execFile(
      process.execPath,
      ['--import', 'tsx', CLI_PATH, ...args],
      { cwd: PACKAGE_ROOT },
      (error, stdout, stderr) => {
        const exitCode = error ? (error as { code?: unknown }).code : 0;
        if (typeof exitCode !== 'number') {
          rejectPromise(error ?? new Error('CLI failed without an exit code'));
          return;
        }
        resolvePromise({ code: exitCode, stdout, stderr });
      },
    );
  });
}

function fixtureSummary(runId: string): RunSummary {
  return {
    runId,
    runfileId: 'fixture',
    runfileName: 'Fixture',
    mode: 'declared',
    startedAt: '2026-04-10T00:00:00.000Z',
    completedAt: '2026-04-10T00:01:00.000Z',
    scenarioCount: 0,
    passed: 0,
    failed: 0,
    targetEnvironments: ['sandbox'],
    orchestration: { planner: 'planner', executor: 'executor', judge: 'judge', reporter: 'reporter' },
    records: [],
  };
}

test('report CLI exits non-zero for an invalid chain and zero for a valid one', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-cli-verify-'));
  const runId = 'cli-run';
  const eventsPath = join(root, runId, 'events.jsonl');

  try {
    const store = new EvidenceStore(runId, root);
    await store.appendEvent('started', { n: 1 });
    await store.appendEvent('observed', { n: 2 });
    await store.writeManifest(runId);

    const valid = await runCli('--verify', join(root, runId));
    assert.equal(valid.code, 0, valid.stderr);
    assert.match(valid.stdout, /Chain valid: 2 event\(s\), head [0-9a-f]{64}/);

    // The relative path form is resolved from the repository root, so pass an
    // absolute path when tampering to keep the test independent of cwd.
    const events = (await readFile(eventsPath, 'utf8')).trim().split('\n');
    const tampered = JSON.parse(events[0]!) as { payload: Record<string, unknown> };
    tampered.payload = { n: 'tampered' };
    await writeFile(eventsPath, `${JSON.stringify(tampered)}\n${events[1]}\n`, 'utf8');

    const invalid = await runCli('--verify', join(root, runId));
    assert.equal(invalid.code, 1);
    assert.match(invalid.stderr, /Chain invalid/);
    assert.match(invalid.stderr, /hash mismatch/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('report CLI --verify detects truncation against the manifest checkpoint without repairing it', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-cli-checkpoint-'));
  const runId = 'cli-checkpoint';
  const eventsPath = join(root, runId, 'events.jsonl');

  try {
    const store = new EvidenceStore(runId, root);
    await store.appendEvent('started', { n: 1 });
    await store.appendEvent('observed', { n: 2 });
    await store.writeManifest(runId);

    const lines = (await readFile(eventsPath, 'utf8')).trim().split('\n');
    const truncatedContent = `${lines[0]}\n`;
    await writeFile(eventsPath, truncatedContent, 'utf8');

    const result = await runCli('--verify', join(root, runId));
    assert.equal(result.code, 1);
    assert.match(result.stderr, /truncation detected/);
    // Verification is read-only: the truncated evidence is left untouched.
    assert.equal(await readFile(eventsPath, 'utf8'), truncatedContent);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('report CLI --verify reports a torn tail as invalid and does not modify the stream', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-cli-torn-'));
  const runId = 'cli-torn';
  const eventsPath = join(root, runId, 'events.jsonl');

  try {
    const store = new EvidenceStore(runId, root);
    await store.appendEvent('started', { n: 1 });
    const complete = await readFile(eventsPath, 'utf8');
    const torn = `${complete}{"index":1,"previousHash":"ab`;
    await writeFile(eventsPath, torn, 'utf8');

    const result = await runCli('--verify', join(root, runId));
    assert.equal(result.code, 1);
    assert.match(result.stderr, /truncated/);
    assert.equal(await readFile(eventsPath, 'utf8'), torn);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('report CLI renders the console summary without --verify', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-cli-summary-'));
  const runId = 'cli-summary';

  try {
    const store = new EvidenceStore(runId, root);
    await store.writeSummary(fixtureSummary(runId));

    const result = await runCli(join(root, runId));
    assert.equal(result.code, 0, result.stderr);
    assert.match(result.stdout, /Run: cli-summary/);
    assert.match(result.stdout, /Runfile: fixture \(Fixture\)/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('report CLI fails with usage text when no run directory is given', async () => {
  const result = await runCli('--verify');

  assert.equal(result.code, 1);
  assert.match(result.stderr, /Usage: npm run evidence:report -- <run-dir> \[--verify\]/);
});

test('report CLI verifies a run directory with no events file as an empty chain', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-cli-empty-'));
  const runId = 'cli-empty';

  try {
    await mkdir(join(root, runId), { recursive: true });

    const result = await runCli('--verify', join(root, runId));
    assert.equal(result.code, 0);
    assert.match(result.stdout, /Chain valid: 0 event\(s\), head \(empty\)/);
    assert.match(result.stderr, /no manifest\.json/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('report CLI resolves a relative run directory from the repository root', async () => {
  const fixtureName = '.tmp-cli-relative-fixture';
  const relative = join('packages', 'evidence-plane', 'src', fixtureName);

  try {
    const store = new EvidenceStore(fixtureName, join(PACKAGE_ROOT, 'src'));
    await store.appendEvent('started', { n: 1 });
    await store.writeManifest(fixtureName);

    const result = await runCli('--verify', relative);
    assert.equal(result.code, 0, result.stderr);
    assert.match(result.stdout, /Chain valid: 1 event\(s\)/);
  } finally {
    await rm(resolve(PACKAGE_ROOT, 'src', fixtureName), { recursive: true, force: true });
  }
});
