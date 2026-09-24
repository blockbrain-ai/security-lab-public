/**
 * Integrity tests for the evidence store: append ordering, torn-tail
 * tolerance, chain verification, atomic artifacts, path containment,
 * draining and manifest freshness.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { appendFile, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EvidenceStore, EvidenceStreamCorruptionError } from './store.js';

async function makeRun(): Promise<{ root: string; runId: string; store: EvidenceStore }> {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-integrity-'));
  const runId = 'run-integrity';
  return { root, runId, store: new EvidenceStore(runId, root) };
}

async function readLines(path: string): Promise<string[]> {
  const raw = await readFile(path, 'utf8');
  return raw.split('\n').filter((line) => line.length > 0);
}

interface StoredEvent {
  index: number;
  previousHash: string;
  hash: string;
  stage: string;
  payload: Record<string, unknown>;
}

async function readEvents(path: string): Promise<StoredEvent[]> {
  return (await readLines(path)).map((line) => JSON.parse(line) as StoredEvent);
}

async function captureStderr<T>(operation: () => Promise<T>): Promise<{ result: T; stderr: string }> {
  const original = process.stderr.write;
  let captured = '';
  process.stderr.write = ((chunk: unknown) => {
    captured += String(chunk);
    return true;
  }) as typeof process.stderr.write;
  try {
    const result = await operation();
    return { result, stderr: captured };
  } finally {
    process.stderr.write = original;
  }
}

test('appendEvent persists before committing: a failed write leaves the chain untouched', async () => {
  const { root, runId, store } = await makeRun();
  const eventsPath = join(root, runId, 'events.jsonl');

  try {
    await store.appendEvent('started', { n: 1 });
    const durable = await readFile(eventsPath, 'utf8');

    // Make the next append fail: events.jsonl becomes a directory, so the
    // filesystem refuses to open it for appending (EISDIR).
    await rm(eventsPath);
    await mkdir(eventsPath);
    await assert.rejects(
      store.appendEvent('poisoned', { n: 2 }),
      (error: NodeJS.ErrnoException) => error.code === 'EISDIR',
    );

    // The failed write must not have advanced the in-memory chain...
    const afterFailure = await store.verifyChain();
    assert.equal(afterFailure.valid, true);
    assert.equal(afterFailure.eventCount, 1);

    // ...and the write queue must survive the rejected operation.
    await rm(eventsPath, { recursive: true });
    await writeFile(eventsPath, durable, 'utf8');
    await store.appendEvent('recovered', { n: 3 });

    const events = await readEvents(eventsPath);
    assert.equal(events.length, 2);
    assert.deepEqual(
      events.map((event) => event.index),
      [0, 1],
    );
    assert.equal(events[0]?.previousHash, '');
    assert.equal(events[1]?.previousHash, events[0]?.hash);
    assert.ok(!JSON.stringify(events).includes('poisoned'));

    const verification = await store.verifyChain();
    assert.equal(verification.valid, true);
    assert.equal(verification.eventCount, 2);
    assert.equal(verification.headHash, events[1]?.hash);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('drain waits for queued writes and resolves after a rejected operation', async () => {
  const { root, runId, store } = await makeRun();
  const eventsPath = join(root, runId, 'events.jsonl');

  try {
    const pending = [
      store.appendEvent('one', { n: 1 }),
      store.appendEvent('two', { n: 2 }),
      store.appendEvent('three', { n: 3 }),
    ];
    await store.drain();
    await Promise.all(pending);

    assert.equal((await readEvents(eventsPath)).length, 3);

    // A rejected queued operation must not wedge the drain barrier.
    await rm(eventsPath);
    await mkdir(eventsPath);
    const failing = store.appendEvent('boom', { n: 4 });
    await assert.rejects(failing);
    await store.drain();

    await rm(eventsPath, { recursive: true });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('loadExistingEvents repairs a torn tail, logs it, and resumes without restarting at index 0', async () => {
  const { root, runId, store } = await makeRun();
  const eventsPath = join(root, runId, 'events.jsonl');

  try {
    await store.appendEvent('started', { n: 1 });
    await store.appendEvent('observed', { n: 2 });
    const complete = await readFile(eventsPath, 'utf8');

    // Simulate a crash mid-append: a partial record with no terminating newline.
    await writeFile(eventsPath, `${complete}{"index":2,"previousHash":"deadbeef","hash":"cafe`, 'utf8');

    const resumedStore = new EvidenceStore(runId, root);
    const { stderr } = await captureStderr(async () => {
      await resumedStore.prepare();
      await resumedStore.appendEvent('resumed', { n: 3 });
    });

    // The recovery is reported, never swallowed.
    assert.match(stderr, /events\.jsonl/);
    assert.match(stderr, /dropped a torn \d+-byte tail/);
    const recoveries = resumedStore.getRecoveryDiagnostics();
    assert.equal(recoveries.length, 1);
    assert.equal(recoveries[0]?.kind, 'torn_tail_dropped');
    assert.equal(recoveries[0]?.retainedEventCount, 2);

    // Every line parses and nothing concatenated onto the fragment.
    const raw = await readFile(eventsPath, 'utf8');
    assert.ok(raw.endsWith('\n'));
    const events = await readEvents(eventsPath);
    assert.equal(events.length, 3);
    assert.deepEqual(
      events.map((event) => event.index),
      [0, 1, 2],
    );
    assert.equal(events[1]?.previousHash, events[0]?.hash);
    assert.equal(events[2]?.previousHash, events[1]?.hash);
    assert.ok(!raw.includes('cafe'));

    const verification = await resumedStore.verifyChain();
    assert.equal(verification.valid, true);
    assert.equal(verification.eventCount, 3);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('a torn first record is dropped explicitly and the repaired stream restarts cleanly', async () => {
  const { root, runId } = await makeRun();
  const runDir = join(root, runId);
  const eventsPath = join(runDir, 'events.jsonl');

  try {
    await mkdir(runDir, { recursive: true });
    await writeFile(eventsPath, '{"index":0,"previousHash":"', 'utf8');

    const store = new EvidenceStore(runId, root);
    const { stderr } = await captureStderr(async () => {
      await store.prepare();
      await store.appendEvent('first', { n: 1 });
    });

    assert.match(stderr, /dropped a torn/);
    const events = await readEvents(eventsPath);
    assert.equal(events.length, 1);
    assert.equal(events[0]?.index, 0);
    assert.equal(events[0]?.previousHash, '');
    assert.equal((await store.verifyChain()).valid, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('a newline-terminated but unparseable final line is dropped and reported', async () => {
  const { root, runId, store } = await makeRun();
  const eventsPath = join(root, runId, 'events.jsonl');

  try {
    await store.appendEvent('started', { n: 1 });
    await appendFile(eventsPath, '{"index":1,"previousHash":\n', 'utf8');

    const resumed = new EvidenceStore(runId, root);
    const { stderr } = await captureStderr(() => resumed.prepare());

    assert.match(stderr, /dropped an unparseable final line/);
    assert.equal(resumed.getRecoveryDiagnostics()[0]?.kind, 'unparseable_final_line_dropped');

    await resumed.appendEvent('resumed', { n: 2 });
    const events = await readEvents(eventsPath);
    assert.deepEqual(
      events.map((event) => event.index),
      [0, 1],
    );
    assert.equal((await resumed.verifyChain()).valid, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('mid-stream corruption fails closed instead of appending or restarting at index 0', async () => {
  const { root, runId, store } = await makeRun();
  const eventsPath = join(root, runId, 'events.jsonl');

  try {
    await store.appendEvent('started', { n: 1 });
    await store.appendEvent('observed', { n: 2 });
    const lines = await readLines(eventsPath);
    const corrupted = `${lines[0]}\nnot-json-at-all\n${lines[1]}\n`;
    await writeFile(eventsPath, corrupted, 'utf8');

    const resumed = new EvidenceStore(runId, root);
    await assert.rejects(
      resumed.appendEvent('resumed', { n: 3 }),
      (error: unknown) => error instanceof EvidenceStreamCorruptionError,
    );
    await assert.rejects(resumed.verifyChain(), (error: unknown) => {
      return error instanceof EvidenceStreamCorruptionError && error.lineNumber === 1;
    });

    // The corrupted stream is untouched: no diagnostics appended to it.
    assert.equal(await readFile(eventsPath, 'utf8'), corrupted);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('verifyChain reports index mismatches caused by truncating a middle record', async () => {
  const { root, runId, store } = await makeRun();
  const eventsPath = join(root, runId, 'events.jsonl');

  try {
    await store.appendEvent('one', { n: 1 });
    await store.appendEvent('two', { n: 2 });
    await store.appendEvent('three', { n: 3 });
    const lines = await readLines(eventsPath);

    // Drop the middle record: linkage of the survivors stays plausible, so
    // only the positional index check can catch it.
    await writeFile(eventsPath, `${lines[0]}\n${lines[2]}\n`, 'utf8');

    const verification = await new EvidenceStore(runId, root).verifyChain();
    assert.equal(verification.valid, false);
    assert.match(verification.errors.join('\n'), /index mismatch/);
    assert.equal(verification.eventCount, 2);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('verifyChain detects tampered payloads on disk', async () => {
  const { root, runId, store } = await makeRun();
  const eventsPath = join(root, runId, 'events.jsonl');

  try {
    await store.appendEvent('started', { n: 1 });
    await store.appendEvent('observed', { n: 2 });
    const events = await readEvents(eventsPath);
    // Tamper the first payload: its own hash no longer matches, which in turn
    // breaks the linkage recorded by the second event.
    events[0]!.payload = { n: 999 };
    events[1]!.payload = { n: 999 };
    await writeFile(eventsPath, `${events.map((event) => JSON.stringify(event)).join('\n')}\n`, 'utf8');

    const verification = await new EvidenceStore(runId, root).verifyChain();
    assert.equal(verification.valid, false);
    assert.match(verification.errors.join('\n'), /Event 0: hash mismatch/);
    assert.match(verification.errors.join('\n'), /Event 1: hash mismatch/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('verifyChain read-only mode reports a torn tail as an error without touching the file', async () => {
  const { root, runId, store } = await makeRun();
  const eventsPath = join(root, runId, 'events.jsonl');

  try {
    await store.appendEvent('started', { n: 1 });
    const complete = await readFile(eventsPath, 'utf8');
    const torn = `${complete}{"index":1,"previousHash":"ab`;
    await writeFile(eventsPath, torn, 'utf8');

    const verification = await new EvidenceStore(runId, root).verifyChain({ repairTornTail: false });
    assert.equal(verification.valid, false);
    assert.match(verification.errors.join('\n'), /truncated/);
    assert.equal(verification.recoveries.length, 1);

    // Verification must not mutate evidence.
    assert.equal(await readFile(eventsPath, 'utf8'), torn);

    // The default (repairing) mode logs the recovery and reports a valid
    // prefix chain.
    const repairing = await captureStderr(
      () => new EvidenceStore(runId, root).verifyChain(),
    );
    assert.match(repairing.stderr, /dropped a torn/);
    assert.equal(repairing.result.valid, true);
    assert.equal(repairing.result.eventCount, 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('verifyChain checks the manifest checkpoint for prefix consistency', async () => {
  const { root, runId, store } = await makeRun();
  const eventsPath = join(root, runId, 'events.jsonl');

  try {
    await store.appendEvent('started', { n: 1 });
    await store.appendEvent('observed', { n: 2 });
    await store.writeManifest(runId);

    const manifest = await EvidenceStore.readManifest(join(root, runId));
    assert.equal(manifest.eventCount, 2);
    const checkpoint = { eventCount: manifest.eventCount, headHash: manifest.headHash };

    // Appending after the manifest keeps the recorded checkpoint a valid
    // prefix of the chain.
    await store.appendEvent('later', { n: 3 });
    const consistent = await new EvidenceStore(runId, root).verifyChain({ checkpoint });
    assert.equal(consistent.valid, true);
    assert.equal(consistent.eventCount, 3);

    // Truncating the stream below the recorded checkpoint is detected.
    const lines = await readLines(eventsPath);
    await writeFile(eventsPath, `${lines[0]}\n`, 'utf8');
    const truncated = await new EvidenceStore(runId, root).verifyChain({ checkpoint });
    assert.equal(truncated.valid, false);
    assert.match(truncated.errors.join('\n'), /truncation detected/);

    // Rewriting the recorded position with a different event is detected too.
    await writeFile(eventsPath, `${lines[1]}\n`, 'utf8');
    const rewritten = await new EvidenceStore(runId, root).verifyChain({ checkpoint });
    assert.equal(rewritten.valid, false);
    assert.match(rewritten.errors.join('\n'), /checkpoint head mismatch|index mismatch/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('writeManifest records the chain position and file hashes of the moment it is written', async () => {
  const { root, runId, store } = await makeRun();
  const eventsPath = join(root, runId, 'events.jsonl');

  try {
    await store.appendEvent('started', { n: 1 });
    await store.appendEvent('observed', { n: 2 });
    await store.writeManifest(runId);

    const raw = await readFile(eventsPath, 'utf8');
    const manifest = await EvidenceStore.readManifest(join(root, runId));
    const events = await readEvents(eventsPath);

    assert.equal(manifest.eventCount, events.length);
    assert.equal(manifest.headHash, events[events.length - 1]?.hash);
    assert.equal(
      manifest.files['events.jsonl'],
      createHash('sha256').update(raw).digest('hex'),
    );
    assert.equal(manifest.files['manifest.json'], undefined);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('readManifest keeps backward compatibility with manifests written before freshness fields', async () => {
  const { root, runId } = await makeRun();
  const runDir = join(root, runId);

  try {
    await mkdir(runDir, { recursive: true });
    await writeFile(
      join(runDir, 'manifest.json'),
      JSON.stringify({ runId, generatedAt: '2026-04-10T00:00:00.000Z', files: { 'events.jsonl': 'abc' } }),
      'utf8',
    );

    const manifest = await EvidenceStore.readManifest(runDir);
    assert.equal(manifest.runId, runId);
    assert.deepEqual(manifest.files, { 'events.jsonl': 'abc' });
    assert.equal(manifest.eventCount, undefined);
    assert.equal(manifest.headHash, undefined);

    // A legacy manifest cannot pin the chain, so verification still succeeds.
    const store = new EvidenceStore(runId, root);
    await store.appendEvent('started', { n: 1 });
    const verification = await store.verifyChain({
      checkpoint: { eventCount: manifest.eventCount, headHash: manifest.headHash },
    });
    assert.equal(verification.valid, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('artifact writers reject paths that escape the run directory', async () => {
  const { root, runId, store } = await makeRun();

  try {
    await store.prepare();
    await assert.rejects(store.writeJsonArtifact('../../escape.json', { ok: true }), /escapes the run directory/);
    await assert.rejects(store.writeTextArtifact('../sibling.md', 'nope'), /escapes the run directory/);
    await assert.rejects(store.writeJsonArtifact(join(root, '..', 'absolute.json'), {}), /escapes the run directory/);

    await assert.rejects(readFile(join(root, 'escape.json'), 'utf8'), (error: NodeJS.ErrnoException) => {
      return error.code === 'ENOENT';
    });
    assert.deepEqual(await readdir(join(root, runId)), []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('artifact writers replace files atomically and leave no temp files behind', async () => {
  const { root, runId, store } = await makeRun();
  const runDir = join(root, runId);

  try {
    await store.writeTextArtifact('report.md', 'first');
    const before = await stat(join(runDir, 'report.md'));
    await store.writeTextArtifact('report.md', 'second');
    const after = await stat(join(runDir, 'report.md'));

    assert.equal(await readFile(join(runDir, 'report.md'), 'utf8'), 'second');
    // Truncate-in-place keeps the inode; temp-file + rename replaces it.
    assert.notEqual(after.ino, before.ino);
    assert.deepEqual((await readdir(runDir)).filter((name) => name.endsWith('.tmp')), []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('a failed artifact replacement cleans up its temp file and keeps the previous good artifact', async () => {
  const { root, runId, store } = await makeRun();
  const runDir = join(root, runId);

  try {
    await store.writeTextArtifact('report.md', 'good');
    // Renaming onto a directory fails, exercising the cleanup path.
    await mkdir(join(runDir, 'summary.json'));
    await assert.rejects(store.writeTextArtifact('summary.json', 'bad'), (error: NodeJS.ErrnoException) => {
      return ['EISDIR', 'ENOTDIR', 'EPERM', 'EACCES', 'EEXIST', 'ENOTEMPTY'].includes(error.code ?? '');
    });

    assert.equal(await readFile(join(runDir, 'report.md'), 'utf8'), 'good');
    assert.deepEqual((await readdir(runDir)).filter((name) => name.endsWith('.tmp')), []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('writeJsonArtifact creates nested directories and round-trips structured data', async () => {
  const { root, runId, store } = await makeRun();

  try {
    const path = await store.writeJsonArtifact('nested/deep/context.json', { ok: true, n: 2 });
    assert.equal(path, join(root, runId, 'nested', 'deep', 'context.json'));
    assert.deepEqual(JSON.parse(await readFile(path, 'utf8')), { ok: true, n: 2 });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('forRunDir binds a store to an existing run directory', async () => {
  const { root, runId } = await makeRun();

  try {
    const created = new EvidenceStore(runId, root);
    await created.appendEvent('started', { n: 1 });

    const bound = EvidenceStore.forRunDir(join(root, runId));
    assert.equal(bound.paths.runDir, join(root, runId));
    const verification = await bound.verifyChain();
    assert.equal(verification.valid, true);
    assert.equal(verification.eventCount, 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
