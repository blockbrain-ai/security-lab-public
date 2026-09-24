import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execSync } from 'node:child_process';
import {
  captureGitState,
  computeConfigHash,
  createManifest,
  finalizeManifest,
  writeManifest,
  readManifest,
  VerificationManifestSchema,
} from './verification-manifest.js';

// ---------------------------------------------------------------------------
// captureGitState
// ---------------------------------------------------------------------------

test('captureGitState returns valid state from a git repo', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'manifest-git-'));
  try {
    execSync('git init && git -c user.name=security-lab -c user.email=security-lab@localhost commit --allow-empty -m "init"', {
      cwd: dir,
      timeout: 5000,
    });
    const state = captureGitState(dir);
    assert.ok(state.commitHash.length >= 7);
    assert.ok(state.branch.length > 0);
    assert.equal(state.isDirty, false);
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('captureGitState returns fallback for non-git directory', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'manifest-nogit-'));
  try {
    const state = captureGitState(dir);
    assert.equal(state.commitHash, 'unknown');
    assert.equal(state.branch, 'unknown');
    assert.equal(state.isDirty, true);
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('captureGitState detects dirty state', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'manifest-dirty-'));
  try {
    execSync('git init && git -c user.name=security-lab -c user.email=security-lab@localhost commit --allow-empty -m "init"', {
      cwd: dir,
      timeout: 5000,
    });
    execSync('echo "hello" > untracked.txt', { cwd: dir });
    const state = captureGitState(dir);
    assert.equal(state.isDirty, true);
  } finally {
    await rm(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// computeConfigHash
// ---------------------------------------------------------------------------

test('computeConfigHash is deterministic', () => {
  const input = {
    lanes: {
      source: { provider: 'bounded_local', model: 'qwen3.6-27b' },
      runtime: { provider: 'bounded_local', model: 'qwen3.6-27b' },
    },
    mode: 'full',
    candidateLimit: 5,
  };
  const hash1 = computeConfigHash(input);
  const hash2 = computeConfigHash(input);
  assert.equal(hash1, hash2);
  assert.equal(hash1.length, 16);
});

test('computeConfigHash changes when model changes', () => {
  const base = {
    lanes: {
      source: { provider: 'bounded_local', model: 'qwen3.6-27b' },
    },
    mode: 'source',
  };
  const variant = {
    lanes: {
      source: { provider: 'bounded_local', model: 'deepseek-r1:14b' },
    },
    mode: 'source',
  };
  assert.notEqual(computeConfigHash(base), computeConfigHash(variant));
});

test('computeConfigHash changes when mode changes', () => {
  const lanes = {
    source: { provider: 'bounded_local', model: 'qwen3.6-27b' },
  };
  assert.notEqual(
    computeConfigHash({ lanes, mode: 'source' }),
    computeConfigHash({ lanes, mode: 'full' }),
  );
});

test('computeConfigHash changes when candidateLimit changes', () => {
  const lanes = {
    source: { provider: 'bounded_local', model: 'qwen3.6-27b' },
  };
  assert.notEqual(
    computeConfigHash({ lanes, mode: 'source', candidateLimit: 5 }),
    computeConfigHash({ lanes, mode: 'source', candidateLimit: 10 }),
  );
});

test('computeConfigHash ignores nested object key order', () => {
  const hashA = computeConfigHash({
    lanes: {
      source: {
        provider: 'bounded_local',
        model: 'qwen3.6-27b',
        baseUrl: 'http://127.0.0.1:8080/v1',
      },
      runtime: {
        provider: 'bounded_local',
        model: 'qwen3.6-27b',
      },
    },
    mode: 'full',
    candidateLimit: 5,
  });

  const hashB = computeConfigHash({
    lanes: {
      runtime: {
        model: 'qwen3.6-27b',
        provider: 'bounded_local',
      },
      source: {
        baseUrl: 'http://127.0.0.1:8080/v1',
        model: 'qwen3.6-27b',
        provider: 'bounded_local',
      },
    },
    mode: 'full',
    candidateLimit: 5,
  });

  assert.equal(hashA, hashB);
});

// ---------------------------------------------------------------------------
// createManifest + finalizeManifest
// ---------------------------------------------------------------------------

test('createManifest produces a valid manifest', () => {
  const manifest = createManifest({
    campaignId: 'inv-test',
    targetId: 'test-target',
    mode: 'source',
    repoRoot: process.cwd(),
    lanes: {
      source: { provider: 'bounded_local', model: 'qwen3.6-27b' },
    },
    cliOptions: { skipAudit: true },
  });

  const parsed = VerificationManifestSchema.parse(manifest);
  assert.ok(parsed.runId.startsWith('verify-'));
  assert.equal(parsed.targetId, 'test-target');
  assert.equal(parsed.mode, 'source');
  assert.ok(parsed.startedAt);
  assert.equal(parsed.finalizedAt, undefined);
  assert.equal(parsed.configHash.length, 16);
});

test('finalizeManifest stamps exit fields', () => {
  const manifest = createManifest({
    targetId: 'test-target',
    mode: 'source',
    repoRoot: process.cwd(),
    lanes: { source: { provider: 'bounded_local', model: 'qwen3.6-27b' } },
    cliOptions: {},
  });

  const finalized = finalizeManifest(manifest, {
    exitStatus: 'success',
    artifactPaths: { source: '/tmp/source-verification.json' },
    telemetrySummary: {
      totalCostUsd: 0,
      totalInputTokens: 1000,
      totalOutputTokens: 500,
      invocationCount: 3,
    },
  });

  assert.ok(finalized.finalizedAt);
  assert.ok(typeof finalized.durationMs === 'number');
  assert.equal(finalized.exitStatus, 'success');
  assert.equal(finalized.artifactPaths.source, '/tmp/source-verification.json');
  assert.equal(finalized.telemetrySummary?.totalInputTokens, 1000);
});

// ---------------------------------------------------------------------------
// Write / read round-trip
// ---------------------------------------------------------------------------

test('writeManifest + readManifest round-trip', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'manifest-rw-'));
  try {
    const manifest = createManifest({
      targetId: 'roundtrip-target',
      mode: 'full',
      repoRoot: process.cwd(),
      lanes: {
        source: { provider: 'bounded_local', model: 'qwen3.6-27b' },
        runtime: { provider: 'bounded_local', model: 'qwen3.6-27b' },
      },
      cliOptions: { candidateLimit: 3 },
      profileId: 'qwen_default',
    });

    const path = await writeManifest(dir, manifest);
    const loaded = await readManifest(path);

    assert.equal(loaded.runId, manifest.runId);
    assert.equal(loaded.targetId, 'roundtrip-target');
    assert.equal(loaded.mode, 'full');
    assert.equal(loaded.profileId, 'qwen_default');
    assert.equal(loaded.configHash, manifest.configHash);
    assert.deepEqual(loaded.lanes, manifest.lanes);
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('writeManifest produces valid JSON file', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'manifest-json-'));
  try {
    const manifest = createManifest({
      targetId: 'json-target',
      mode: 'source',
      repoRoot: process.cwd(),
      lanes: { source: { provider: 'bounded_local', model: 'qwen3.6-27b' } },
      cliOptions: {},
    });
    const path = await writeManifest(dir, manifest);
    const raw = await readFile(path, 'utf8');
    const parsed = JSON.parse(raw);
    assert.equal(parsed.schemaVersion, 1);
    assert.equal(parsed.targetId, 'json-target');
  } finally {
    await rm(dir, { recursive: true });
  }
});
