import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  fetchExcerpt,
  fetchExcerpts,
  redactCredentials,
  MAX_LINES_PER_EXCERPT,
  MAX_REFS_PER_HYPOTHESIS,
} from './source-excerpt-fetcher.js';
import type { SourceLocationRef } from '../../../evidence-plane/src/source-location-ref.js';

// ---------------------------------------------------------------------------
// redactCredentials
// ---------------------------------------------------------------------------

test('redactCredentials replaces long alphanumeric tokens', () => {
  const input = 'const key = "abcdefghijklmnopqrstuvwxyz1234567890abcdef";';
  const result = redactCredentials(input);
  assert.match(result, /\[REDACTED\]/);
  assert.ok(!result.includes('abcdefghijklmnopqrstuvwxyz1234567890'));
});

test('redactCredentials replaces Bearer tokens', () => {
  const input = 'Authorization: Bearer sk-proj-abc123def456';
  const result = redactCredentials(input);
  assert.match(result, /\[REDACTED\]/);
});

test('redactCredentials replaces password/secret assignments', () => {
  const input = 'password = "my_super_secret"';
  const result = redactCredentials(input);
  assert.match(result, /\[REDACTED\]/);
});

test('redactCredentials leaves short tokens alone', () => {
  const input = 'const id = "short";';
  const result = redactCredentials(input);
  assert.equal(result, input);
});

// ---------------------------------------------------------------------------
// fetchExcerpt
// ---------------------------------------------------------------------------

test('fetchExcerpt reads specified lines from a file', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'excerpt-'));
  try {
    const lines = Array.from({ length: 30 }, (_, i) => `line ${i + 1}`);
    await writeFile(join(dir, 'handler.ts'), lines.join('\n'), 'utf8');

    const ref: SourceLocationRef = { path: 'handler.ts', startLine: 5, endLine: 10 };
    const excerpt = await fetchExcerpt(ref, dir);

    assert.ok(excerpt != null);
    assert.equal(excerpt!.label, 'handler.ts:5-10');
    assert.equal(excerpt!.lineCount, 6);
    assert.match(excerpt!.content, /line 5/);
    assert.match(excerpt!.content, /line 10/);
    assert.ok(!excerpt!.content.includes('line 4'));
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('fetchExcerpt caps at MAX_LINES_PER_EXCERPT', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'excerpt-'));
  try {
    const lines = Array.from({ length: 100 }, (_, i) => `line ${i + 1}`);
    await writeFile(join(dir, 'big.ts'), lines.join('\n'), 'utf8');

    const ref: SourceLocationRef = { path: 'big.ts', startLine: 1, endLine: 100 };
    const excerpt = await fetchExcerpt(ref, dir);

    assert.ok(excerpt != null);
    assert.equal(excerpt!.lineCount, MAX_LINES_PER_EXCERPT);
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('fetchExcerpt returns undefined for missing files', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'excerpt-'));
  try {
    const ref: SourceLocationRef = { path: 'nonexistent.ts', startLine: 1 };
    const excerpt = await fetchExcerpt(ref, dir);
    assert.equal(excerpt, undefined);
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('fetchExcerpt redacts credentials in output', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'excerpt-'));
  try {
    const content = 'const secret = "abcdefghijklmnopqrstuvwxyz1234567890abcdef";\nconst name = "ok";';
    await writeFile(join(dir, 'secrets.ts'), content, 'utf8');

    const ref: SourceLocationRef = { path: 'secrets.ts', startLine: 1, endLine: 2 };
    const excerpt = await fetchExcerpt(ref, dir);

    assert.ok(excerpt != null);
    assert.match(excerpt!.content, /\[REDACTED\]/);
    assert.ok(!excerpt!.content.includes('abcdefghijklmnopqrstuvwxyz1234567890'));
  } finally {
    await rm(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// fetchExcerpts
// ---------------------------------------------------------------------------

test('fetchExcerpts bounds to MAX_REFS_PER_HYPOTHESIS', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'excerpt-'));
  try {
    await writeFile(join(dir, 'a.ts'), 'line 1\nline 2', 'utf8');

    const refs: SourceLocationRef[] = Array.from(
      { length: MAX_REFS_PER_HYPOTHESIS + 3 },
      () => ({ path: 'a.ts', startLine: 1, endLine: 2 }),
    );

    const excerpts = await fetchExcerpts(refs, dir);
    assert.ok(excerpts.length <= MAX_REFS_PER_HYPOTHESIS);
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('fetchExcerpts skips missing files', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'excerpt-'));
  try {
    await writeFile(join(dir, 'exists.ts'), 'hello', 'utf8');

    const refs: SourceLocationRef[] = [
      { path: 'exists.ts', startLine: 1 },
      { path: 'missing.ts', startLine: 1 },
    ];

    const excerpts = await fetchExcerpts(refs, dir);
    assert.equal(excerpts.length, 1);
    assert.equal(excerpts[0]!.label, 'exists.ts:1');
  } finally {
    await rm(dir, { recursive: true });
  }
});
