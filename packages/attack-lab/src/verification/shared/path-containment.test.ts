import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { assertWithinRootReal, isWithinRootReal, realpathOrResolved } from './path-containment.js';

test('ordinary paths inside the root are contained', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-contain-'));
  try {
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, 'src', 'app.ts'), 'export {};\n', 'utf8');

    assert.equal(isWithinRootReal(join(root, 'src', 'app.ts'), root), true);
    assert.equal(isWithinRootReal(root, root), true);
    assert.equal(isWithinRootReal(resolve(root, '..'), root), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('a symlink inside the root cannot be read through', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-contain-'));
  const outside = await mkdtemp(join(tmpdir(), 'security-lab-outside-'));
  try {
    await writeFile(join(outside, 'id_rsa'), 'PRIVATE', 'utf8');
    await mkdir(join(root, 'docs'), { recursive: true });
    await symlink(outside, join(root, 'docs', 'keys'));

    const throughLink = join(root, 'docs', 'keys', 'id_rsa');
    // The lexical check would allow this; the real one must not.
    assert.equal(isWithinRootReal(throughLink, root), false);
    assert.throws(() => assertWithinRootReal(throughLink, root, 'read path'), /escapes its sandbox/);
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test('a symlinked root is resolved before comparison', async () => {
  const base = await mkdtemp(join(tmpdir(), 'security-lab-contain-'));
  try {
    const real = join(base, 'real');
    await mkdir(real, { recursive: true });
    await writeFile(join(real, 'file.txt'), 'ok', 'utf8');
    const link = join(base, 'link');
    await symlink(real, link);

    // A path expressed through the symlinked root is still inside it.
    assert.equal(isWithinRootReal(join(link, 'file.txt'), link), true);
    assert.equal(isWithinRootReal(join(real, 'file.txt'), link), true);
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});

test('a path that does not exist falls back to the lexical answer', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-contain-'));
  try {
    assert.equal(isWithinRootReal(join(root, 'not-yet-created.txt'), root), true);
    assert.ok(realpathOrResolved(join(root, 'not-yet-created.txt')).endsWith('not-yet-created.txt'));
    // And a not-yet-created path outside the root is still refused.
    assert.equal(isWithinRootReal(join(root, '..', 'elsewhere.txt'), root), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
