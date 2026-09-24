import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runCodeProbe } from './code-probe.js';

test('runCodeProbe reads in-root files and blocks traversal', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-code-probe-'));

  try {
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, 'src', 'app.ts'), 'export const bypassPermissions = true;\n', 'utf8');

    const allowed = await runCodeProbe(
      {
        kind: 'code_read',
        action: 'read_file',
        filePath: 'src/app.ts',
        timeoutMs: 1000,
      },
      {
        kind: 'code',
        id: 'fixture',
        environment: 'sandbox',
        repoRoot: root,
      },
    );

    assert.equal(allowed.exitCode, 0);
    assert.match(allowed.stdout ?? '', /bypassPermissions/);

    const blocked = await runCodeProbe(
      {
        kind: 'code_read',
        action: 'read_file',
        filePath: '../etc/passwd',
        timeoutMs: 1000,
      },
      {
        kind: 'code',
        id: 'fixture',
        environment: 'sandbox',
        repoRoot: root,
      },
    );

    assert.equal(blocked.exitCode, 1);
    assert.match(blocked.stderr ?? '', /path traversal|outside target root/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('runCodeProbe honours include/exclude scopes for listing and search', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-code-scope-'));

  try {
    await mkdir(join(root, 'src'), { recursive: true });
    await mkdir(join(root, 'docs'), { recursive: true });
    await writeFile(join(root, 'src', 'app.ts'), 'export const route = "/private";\n', 'utf8');
    await writeFile(join(root, 'docs', 'notes.ts'), 'export const route = "/docs";\n', 'utf8');

    const list = await runCodeProbe(
      {
        kind: 'code_read',
        action: 'list_dir',
        timeoutMs: 1000,
      },
      {
        kind: 'code',
        id: 'fixture',
        environment: 'sandbox',
        repoRoot: root,
        includePaths: ['src'],
        excludePaths: ['docs'],
      },
    );

    assert.equal(list.exitCode, 0);
    assert.match(list.stdout ?? '', /src\/app\.ts/);
    assert.doesNotMatch(list.stdout ?? '', /docs\/notes\.ts/);

    const search = await runCodeProbe(
      {
        kind: 'code_read',
        action: 'search_pattern',
        pattern: 'route',
        timeoutMs: 1000,
      },
      {
        kind: 'code',
        id: 'fixture',
        environment: 'sandbox',
        repoRoot: root,
        includePaths: ['src'],
        excludePaths: ['docs'],
      },
    );

    assert.match(search.stdout ?? '', /src\/app\.ts/);
    assert.doesNotMatch(search.stdout ?? '', /docs\/notes\.ts/);

    const blocked = await runCodeProbe(
      {
        kind: 'code_read',
        action: 'read_file',
        filePath: 'docs/notes.ts',
        timeoutMs: 1000,
      },
      {
        kind: 'code',
        id: 'fixture',
        environment: 'sandbox',
        repoRoot: root,
        includePaths: ['src'],
        excludePaths: ['docs'],
      },
    );

    assert.equal(blocked.exitCode, 1);
    assert.match(blocked.stderr ?? '', /outside scoped include paths/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
