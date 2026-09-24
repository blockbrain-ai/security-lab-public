import test from 'node:test';
import assert from 'node:assert/strict';
import { access, mkdir, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { constants as fsConstants } from 'node:fs';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  buildIsolatedEnv,
  createIsolatedWorktree,
  defaultIsolationConfig,
  destroyWorktree,
  runCommand,
  writeTestFile,
} from './isolation.js';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

test('createIsolatedWorktree falls back to repo copy and destroyWorktree removes it', async () => {
  const source = await mkdtemp(join(tmpdir(), 'security-lab-source-'));
  const baseDir = await mkdtemp(join(tmpdir(), 'security-lab-worktrees-'));

  try {
    await mkdir(join(source, 'src'), { recursive: true });
    await mkdir(join(source, 'node_modules', 'left-pad'), { recursive: true });
    await mkdir(join(source, '.next'), { recursive: true });
    await writeFile(join(source, 'src', 'index.ts'), 'export const ok = true;\n', 'utf8');
    await writeFile(join(source, 'node_modules', 'left-pad', 'index.js'), 'skip', 'utf8');
    await writeFile(join(source, '.next', 'build.js'), 'skip', 'utf8');

    const worktree = await createIsolatedWorktree({
      repoRoot: source,
      campaignId: 'campaign-1',
      testId: 'test-1',
      baseDir,
    });

    const copied = await readFile(join(worktree, 'src', 'index.ts'), 'utf8');
    assert.match(copied, /ok = true/);
    await assert.rejects(access(join(worktree, 'node_modules'), fsConstants.F_OK));
    await assert.rejects(access(join(worktree, '.next'), fsConstants.F_OK));

    const written = await writeTestFile(worktree, '__security_lab__/generated.test.ts', 'test');
    assert.equal(await readFile(written, 'utf8'), 'test');

    const config = defaultIsolationConfig(worktree, written);
    assert.equal(config.keepOnFailure, false);
    assert.equal(config.timeoutMs, 120_000);

    await destroyWorktree(worktree, source);
    await assert.rejects(stat(worktree));
  } finally {
    await rm(source, { recursive: true, force: true });
    await rm(baseDir, { recursive: true, force: true });
  }
});

test('buildIsolatedEnv keeps only allowed variables and blocks network defaults', () => {
  process.env.SECURITY_LAB_ALLOWED = 'present';
  process.env.SECURITY_LAB_SECRET = 'hidden';

  const env = buildIsolatedEnv(['SECURITY_LAB_ALLOWED']);
  assert.equal(env.SECURITY_LAB_ALLOWED, 'present');
  assert.equal(env.SECURITY_LAB_SECRET, undefined);
  assert.equal(env.SECURITY_LAB_ISOLATED, '1');
  assert.match(env.HTTP_PROXY ?? '', /invalid\.local/);
  assert.equal(env.NO_PROXY, '');
});

test('runCommand reports success, timeout, and command-launch errors', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'security-lab-run-command-'));

  try {
    const ok = await runCommand('node', ['-e', 'console.log("ok")'], {
      cwd,
      timeoutMs: 2_000,
    });
    assert.equal(ok.exitCode, 0);
    assert.match(ok.stdout, /ok/);
    assert.equal(ok.timedOut, false);

    const timedOut = await runCommand('node', ['-e', 'setTimeout(() => {}, 500)'], {
      cwd,
      timeoutMs: 20,
    });
    assert.equal(timedOut.timedOut, true);

    const errored = await runCommand('definitely-not-a-command', [], {
      cwd,
      timeoutMs: 200,
    });
    assert.equal(errored.exitCode, -1);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('createIsolatedWorktree does not touch the source repository by default', async () => {
  const base = await mkdtemp(join(tmpdir(), 'security-lab-isolation-'));
  try {
    const repoRoot = join(base, 'target-repo');
    await mkdir(join(repoRoot, 'src'), { recursive: true });
    await writeFile(join(repoRoot, 'src', 'app.ts'), 'export const x = 1;\n', 'utf8');
    await writeFile(join(repoRoot, 'package.json'), '{ "name": "target" }\n', 'utf8');

    // A git repository whose HEAD exists, so a worktree *could* be created.
    const runGit = async (...args: string[]) => {
      await execFileAsync('git', args, { cwd: repoRoot });
    };
    await runGit('init');
    await runGit('add', '-A');
    await runGit('-c', 'user.name=test', '-c', 'user.email=test@localhost', 'commit', '-m', 'init');

    const before = await readdir(join(repoRoot, '.git'));

    const isolated = await createIsolatedWorktree({
      repoRoot,
      campaignId: 'campaign-1',
      testId: 'test-1',
      baseDir: join(base, 'worktrees'),
    });

    const after = await readdir(join(repoRoot, '.git'));
    assert.deepEqual(after.sort(), before.sort(), 'the source repo .git must be untouched');
    assert.equal(existsSync(join(repoRoot, '.git', 'worktrees')), false);

    // The copy still contains the source files.
    assert.equal(existsSync(join(isolated, 'src', 'app.ts')), true);

    await destroyWorktree(isolated, repoRoot);
    assert.equal(existsSync(isolated), false);
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});
