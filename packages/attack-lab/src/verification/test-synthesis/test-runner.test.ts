import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runSynthesizedTest } from './test-runner.js';
import type { SynthesizedTest } from './contracts.js';

const approvedTest: SynthesizedTest = {
  testId: 'approved-test',
  code: 'console.log("hello");',
  filename: 'approved.test.ts',
  framework: 'node-test',
  imports: [],
  approved: true,
};

test('runSynthesizedTest rejects tests not approved by counter-review', async () => {
  const result = await runSynthesizedTest(
    { ...approvedTest, testId: 'rejected-test', approved: false },
    {
      repoRoot: process.cwd(),
      campaignId: 'campaign-1',
      baseWorktreeDir: join(tmpdir(), 'security-lab-test-runner'),
    },
  );

  assert.equal(result.compiled, false);
  assert.match(result.stderr, /counter-review/i);
});

test('runSynthesizedTest keeps the worktree on failure when requested', async () => {
  const repoRoot = await mkdtemp(join(tmpdir(), 'security-lab-runner-repo-'));
  const baseWorktreeDir = await mkdtemp(join(tmpdir(), 'security-lab-runner-worktrees-'));

  try {
    await mkdir(join(repoRoot, 'src'), { recursive: true });
    await writeFile(join(repoRoot, 'src', 'index.ts'), 'export const ok = true;\n', 'utf8');

    const result = await runSynthesizedTest(approvedTest, {
      repoRoot,
      campaignId: 'campaign-2',
      baseWorktreeDir,
      keepOnFailure: true,
      testRunnerCommand: [
        'node',
        '-e',
        'process.stderr.write("EACCES ECONNREFUSED"); process.exit(1);',
      ],
    });

    assert.equal(result.ran, true);
    assert.equal(result.exitCode, 1);
    assert.equal(result.networkBlocked, true);
    assert.equal(result.fsViolation, true);
    assert.ok(result.worktreePath);
  } finally {
    await rm(repoRoot, { recursive: true, force: true });
    await rm(baseWorktreeDir, { recursive: true, force: true });
  }
});

test('runSynthesizedTest cleans up successful worktrees', async () => {
  const repoRoot = await mkdtemp(join(tmpdir(), 'security-lab-runner-repo-'));
  const baseWorktreeDir = await mkdtemp(join(tmpdir(), 'security-lab-runner-worktrees-'));

  try {
    await mkdir(join(repoRoot, 'src'), { recursive: true });
    await writeFile(join(repoRoot, 'src', 'index.ts'), 'export const ok = true;\n', 'utf8');

    const result = await runSynthesizedTest(approvedTest, {
      repoRoot,
      campaignId: 'campaign-3',
      baseWorktreeDir,
      testRunnerCommand: ['node', '-e', 'process.stdout.write("SAFE"); process.exit(0);'],
    });

    assert.equal(result.exitCode, 0);
    assert.equal(result.worktreePath, undefined);
  } finally {
    await rm(repoRoot, { recursive: true, force: true });
    await rm(baseWorktreeDir, { recursive: true, force: true });
  }
});
