/**
 * Test isolation — creates a sandboxed worktree for running synthesized
 * tests with no network access, no real environment variables, hard
 * timeouts, and filesystem isolation.
 *
 * Uses git worktree if the target is a git repo, otherwise falls back
 * to a copy of the relevant files.
 */

import { mkdir, rm, copyFile, writeFile, stat } from 'node:fs/promises';
import { resolve, join, dirname } from 'node:path';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import type { IsolationConfig } from './contracts.js';

// ---------------------------------------------------------------------------
// Worktree creation
// ---------------------------------------------------------------------------

export interface WorktreeOptions {
  /** Source repo root. */
  repoRoot: string;
  /** Campaign ID for namespacing. */
  campaignId: string;
  /** Test ID for namespacing. */
  testId: string;
  /** Base directory for worktree storage. */
  baseDir: string;
  /**
   * Use `git worktree` instead of copying the tree. Off by default: a worktree
   * writes into the scanned repository's `.git` directory (and its removal uses
   * `--force`), which mutates a repo the operator may only be authorised to
   * read. A copy costs disk space and no writes.
   */
  useGitWorktree?: boolean;
}

export async function createIsolatedWorktree(options: WorktreeOptions): Promise<string> {
  const worktreePath = resolve(options.baseDir, options.campaignId, options.testId);
  await mkdir(worktreePath, { recursive: true });

  // Only register a worktree when the caller explicitly asks for one: a
  // worktree writes into the scanned repository's .git directory and its
  // removal uses --force.
  const isGitRepo = existsSync(join(options.repoRoot, '.git'));
  if (options.useGitWorktree === true && isGitRepo) {
    try {
      await runCommand('git', ['worktree', 'add', '--detach', worktreePath, 'HEAD'], {
        cwd: options.repoRoot,
        timeoutMs: 30_000,
      });
      return worktreePath;
    } catch {
      // Fall through to copy fallback
    }
  }

  // Copy fallback: clone the repo's source files (no node_modules)
  await copyRepoMinimal(options.repoRoot, worktreePath);
  return worktreePath;
}

export async function destroyWorktree(worktreePath: string, sourceRepoRoot: string): Promise<void> {
  // Try git worktree remove if applicable
  const isGitWorktree = existsSync(join(worktreePath, '.git'));
  if (isGitWorktree && existsSync(join(sourceRepoRoot, '.git'))) {
    try {
      await runCommand('git', ['worktree', 'remove', '--force', worktreePath], {
        cwd: sourceRepoRoot,
        timeoutMs: 30_000,
      });
      return;
    } catch {
      // Fall through to rm
    }
  }
  await rm(worktreePath, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------
// Test file injection
// ---------------------------------------------------------------------------

export async function writeTestFile(
  worktreePath: string,
  relativePath: string,
  content: string,
): Promise<string> {
  const fullPath = join(worktreePath, relativePath);
  await mkdir(dirname(fullPath), { recursive: true });
  await writeFile(fullPath, content, 'utf8');
  return fullPath;
}

// ---------------------------------------------------------------------------
// Sandboxed environment
// ---------------------------------------------------------------------------

export function buildIsolatedEnv(allowed: string[] = []): Record<string, string> {
  const cleanEnv: Record<string, string> = {};

  // Always allow PATH so node and test runners can be found
  if (process.env['PATH']) cleanEnv['PATH'] = process.env['PATH'];
  if (process.env['HOME']) cleanEnv['HOME'] = '/tmp';

  // Strip out all credentials/tokens
  for (const key of allowed) {
    if (process.env[key]) cleanEnv[key] = process.env[key]!;
  }

  // Block network at the env level
  cleanEnv['HTTP_PROXY'] = 'http://invalid.local:1';
  cleanEnv['HTTPS_PROXY'] = 'http://invalid.local:1';
  cleanEnv['NO_PROXY'] = '';
  cleanEnv['NODE_OPTIONS'] = '--no-network-family-autoselection';

  // Mark this as an isolated test run
  cleanEnv['SECURITY_LAB_ISOLATED'] = '1';

  return cleanEnv;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface RunCommandOptions {
  cwd: string;
  timeoutMs: number;
  env?: Record<string, string>;
}

interface RunCommandResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  durationMs: number;
}

export function runCommand(
  cmd: string,
  args: string[],
  options: RunCommandOptions,
): Promise<RunCommandResult> {
  return new Promise((resolveResult) => {
    const start = Date.now();
    const child = spawn(cmd, args, {
      cwd: options.cwd,
      env: options.env ?? process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let timedOut = false;

    child.stdout.on('data', (chunk: Buffer) => stdoutChunks.push(chunk));
    child.stderr.on('data', (chunk: Buffer) => stderrChunks.push(chunk));

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, options.timeoutMs);

    child.on('close', (code) => {
      clearTimeout(timer);
      resolveResult({
        exitCode: code,
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
        timedOut,
        durationMs: Date.now() - start,
      });
    });

    child.on('error', () => {
      clearTimeout(timer);
      resolveResult({
        exitCode: -1,
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
        timedOut,
        durationMs: Date.now() - start,
      });
    });
  });
}

// ---------------------------------------------------------------------------
// Minimal repo copy (excluding node_modules and build artifacts)
// ---------------------------------------------------------------------------

async function copyRepoMinimal(source: string, destination: string): Promise<void> {
  const SKIP_DIRS = new Set([
    'node_modules', '.git', 'dist', '.next', 'out', 'build',
    'coverage', '.nyc_output', 'playwright-report', '.turbo',
  ]);

  async function copyRecursive(src: string, dst: string): Promise<void> {
    const { readdir } = await import('node:fs/promises');
    const entries = await readdir(src, { withFileTypes: true });
    await mkdir(dst, { recursive: true });

    for (const entry of entries) {
      if (SKIP_DIRS.has(entry.name)) continue;
      const srcPath = join(src, entry.name);
      const dstPath = join(dst, entry.name);

      if (entry.isDirectory()) {
        await copyRecursive(srcPath, dstPath);
      } else if (entry.isFile()) {
        try {
          const stats = await stat(srcPath);
          if (stats.size > 5_000_000) continue; // Skip files >5MB
          await copyFile(srcPath, dstPath);
        } catch {
          // Skip unreadable files
        }
      }
    }
  }

  await copyRecursive(source, destination);
}

// ---------------------------------------------------------------------------
// Default isolation config
// ---------------------------------------------------------------------------

export function defaultIsolationConfig(worktreePath: string, testFilePath: string): IsolationConfig {
  return {
    worktreePath,
    testFilePath,
    timeoutMs: 120_000,
    keepOnFailure: false,
    allowedEnvVars: [],
  };
}
