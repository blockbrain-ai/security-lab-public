/**
 * Test runner — compiles and executes synthesized tests in an isolated
 * worktree with strict safety constraints.
 */

import type { SynthesizedTest, TestExecutionResult } from './contracts.js';
import {
  createIsolatedWorktree,
  destroyWorktree,
  writeTestFile,
  buildIsolatedEnv,
  runCommand,
} from './isolation.js';

// ---------------------------------------------------------------------------
// Test runner options
// ---------------------------------------------------------------------------

export interface RunTestOptions {
  /** Source repo root. */
  repoRoot: string;
  /** Campaign ID for namespacing. */
  campaignId: string;
  /** Base directory for worktrees. */
  baseWorktreeDir: string;
  /** Hard timeout per test in ms. */
  timeoutMs?: number;
  /** Keep worktree after failure for debugging. */
  keepOnFailure?: boolean;
  /** Test framework command (e.g., 'npx vitest run'). */
  testRunnerCommand?: string[];
  /** Hard cap even when a target profile requests a larger timeout. */
  hardTimeoutCapMs?: number;
}

// ---------------------------------------------------------------------------
// Run a synthesized test
// ---------------------------------------------------------------------------

export async function runSynthesizedTest(
  test: SynthesizedTest,
  options: RunTestOptions,
): Promise<TestExecutionResult> {
  const configuredTimeoutMs = options.timeoutMs ?? 120_000;
  const hardTimeoutCapMs = options.hardTimeoutCapMs ?? 300_000;
  const timeoutMs = Math.min(configuredTimeoutMs, hardTimeoutCapMs);

  if (!test.approved) {
    return {
      testId: test.testId,
      compiled: false,
      compileErrors: 'test was not approved by counter-review',
      ran: false,
      exitCode: null,
      stdout: '',
      stderr: 'rejected by counter-review',
      durationMs: 0,
      timedOut: false,
      timeoutMs,
      stalled: false,
      networkBlocked: false,
      fsViolation: false,
    };
  }

  let worktreePath: string | undefined;
  let testFilePath: string;

  try {
    // Step 1: Create isolated worktree
    worktreePath = await createIsolatedWorktree({
      repoRoot: options.repoRoot,
      campaignId: options.campaignId,
      testId: test.testId,
      baseDir: options.baseWorktreeDir,
    });

    // Step 2: Write the test file into the worktree
    testFilePath = await writeTestFile(
      worktreePath,
      `__security_lab_tests__/${test.filename}`,
      test.code,
    );

    // Step 3: Build isolated environment
    const env = buildIsolatedEnv([]);

    // Step 4: Run the test
    const cmd = options.testRunnerCommand ?? defaultTestCommand(test, testFilePath);
    const result = await runCommand(cmd[0]!, cmd.slice(1), {
      cwd: worktreePath,
      timeoutMs,
      env,
    });

    // Step 5: Interpret the result
    const compiled = !result.stderr.includes('TS') || !result.stderr.includes('error');
    const networkBlocked = /network|ECONNREFUSED|invalid\.local|EAI_AGAIN/.test(result.stderr);
    const fsViolation = /EACCES|EPERM/.test(result.stderr);
    const stalled = result.timedOut
      && result.stdout.trim().length === 0
      && result.stderr.trim().length === 0;

    const executionResult: TestExecutionResult = {
      testId: test.testId,
      compiled,
      compileErrors: !compiled ? result.stderr.slice(0, 2000) : undefined,
      ran: result.exitCode !== null && !result.timedOut,
      exitCode: result.exitCode,
      stdout: result.stdout.slice(0, 8000),
      stderr: result.stderr.slice(0, 8000),
      durationMs: result.durationMs,
      timedOut: result.timedOut,
      timeoutMs,
      stalled,
      networkBlocked,
      fsViolation,
    };

    // Step 6: Cleanup unless keeping for debugging
    const shouldKeep = options.keepOnFailure && (result.exitCode !== 0 || result.timedOut);
    if (!shouldKeep && worktreePath) {
      await destroyWorktree(worktreePath, options.repoRoot);
    } else if (shouldKeep) {
      executionResult.worktreePath = worktreePath;
    }

    return executionResult;
  } catch (error) {
    if (worktreePath) {
      try {
        await destroyWorktree(worktreePath, options.repoRoot);
      } catch {
        // Best effort cleanup
      }
    }
    return {
      testId: test.testId,
      compiled: false,
      compileErrors: error instanceof Error ? error.message : String(error),
      ran: false,
      exitCode: null,
      stdout: '',
      stderr: error instanceof Error ? error.message : String(error),
      durationMs: 0,
      timedOut: false,
      timeoutMs,
      stalled: false,
      networkBlocked: false,
      fsViolation: false,
    };
  }
}

// ---------------------------------------------------------------------------
// Default test command per framework
// ---------------------------------------------------------------------------

function defaultTestCommand(test: SynthesizedTest, testFilePath: string): string[] {
  switch (test.framework) {
    case 'vitest':
      return ['npx', 'vitest', 'run', testFilePath, '--no-coverage', '--reporter=basic'];
    case 'jest':
      return ['npx', 'jest', testFilePath, '--no-coverage'];
    case 'node-test':
      return ['node', '--test', '--import', 'tsx', testFilePath];
    default:
      return ['node', '--test', '--import', 'tsx', testFilePath];
  }
}
