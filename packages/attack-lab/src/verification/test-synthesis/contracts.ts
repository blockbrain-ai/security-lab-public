/**
 * Test synthesis contracts — types for generating, isolating,
 * executing, and interpreting unit tests that confirm or refute
 * static security findings.
 */

import type { VerificationVerdict } from '../shared/contracts.js';
import type { ModelResponse } from '../../providers/contracts.js';

// ---------------------------------------------------------------------------
// Synthesis request — what we want to test
// ---------------------------------------------------------------------------

export interface SynthesisRequest {
  /** Finding ID being verified. */
  findingId: string;
  /** Hypothesis being tested in plain language. */
  hypothesis: string;
  /** Suspect file path relative to repo root. */
  suspectFile: string;
  /** Function or symbol name being tested. */
  suspectSymbol?: string;
  /** Suspect line range if known. */
  suspectLineStart?: number;
  suspectLineEnd?: number;
  /** What hostile input pattern should be tried. */
  hostileInputPattern: string;
  /** What dangerous behaviour we are trying to trigger. */
  dangerousBehaviour: string;
  /** Test framework to target. */
  testFramework: 'vitest' | 'jest' | 'node-test';
  /** Stack hints for the synthesizer. */
  stackHints?: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Synthesized test — what the model produced
// ---------------------------------------------------------------------------

export interface SynthesizedTest {
  /** Unique ID for this synthesized test. */
  testId: string;
  /** Source code of the test. */
  code: string;
  /** Filename for the test. */
  filename: string;
  /** Test framework. */
  framework: 'vitest' | 'jest' | 'node-test';
  /** Imports the test relies on. */
  imports: string[];
  /** Counter-review notes from a second model. */
  counterReviewNotes?: string;
  /** Whether the counter-review approved the test. */
  approved: boolean;
  /** Optional invocation metadata for the synthesizer model call. */
  synthesizerInvocation?: {
    systemPrompt: string;
    prompt: string;
    response: ModelResponse;
    parseSuccess: boolean;
  };
  /** Optional invocation metadata for the counter-review model call. */
  counterReviewInvocation?: {
    systemPrompt: string;
    prompt: string;
    response: ModelResponse;
    parseSuccess: boolean;
  };
}

// ---------------------------------------------------------------------------
// Test execution result
// ---------------------------------------------------------------------------

export interface TestExecutionResult {
  testId: string;
  /** Did the test compile? */
  compiled: boolean;
  /** Compilation errors if any. */
  compileErrors?: string;
  /** Did the test run to completion? */
  ran: boolean;
  /** Exit code from the test runner. */
  exitCode: number | null;
  /** Stdout from the test. */
  stdout: string;
  /** Stderr from the test. */
  stderr: string;
  /** Wall clock duration. */
  durationMs: number;
  /** Whether the test was killed by timeout. */
  timedOut: boolean;
  /** The configured timeout for this run. */
  timeoutMs: number;
  /** Whether the test appears to have made no progress before timing out. */
  stalled: boolean;
  /** Whether the test was killed by network access detection. */
  networkBlocked: boolean;
  /** Whether the test was killed for trying to write outside the worktree. */
  fsViolation: boolean;
  /** Worktree path for debugging if kept. */
  worktreePath?: string;
}

// ---------------------------------------------------------------------------
// Verdict interpretation
// ---------------------------------------------------------------------------

export interface InterpretedResult {
  verdict: VerificationVerdict;
  reasoning: string;
  confidence: number;
  /** Was the dangerous behaviour observed? */
  dangerousBehaviourObserved: boolean;
  /** Was the hostile input rejected? */
  hostileInputRejected: boolean;
}

// ---------------------------------------------------------------------------
// Isolation configuration
// ---------------------------------------------------------------------------

export interface IsolationConfig {
  /** Path to the isolated worktree. */
  worktreePath: string;
  /** Path to the test file inside the worktree. */
  testFilePath: string;
  /** Hard timeout in milliseconds. */
  timeoutMs: number;
  /** Whether to keep the worktree after execution (for debugging failures). */
  keepOnFailure: boolean;
  /** Allowed environment variables (everything else stripped). */
  allowedEnvVars: string[];
}
