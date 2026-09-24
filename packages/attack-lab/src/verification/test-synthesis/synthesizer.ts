/**
 * Test synthesizer — uses a model to generate hostile-input unit tests
 * targeting suspect functions, with optional counter-review for soundness.
 */

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { z } from 'zod';
import type { InvokeOptions, ModelAdapter } from '../../providers/contracts.js';
import { tryParseStructured } from '../../providers/parse-structured.js';
import type { SynthesisRequest, SynthesizedTest } from './contracts.js';
import {
  SYNTHESIZER_SYSTEM_PROMPT,
  SYNTHESIZER_USER_TEMPLATE,
  COUNTER_REVIEW_SYSTEM_PROMPT,
  COUNTER_REVIEW_USER_TEMPLATE,
  renderTemplate,
} from './prompts.js';

// ---------------------------------------------------------------------------
// Synthesis options
// ---------------------------------------------------------------------------

export interface SynthesizeOptions {
  /** Repo root for reading the suspect source file. */
  repoRoot: string;
  /** Synthesizer model adapter. */
  synthesizer: ModelAdapter;
  /** Optional counter-reviewer adapter for soundness check. */
  counterReviewer?: ModelAdapter;
  /** Maximum tokens for the synthesizer call. */
  maxTokens?: number;
  invokeOptions?: Partial<InvokeOptions<SynthesizedTest>>;
  counterInvokeOptions?: Partial<InvokeOptions<CounterReviewResult>>;
  /**
   * Optional system prompt override for retry attempts. When set, replaces
   * the default SYNTHESIZER_SYSTEM_PROMPT. Used by callers implementing the
   * simpler-fallback retry ladder documented in Section 3.1.
   */
  systemPromptOverride?: string;
  /**
   * Optional context appended to the user prompt. Used to feed prior compile
   * errors back to the model on retry attempts.
   */
  userPromptSuffix?: string;
}

const CounterReviewResponseSchema = z.object({
  approved: z.union([
    z.boolean(),
    z.string().transform((value) => value.trim().toLowerCase() === 'true'),
  ]).default(true),
  issues: z.union([
    z.array(z.string()),
    z.string().transform((value) => [value]),
  ]).default([]),
  suggestion: z.string().default(''),
}).passthrough();

type CounterReviewResponse = z.infer<typeof CounterReviewResponseSchema>;

// ---------------------------------------------------------------------------
// Synthesize a test
// ---------------------------------------------------------------------------

export async function synthesizeTest(
  request: SynthesisRequest,
  options: SynthesizeOptions,
): Promise<SynthesizedTest> {
  const sourceCode = await readSuspectFile(options.repoRoot, request.suspectFile);
  const synthesizerSourceContext = buildSourceContext(
    options.repoRoot,
    request.suspectFile,
    sourceCode,
    options.synthesizer,
  );

  const basePrompt = renderTemplate(SYNTHESIZER_USER_TEMPLATE, {
    HYPOTHESIS: request.hypothesis,
    SUSPECT_FILE: request.suspectFile,
    SUSPECT_SYMBOL: request.suspectSymbol ?? '(unknown)',
    HOSTILE_INPUT: request.hostileInputPattern,
    DANGEROUS_BEHAVIOUR: request.dangerousBehaviour,
    TEST_FRAMEWORK: request.testFramework,
    SOURCE_CODE: synthesizerSourceContext,
  });
  const prompt = options.userPromptSuffix
    ? `${basePrompt}\n\n${options.userPromptSuffix}`
    : basePrompt;
  const systemPrompt = options.systemPromptOverride ?? SYNTHESIZER_SYSTEM_PROMPT;

  const response = await options.synthesizer.invoke({
    ...(options.invokeOptions ?? {}),
    systemPrompt,
    prompt,
    maxTokens: options.maxTokens ?? 4096,
    temperature: 0,
  });

  const testCode = stripCodeFences(response.content);
  const testId = `synth-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const filename = `${testId}.${request.testFramework === 'node-test' ? 'test.ts' : 'spec.ts'}`;

  let approved = true;
  let counterReviewNotes: string | undefined;
  let counterReviewInvocation: SynthesizedTest['counterReviewInvocation'];

  if (options.counterReviewer) {
    const review = await counterReview(
      request,
      buildSourceContext(options.repoRoot, request.suspectFile, sourceCode, options.counterReviewer),
      testCode,
      options.counterReviewer,
      options.counterInvokeOptions,
    );
    approved = review.approved;
    counterReviewNotes = review.issues.join('; ') || review.suggestion;
    counterReviewInvocation = review.invocation;
  }

  return {
    testId,
    code: testCode,
    filename,
    framework: request.testFramework,
    imports: extractImports(testCode),
    counterReviewNotes,
    approved,
    synthesizerInvocation: {
      systemPrompt,
      prompt,
      response,
      parseSuccess: true,
    },
    counterReviewInvocation,
  };
}

/** System prompts to use for retry attempts 2 and 3 — see SYNTHESIZER_RETRY_SYSTEM_PROMPT_* below. */
export function retrySystemPromptForAttempt(attempt: number): string {
  if (attempt <= 1) return SYNTHESIZER_SYSTEM_PROMPT;
  if (attempt === 2) return SYNTHESIZER_RETRY_SYSTEM_PROMPT_2;
  return SYNTHESIZER_RETRY_SYSTEM_PROMPT_3;
}

// ---------------------------------------------------------------------------
// Retry-aware synthesis (Section 3.1)
// ---------------------------------------------------------------------------

/** Simpler system prompt for retry attempt 2 — no setup, just the critical assertion. */
const SYNTHESIZER_RETRY_SYSTEM_PROMPT_2 = `You are a security verification engineer. A previous test failed to compile. Generate a SIMPLER test with:
- Only the critical assertion — skip complex setup, skip mocking, skip type imports that aren't strictly needed.
- Import the suspect function directly and call it with the hostile input.
- Use the specified test framework.
- Output ONLY the test source code, no markdown, no commentary.`;

/** Minimal system prompt for retry attempt 3 — just exercise the file. */
const SYNTHESIZER_RETRY_SYSTEM_PROMPT_3 = `You are a security verification engineer. Two previous tests failed to compile. Generate the SIMPLEST possible test:
- Import the suspect file (not a specific function — use * as namespace import if needed).
- Call the suspect function with the hostile input pattern.
- Print "VULNERABLE" or "SAFE" to stdout based on what happens.
- Do NOT import types, do NOT use complex assertions, do NOT mock anything.
- Output ONLY the test source code, no markdown, no commentary.`;

export interface SynthesisRetryResult {
  /** Final synthesized test (from whichever attempt succeeded). */
  test: SynthesizedTest;
  /** Which attempt produced the final test (1, 2, or 3). */
  attempt: number;
  /** Evidence records for each attempt. */
  attempts: Array<{
    attempt: number;
    testId: string;
    code: string;
    compileError?: string;
  }>;
  /** If all attempts failed to compile, the reason code. */
  exhaustedReason?: 'test_synthesis_compile_retry_exhausted';
}

/**
 * Synthesize a test with retry on compile error. Up to 3 attempts:
 * 1. Full test with imports, setup, assertion
 * 2. Simpler test with only the critical assertion (on compile error)
 * 3. Minimal test that just exercises the suspect file (on compile error)
 *
 * The `compileCheck` callback determines whether the generated code compiles.
 */
export async function synthesizeTestWithRetry(
  request: SynthesisRequest,
  options: SynthesizeOptions,
  compileCheck: (code: string, filename: string) => Promise<{ compiled: boolean; errors?: string }>,
  onAttemptEvent?: (attempt: number, event: Record<string, unknown>) => void,
): Promise<SynthesisRetryResult> {
  const attempts: SynthesisRetryResult['attempts'] = [];
  const prompts = [SYNTHESIZER_SYSTEM_PROMPT, SYNTHESIZER_RETRY_SYSTEM_PROMPT_2, SYNTHESIZER_RETRY_SYSTEM_PROMPT_3];

  for (let attempt = 1; attempt <= 3; attempt++) {
    const systemPrompt = prompts[attempt - 1]!;
    const priorErrors = attempts.map((a) => a.compileError).filter(Boolean).join('\n---\n');

    const sourceCode = await readSuspectFile(options.repoRoot, request.suspectFile);
    const synthesizerSourceContext = buildSourceContext(
      options.repoRoot,
      request.suspectFile,
      sourceCode,
      options.synthesizer,
    );

    const userPromptBase = renderTemplate(SYNTHESIZER_USER_TEMPLATE, {
      HYPOTHESIS: request.hypothesis,
      SUSPECT_FILE: request.suspectFile,
      SUSPECT_SYMBOL: request.suspectSymbol ?? '(unknown)',
      HOSTILE_INPUT: request.hostileInputPattern,
      DANGEROUS_BEHAVIOUR: request.dangerousBehaviour,
      TEST_FRAMEWORK: request.testFramework,
      SOURCE_CODE: synthesizerSourceContext,
    });

    const userPrompt = attempt > 1
      ? `${userPromptBase}\n\n## Previous Compile Errors (attempt ${attempt - 1})\n\`\`\`\n${priorErrors}\n\`\`\`\n\nGenerate a SIMPLER test that avoids these errors.`
      : userPromptBase;

    const response = await options.synthesizer.invoke({
      ...(options.invokeOptions ?? {}),
      systemPrompt,
      prompt: userPrompt,
      maxTokens: options.maxTokens ?? 4096,
      temperature: 0,
    });

    const testCode = stripCodeFences(response.content);
    const testId = `synth-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const filename = `${testId}.${request.testFramework === 'node-test' ? 'test.ts' : 'spec.ts'}`;

    const check = await compileCheck(testCode, filename);

    onAttemptEvent?.(attempt, {
      attempt,
      testId,
      compiled: check.compiled,
      compileErrors: check.errors ?? null,
    });

    attempts.push({
      attempt,
      testId,
      code: testCode,
      compileError: check.compiled ? undefined : check.errors,
    });

    if (check.compiled) {
      // Run counter-review if available
      let approved = true;
      let counterReviewNotes: string | undefined;
      let counterReviewInvocation: SynthesizedTest['counterReviewInvocation'];

      if (options.counterReviewer) {
        const review = await counterReview(
          request,
          buildSourceContext(options.repoRoot, request.suspectFile, sourceCode, options.counterReviewer),
          testCode,
          options.counterReviewer,
          options.counterInvokeOptions,
        );
        approved = review.approved;
        counterReviewNotes = review.issues.join('; ') || review.suggestion;
        counterReviewInvocation = review.invocation;
      }

      return {
        test: {
          testId,
          code: testCode,
          filename,
          framework: request.testFramework,
          imports: extractImports(testCode),
          counterReviewNotes,
          approved,
          synthesizerInvocation: {
            systemPrompt,
            prompt: userPrompt,
            response,
            parseSuccess: true,
          },
          counterReviewInvocation,
        },
        attempt,
        attempts,
      };
    }
  }

  // All 3 attempts failed to compile
  const lastAttempt = attempts[attempts.length - 1]!;
  return {
    test: {
      testId: lastAttempt.testId,
      code: lastAttempt.code,
      filename: `${lastAttempt.testId}.${request.testFramework === 'node-test' ? 'test.ts' : 'spec.ts'}`,
      framework: request.testFramework,
      imports: extractImports(lastAttempt.code),
      approved: false,
    },
    attempt: 3,
    attempts,
    exhaustedReason: 'test_synthesis_compile_retry_exhausted',
  };
}

// ---------------------------------------------------------------------------
// Counter-review
// ---------------------------------------------------------------------------

interface CounterReviewResult {
  approved: boolean;
  issues: string[];
  suggestion: string;
  invocation: {
    systemPrompt: string;
    prompt: string;
    response: Awaited<ReturnType<ModelAdapter['invoke']>>;
    parseSuccess: boolean;
  };
}

async function counterReview(
  request: SynthesisRequest,
  sourceCode: string,
  testCode: string,
  reviewer: ModelAdapter,
  invokeOptions?: Partial<InvokeOptions<CounterReviewResult>>,
): Promise<CounterReviewResult> {
  const prompt = renderTemplate(COUNTER_REVIEW_USER_TEMPLATE, {
    HYPOTHESIS: request.hypothesis,
    TEST_CODE: testCode,
    SOURCE_CODE: sourceCode.slice(0, 8000),
  });

  const response = await reviewer.invoke<CounterReviewResponse>({
    ...((invokeOptions ?? {}) as Partial<InvokeOptions<CounterReviewResponse>>),
    systemPrompt: COUNTER_REVIEW_SYSTEM_PROMPT,
    prompt,
    maxTokens: 1024,
    temperature: 0,
    schema: CounterReviewResponseSchema,
  });

  const parsed = response.structured ?? tryParseStructured(response.content, CounterReviewResponseSchema);
  if (parsed) {
    return {
      approved: parsed.approved,
      issues: parsed.issues,
      suggestion: parsed.suggestion,
      invocation: {
        systemPrompt: COUNTER_REVIEW_SYSTEM_PROMPT,
        prompt,
        response,
        parseSuccess: true,
      },
    };
  }

  // If we cannot parse, default to approved with caveat
  return {
    approved: true,
    issues: ['counter-reviewer output unparseable'],
    suggestion: '',
    invocation: {
      systemPrompt: COUNTER_REVIEW_SYSTEM_PROMPT,
      prompt,
      response,
      parseSuccess: false,
    },
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function readSuspectFile(repoRoot: string, file: string): Promise<string> {
  try {
    return await readFile(resolve(repoRoot, file), 'utf8');
  } catch {
    return '// FILE_NOT_FOUND';
  }
}

function buildSourceContext(
  repoRoot: string,
  suspectFile: string,
  sourceCode: string,
  adapter: ModelAdapter | undefined,
): string {
  if (sourceCode === '// FILE_NOT_FOUND') {
    return sourceCode;
  }

  if (isCliBackedAdapter(adapter)) {
    return [
      '// SECURITY_LAB_FILE_POINTER',
      `// The suspect file is available in the working directory at: ${suspectFile}`,
      `// Repo root: ${repoRoot}`,
      '// Read the file directly with your tools before generating or reviewing the test.',
      '// SECURITY_LAB_FILE_POINTER_END',
    ].join('\n');
  }

  return sourceCode.slice(0, 8000);
}

function isCliBackedAdapter(adapter: ModelAdapter | undefined): boolean {
  return adapter?.provider === 'claude_code' || adapter?.provider === 'codex_cli';
}

function stripCodeFences(content: string): string {
  // Remove opening ```typescript or ```ts or ```
  let cleaned = content.trim();
  cleaned = cleaned.replace(/^```(?:typescript|ts|javascript|js)?\n/, '');
  cleaned = cleaned.replace(/\n```$/, '');
  return cleaned;
}

function extractImports(code: string): string[] {
  const imports: string[] = [];
  const importRegex = /^import .* from ['"]([^'"]+)['"]/gm;
  let match;
  while ((match = importRegex.exec(code)) !== null) {
    imports.push(match[1]!);
  }
  return imports;
}
