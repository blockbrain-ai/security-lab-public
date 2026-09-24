import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { synthesizeTestWithRetry, retrySystemPromptForAttempt } from './synthesizer.js';
import type { SynthesisRequest } from './contracts.js';
import type { InvokeOptions, ModelAdapter, ModelResponse } from '../../providers/contracts.js';

class ScriptedAdapter implements ModelAdapter {
  readonly provider = 'fixture';
  readonly model = 'fixture-model';
  readonly systemPrompts: string[] = [];
  readonly prompts: string[] = [];

  constructor(private readonly outputs: string[]) {}

  async invoke<T = unknown>(options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    this.systemPrompts.push(options.systemPrompt ?? '');
    this.prompts.push(options.prompt);
    const content = this.outputs.shift() ?? '';
    return {
      content,
      usage: { inputTokens: 1, outputTokens: 1, costUsd: 0 },
      durationMs: 1,
      provider: this.provider,
      model: this.model,
    };
  }
}

const baseRequest: SynthesisRequest = {
  findingId: 'finding-retry',
  hypothesis: 'retry ladder exercises compile fallback',
  suspectFile: 'src/suspect.ts',
  suspectSymbol: 'dangerousFn',
  hostileInputPattern: 'payload',
  dangerousBehaviour: 'unsanitized sink',
  testFramework: 'node-test',
};

async function makeRepo(): Promise<string> {
  const repoRoot = await mkdtemp(join(tmpdir(), 'security-lab-synth-retry-'));
  await mkdir(join(repoRoot, 'src'), { recursive: true });
  await writeFile(join(repoRoot, 'src', 'suspect.ts'), 'export function dangerousFn() {}\n', 'utf8');
  return repoRoot;
}

test('retrySystemPromptForAttempt selects progressively simpler prompts per attempt', () => {
  const p1 = retrySystemPromptForAttempt(1);
  const p2 = retrySystemPromptForAttempt(2);
  const p3 = retrySystemPromptForAttempt(3);
  assert.notEqual(p1, p2);
  assert.notEqual(p2, p3);
  assert.match(p2, /SIMPLER/);
  assert.match(p3, /SIMPLEST/);
});

test('synthesizeTestWithRetry returns on first attempt when code compiles', async () => {
  const repoRoot = await makeRepo();
  const adapter = new ScriptedAdapter(['// attempt 1 body\nconsole.log("ok");']);
  const compileChecks: number[] = [];
  const result = await synthesizeTestWithRetry(
    baseRequest,
    { repoRoot, synthesizer: adapter },
    async () => {
      compileChecks.push(1);
      return { compiled: true };
    },
  );
  assert.equal(result.attempt, 1);
  assert.equal(result.attempts.length, 1);
  assert.equal(result.exhaustedReason, undefined);
  assert.equal(compileChecks.length, 1);
  assert.equal(adapter.prompts.length, 1, 'only one model invocation needed');
});

test('synthesizeTestWithRetry recovers on attempt 2 after a compile error on attempt 1', async () => {
  const repoRoot = await makeRepo();
  const adapter = new ScriptedAdapter([
    '// attempt 1 broken',
    '// attempt 2 ok',
  ]);
  let call = 0;
  const result = await synthesizeTestWithRetry(
    baseRequest,
    { repoRoot, synthesizer: adapter },
    async () => {
      call += 1;
      if (call === 1) return { compiled: false, errors: "TS2304: Cannot find name 'foo'" };
      return { compiled: true };
    },
  );
  assert.equal(result.attempt, 2);
  assert.equal(result.attempts.length, 2);
  assert.equal(result.attempts[0]?.compileError, "TS2304: Cannot find name 'foo'");
  assert.equal(result.exhaustedReason, undefined);
  // Retry prompt 2 should have been used on attempt 2
  assert.equal(adapter.systemPrompts[1], retrySystemPromptForAttempt(2));
  // Attempt 2 prompt should include prior compile error context
  assert.match(adapter.prompts[1] ?? '', /Previous Compile Errors/);
  assert.match(adapter.prompts[1] ?? '', /TS2304/);
});

test('synthesizeTestWithRetry marks result exhausted after three consecutive compile errors', async () => {
  const repoRoot = await makeRepo();
  const adapter = new ScriptedAdapter([
    '// attempt 1 broken',
    '// attempt 2 still broken',
    '// attempt 3 also broken',
  ]);
  const events: Array<{ attempt: number; compiled: boolean }> = [];
  const result = await synthesizeTestWithRetry(
    baseRequest,
    { repoRoot, synthesizer: adapter },
    async () => ({ compiled: false, errors: 'boom' }),
    (attempt, ev) => events.push({ attempt, compiled: Boolean(ev['compiled']) }),
  );
  assert.equal(result.attempt, 3);
  assert.equal(result.attempts.length, 3);
  assert.equal(result.exhaustedReason, 'test_synthesis_compile_retry_exhausted');
  assert.equal(result.test.approved, false);
  assert.equal(events.length, 3);
  assert.deepEqual(events.map((e) => e.compiled), [false, false, false]);
  // Progressively simpler prompts used
  assert.equal(adapter.systemPrompts[0], retrySystemPromptForAttempt(1));
  assert.equal(adapter.systemPrompts[1], retrySystemPromptForAttempt(2));
  assert.equal(adapter.systemPrompts[2], retrySystemPromptForAttempt(3));
});
