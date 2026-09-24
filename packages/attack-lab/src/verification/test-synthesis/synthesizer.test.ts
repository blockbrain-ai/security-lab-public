import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { synthesizeTest } from './synthesizer.js';
import type { SynthesisRequest } from './contracts.js';
import type { InvokeOptions, ModelAdapter, ModelResponse } from '../../providers/contracts.js';

class QueueAdapter implements ModelAdapter {
  readonly provider = 'fixture';
  readonly model = 'fixture-model';

  constructor(private readonly outputs: string[]) {}

  async invoke<T = unknown>(_options: InvokeOptions<T>): Promise<ModelResponse<T>> {
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

class CapturingAdapter implements ModelAdapter {
  readonly provider: 'claude_code' | 'codex_cli';
  readonly model = 'fixture-model';
  prompts: string[] = [];

  constructor(provider: 'claude_code' | 'codex_cli', private readonly content: string) {
    this.provider = provider;
  }

  async invoke<T = unknown>(options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    this.prompts.push(options.prompt);
    return {
      content: this.content,
      usage: { inputTokens: 1, outputTokens: 1, costUsd: 0 },
      durationMs: 1,
      provider: this.provider,
      model: this.model,
    };
  }
}

const baseRequest: SynthesisRequest = {
  findingId: 'finding-1',
  hypothesis: 'hostile input reaches dangerous sink',
  suspectFile: 'src/suspect.ts',
  suspectSymbol: 'dangerousFn',
  hostileInputPattern: 'DROP TABLE users',
  dangerousBehaviour: 'unsanitized SQL execution',
  testFramework: 'node-test',
};

test('synthesizeTest strips code fences, extracts imports, and reads source context', async () => {
  const repoRoot = await mkdtemp(join(tmpdir(), 'security-lab-synth-'));

  try {
    await mkdir(join(repoRoot, 'src'), { recursive: true });
    await writeFile(join(repoRoot, 'src', 'suspect.ts'), 'export function dangerousFn() {}\n', 'utf8');

    const synthesized = await synthesizeTest(baseRequest, {
      repoRoot,
      synthesizer: new QueueAdapter([
        "```ts\nimport { strict as assert } from 'node:assert';\nconsole.log('test body');\n```",
      ]),
    });

    assert.equal(synthesized.approved, true);
    assert.doesNotMatch(synthesized.code, /^```/);
    assert.ok(synthesized.filename.endsWith('.test.ts'));
    assert.deepEqual(synthesized.imports, ['node:assert']);
    assert.equal(synthesized.synthesizerInvocation?.response.provider, 'fixture');
    assert.equal(synthesized.synthesizerInvocation?.parseSuccess, true);
  } finally {
    await rm(repoRoot, { recursive: true, force: true });
  }
});

test('synthesizeTest honors parseable counter-review decisions', async () => {
  const repoRoot = await mkdtemp(join(tmpdir(), 'security-lab-synth-'));

  try {
    await mkdir(join(repoRoot, 'src'), { recursive: true });
    await writeFile(join(repoRoot, 'src', 'suspect.ts'), 'export const risky = true;\n', 'utf8');

    const synthesized = await synthesizeTest(baseRequest, {
      repoRoot,
      synthesizer: new QueueAdapter(['console.log("candidate");']),
      counterReviewer: new QueueAdapter([
        '```json\n{"approved":false,"issues":["false positive"],"suggestion":"tighten oracle"}\n```',
      ]),
    });

    assert.equal(synthesized.approved, false);
    assert.match(synthesized.counterReviewNotes ?? '', /false positive/);
    assert.equal(synthesized.counterReviewInvocation?.response.provider, 'fixture');
    assert.equal(synthesized.counterReviewInvocation?.parseSuccess, true);
  } finally {
    await rm(repoRoot, { recursive: true, force: true });
  }
});

test('synthesizeTest accepts prose-wrapped counter-review output with string issues', async () => {
  const repoRoot = await mkdtemp(join(tmpdir(), 'security-lab-synth-'));

  try {
    await mkdir(join(repoRoot, 'src'), { recursive: true });
    await writeFile(join(repoRoot, 'src', 'suspect.ts'), 'export const risky = true;\n', 'utf8');

    const synthesized = await synthesizeTest(baseRequest, {
      repoRoot,
      synthesizer: new QueueAdapter(['console.log("candidate");']),
      counterReviewer: new QueueAdapter([
        [
          'Counter-review result:',
          '```json',
          '{"approved":false,"issues":"oracle still matches the safe path","suggestion":"tighten assertion"}',
          '```',
        ].join('\n'),
      ]),
    });

    assert.equal(synthesized.approved, false);
    assert.match(synthesized.counterReviewNotes ?? '', /oracle still matches the safe path/);
    assert.equal(synthesized.counterReviewInvocation?.parseSuccess, true);
  } finally {
    await rm(repoRoot, { recursive: true, force: true });
  }
});

test('synthesizeTest tolerates missing suspect files and unparseable counter-review output', async () => {
  const repoRoot = await mkdtemp(join(tmpdir(), 'security-lab-synth-'));

  try {
    const synthesized = await synthesizeTest(baseRequest, {
      repoRoot,
      synthesizer: new QueueAdapter(['console.log("candidate");']),
      counterReviewer: new QueueAdapter(['not valid json']),
    });

    assert.equal(synthesized.approved, true);
    assert.match(synthesized.counterReviewNotes ?? '', /unparseable/i);
    assert.equal(synthesized.counterReviewInvocation?.parseSuccess, false);
  } finally {
    await rm(repoRoot, { recursive: true, force: true });
  }
});

test('synthesizeTest uses file-pointer prompts for CLI-backed worker adapters', async () => {
  const repoRoot = await mkdtemp(join(tmpdir(), 'security-lab-synth-'));

  try {
    await mkdir(join(repoRoot, 'src'), { recursive: true });
    await writeFile(join(repoRoot, 'src', 'suspect.ts'), 'export function dangerousFn() {}\n', 'utf8');
    const synthesizer = new CapturingAdapter('claude_code', 'console.log("candidate");');
    const reviewer = new CapturingAdapter('codex_cli', '{"approved":true,"issues":[],"suggestion":""}');

    await synthesizeTest(baseRequest, {
      repoRoot,
      synthesizer,
      counterReviewer: reviewer,
    });

    assert.match(synthesizer.prompts[0] ?? '', /SECURITY_LAB_FILE_POINTER/);
    assert.match(synthesizer.prompts[0] ?? '', /src\/suspect\.ts/);
    assert.match(reviewer.prompts[0] ?? '', /SECURITY_LAB_FILE_POINTER/);
  } finally {
    await rm(repoRoot, { recursive: true, force: true });
  }
});
