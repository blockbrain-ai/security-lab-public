import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { judge } from './judge.js';
import { RoleSessionStore } from './role-session-store.js';
import { createEmptyMemory } from './contracts.js';
import type { ChainHypothesis } from './contracts.js';
import type { ModelAdapter, ModelResponse, InvokeOptions } from '../providers/contracts.js';

// ---------------------------------------------------------------------------
// Judge output parsing — regression tests for the real-world JSON shapes
// observed on the fixture-target audit campaign inv-1776170280103, where both
// openai/gpt-5.4 and claude_code/claude-opus-4-6 returned plausible-sounding
// verdict strings that failed strict schema validation and got masked to
// dead_end by the old fallback. See docs/CODEX-BRIEF-MODE-FIX.md section on
// "Two things worth flagging" for the original analysis.
// ---------------------------------------------------------------------------

// Stub adapter — just returns the content provided at construction time.
class ScriptedAdapter implements ModelAdapter {
  readonly provider = 'stub';
  readonly model = 'stub-1';
  readonly supportsNativeSessionResume: boolean;
  lastInvokeOptions?: InvokeOptions<unknown>;

  constructor(private readonly responseContent: string, supportsResume: boolean = false) {
    this.supportsNativeSessionResume = supportsResume;
  }

  async invoke<T = unknown>(options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    this.lastInvokeOptions = options as InvokeOptions<unknown>;
    return {
      content: this.responseContent,
      structured: undefined,
      usage: { inputTokens: 10, outputTokens: 20, costUsd: 0.001 },
      durationMs: 1,
      provider: this.provider,
      model: this.model,
    } as ModelResponse<T>;
  }
}

function hypothesisFixture(): ChainHypothesis {
  return {
    id: 'ph-test-1',
    description: 'Test hypothesis',
    signalIds: ['ws-1', 'ws-2'],
    severity: 'high',
    status: 'pending',
    prerequisites: [],
    attempts: [],
    synthesizedAt: new Date().toISOString(),
    iteration: 0,
  } as unknown as ChainHypothesis;
}

async function runJudge(responseContent: string) {
  const adapter = new ScriptedAdapter(responseContent);
  const memory = createEmptyMemory('test');
  const hypothesis = hypothesisFixture();
  return judge(memory, adapter, hypothesis, 'No probe observations recorded.');
}

test('parseJudgeOutput accepts canonical JudgeOutput JSON', async () => {
  const result = await runJudge(JSON.stringify({
    verdict: 'dead_end',
    promoteSignals: [],
    dismissSignals: [],
    reactivateSignals: [],
    newCorrelations: [],
    partialProgress: false,
    reasoning: 'Evidence conclusively refutes the chain.',
  }));
  assert.equal(result.parseSuccess, true);
  assert.equal(result.output.verdict, 'dead_end');
  assert.equal(result.output.partialProgress, false);
});

test('parseJudgeOutput normalizes "partial_progress" to "continue" + partialProgress=true', async () => {
  // This is the exact shape ch-1-20 opus returned on the fixture-target campaign.
  const result = await runJudge(JSON.stringify({
    verdict: 'partial_progress',
    promoteSignals: ['ws-1'],
    reasoning: 'Static checks advance the chain but do not confirm exploitability.',
  }));
  assert.equal(result.parseSuccess, true);
  assert.equal(result.output.verdict, 'continue');
  assert.equal(result.output.partialProgress, true);
});

test('parseJudgeOutput normalizes "needs_more_evidence" to "continue"', async () => {
  // ch-1-20 gpt-5.4 shape.
  const result = await runJudge(JSON.stringify({
    verdict: 'needs_more_evidence',
    hypothesis_confidence: 0.62,
    progress_score: 0.46,
    summary: 'Chain plausible but not confirmed.',
  }));
  assert.equal(result.parseSuccess, true);
  assert.equal(result.output.verdict, 'continue');
  // Summary field should be promoted to reasoning when no `reasoning` key.
  assert.match(result.output.reasoning, /Chain plausible/);
});

test('parseJudgeOutput normalizes "partial" to "continue"', async () => {
  // ch-1-19 gpt-5.4 shape.
  const result = await runJudge(JSON.stringify({
    hypothesis_id: 'ch-1-19',
    verdict: 'partial',
    confidence: 0.9,
    progress_score: 0.72,
    summary: 'Chain materially advanced but not confirmed.',
  }));
  assert.equal(result.parseSuccess, true);
  assert.equal(result.output.verdict, 'continue');
});

test('parseJudgeOutput normalizes "refuted" to "continue" (not dead_end)', async () => {
  // "refuted" on a static run means "this pass did not prove it" — the
  // hypothesis should stay open for live verification, not get killed.
  const result = await runJudge(JSON.stringify({
    verdict: 'refuted',
    reasoning: 'Could not find a reachable code path in the static scan.',
  }));
  assert.equal(result.parseSuccess, true);
  assert.equal(
    result.output.verdict,
    'continue',
    'refuted should map to continue, not dead_end — preserves the hypothesis for live verification',
  );
});

test('parseJudgeOutput only maps to dead_end on explicit decisive-refute aliases', async () => {
  for (const verdict of ['hopeless', 'not_exploitable', 'impossible', 'definitely_refuted']) {
    const result = await runJudge(JSON.stringify({
      verdict,
      reasoning: `Verdict: ${verdict}`,
    }));
    assert.equal(result.parseSuccess, true, `verdict=${verdict} should parse`);
    assert.equal(
      result.output.verdict,
      'dead_end',
      `verdict=${verdict} should normalize to dead_end`,
    );
  }
});

test('parseJudgeOutput extracts JSON from ```json fenced blocks with leading reasoning', async () => {
  // Opus on ch-1-19 returned reasoning text, then a fenced JSON block.
  const content = `Now let me examine the actual code for each of the three signals.

First, I'll check user_api_key_auth.py around line 470.

\`\`\`json
{
  "verdict": "partial_progress",
  "promoteSignals": ["ws-1-12", "ws-1-22"],
  "dismissSignals": [],
  "reactivateSignals": [],
  "newCorrelations": [],
  "partialProgress": true,
  "reasoning": "Chain is materially advanced."
}
\`\`\``;
  const result = await runJudge(content);
  assert.equal(result.parseSuccess, true);
  assert.equal(result.output.verdict, 'continue');
  assert.deepEqual(result.output.promoteSignals, ['ws-1-12', 'ws-1-22']);
});

test('parseJudgeOutput handles multiple JSON blocks, picking the one with `verdict`', async () => {
  // Sometimes models include small tool-call JSON earlier in the response.
  const content = `First I will check the signal list:

{"tool": "code_read", "path": "src/auth.py"}

After reading it:

{"verdict": "dead_end", "reasoning": "code path does not exist", "partialProgress": false}`;
  const result = await runJudge(content);
  assert.equal(result.parseSuccess, true);
  assert.equal(result.output.verdict, 'dead_end');
});

test('parseJudgeOutput field aliases: partial_progress → partialProgress, snake_case arrays', async () => {
  const result = await runJudge(JSON.stringify({
    verdict: 'continue',
    promote_signals: ['ws-a', 'ws-b'],
    dismiss_signals: ['ws-c'],
    reactivate_signals: [{ signalId: 'ws-d', reason: 'new evidence' }],
    new_correlations: [{ signalIdA: 'ws-a', signalIdB: 'ws-b', resolved: true }],
    partial_progress: true,
    reasoning: 'test',
  }));
  assert.equal(result.parseSuccess, true);
  assert.deepEqual(result.output.promoteSignals, ['ws-a', 'ws-b']);
  assert.deepEqual(result.output.dismissSignals, ['ws-c']);
  assert.equal(result.output.reactivateSignals.length, 1);
  assert.equal(result.output.newCorrelations.length, 1);
  assert.equal(result.output.partialProgress, true);
});

test('parseJudgeOutput coerces local-model object payloads for signal actions', async () => {
  const result = await runJudge(JSON.stringify({
    verdict: 'continue',
    promoteSignals: [{ signalId: 'ws-a', newConfidence: 0.74, reason: 'confirmed' }],
    dismissSignals: [{ id: 'ws-b', reason: 'false positive' }],
    reactivateSignals: [{ signal: 'ws-c', reason: 'new evidence' }],
    newCorrelations: [{ signals: ['ws-a', 'ws-c'], reasoning: 'same auth path' }],
    partialProgress: true,
    reasoning: 'test',
  }));
  assert.equal(result.parseSuccess, true);
  assert.deepEqual(result.output.promoteSignals, ['ws-a']);
  assert.deepEqual(result.output.dismissSignals, ['ws-b']);
  assert.deepEqual(result.output.reactivateSignals, [{ signalId: 'ws-c', reason: 'new evidence' }]);
  assert.deepEqual(result.output.newCorrelations, [{ signalIdA: 'ws-a', signalIdB: 'ws-c', resolved: false }]);
});

test('parseJudgeOutput drops bare-string newCorrelations from local-model output', async () => {
  const result = await runJudge(JSON.stringify({
    verdict: 'continue',
    promoteSignals: [],
    dismissSignals: [],
    reactivateSignals: [],
    newCorrelations: [
      'ws-a and ws-b appear related',
      { signals: ['ws-b', 'ws-c'], resolved: true },
    ],
    partialProgress: true,
    reasoning: 'test',
  }));
  assert.equal(result.parseSuccess, true);
  assert.deepEqual(result.output.newCorrelations, [{ signalIdA: 'ws-b', signalIdB: 'ws-c', resolved: true }]);
});

test('parseJudgeOutput unparseable content defaults to "continue", not "dead_end"', async () => {
  // Previous behaviour was to default to dead_end on parse failure, which
  // hid real uncertainty and killed hypotheses that were actually still
  // plausible. The new default is "continue" with a marker in reasoning.
  const result = await runJudge('Sorry, I was unable to generate a structured response.');
  assert.equal(result.parseSuccess, false);
  assert.equal(result.output.verdict, 'continue');
  assert.equal(result.output.partialProgress, true);
  assert.match(result.output.reasoning, /Failed to parse judge output/);
});

test('parseJudgeOutput "confirmed" alias maps to confirmed_finding', async () => {
  const result = await runJudge(JSON.stringify({
    verdict: 'confirmed',
    reasoning: 'Exploit demonstrated end-to-end.',
    finding: {
      description: 'Auth bypass via pass-through default',
      severity: 'high',
      reproductionSteps: ['step 1'],
      remediationSuggestion: 'flip default to True',
    },
  }));
  assert.equal(result.parseSuccess, true);
  assert.equal(result.output.verdict, 'confirmed_finding');
  assert.ok(result.output.finding);
});

test('parseJudgeOutput preserves hypothesis.id not-a-verdict fields cleanly', async () => {
  // Ensure extra fields like hypothesis_id don't break zod validation.
  const result = await runJudge(JSON.stringify({
    hypothesis_id: 'ph-0-1',
    verdict: 'continue',
    partial_progress: true,
    confidence: 0.7,
    reasoning: 'More probing needed.',
  }));
  assert.equal(result.parseSuccess, true);
  assert.equal(result.output.verdict, 'continue');
});

// ---------------------------------------------------------------------------
// End-to-end: judge uses brief mode when adapter supports session resume
// ---------------------------------------------------------------------------

test('judge uses brief mode when adapter supports native session resume', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'security-lab-judge-brief-'));
  try {
    const store = new RoleSessionStore(dir);
    await store.prepare();

    const adapter = new ScriptedAdapter(
      JSON.stringify({
        verdict: 'continue',
        partial_progress: true,
        reasoning: 'Probing continues.',
      }),
      /*supportsResume*/ true,
    );

    const result = await judge(
      createEmptyMemory('test'),
      adapter,
      hypothesisFixture(),
      'observations go here',
      {
        briefModeContext: { store, iteration: 1 },
      },
    );

    assert.equal(result.parseSuccess, true);
    // Prompt should be the short pointer prompt, not the full template.
    assert.ok(adapter.lastInvokeOptions?.prompt);
    const prompt = adapter.lastInvokeOptions!.prompt!;
    assert.ok(
      prompt.length < 2500,
      `brief-mode judge prompt should stay small; got ${prompt.length} chars`,
    );
    assert.match(prompt, /Read your brief first:/);
    // briefMode should be threaded into invoke options.
    assert.ok(adapter.lastInvokeOptions?.briefMode);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
