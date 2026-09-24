import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { InvokeOptions, ModelAdapter, ModelResponse } from '../providers/contracts.js';
import { createEmptyMemory } from '../autonomous/contracts.js';
import { runJudgePanel, normalizePanelForSynthesis } from './judge-panel.js';

class StaticAdapter implements ModelAdapter {
  readonly provider: 'anthropic' | 'openai' | 'gemini';
  readonly model: string;
  private readonly content: string;
  /** Section 7.1 — captured prompts for asserting source excerpt inclusion. */
  public capturedPrompts: string[] = [];

  constructor(
    provider: 'anthropic' | 'openai' | 'gemini',
    model: string,
    content: string,
  ) {
    this.provider = provider;
    this.model = model;
    this.content = content;
  }

  async invoke<T = unknown>(options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    if (options.prompt) this.capturedPrompts.push(options.prompt);
    return {
      content: this.content,
      usage: { inputTokens: 20, outputTokens: 40, costUsd: 0.05 },
      durationMs: 2,
      provider: this.provider,
      model: this.model,
    };
  }
}

test('runJudgePanel executes multiple judge models and computes disagreement metadata', async () => {
  const memory = createEmptyMemory('campaign-1');
  memory.signals.push(
    {
      id: 'ws-1',
      discoveredAt: new Date().toISOString(),
      iteration: 0,
      description: 'Missing auth guard on sensitive route',
      surface: 'code',
      confidence: 0.8,
      novelty: 0.7,
      relatedAssets: ['src/routes/admin.ts'],
      potentialCapabilities: ['auth_bypass'],
      suggestedFollowUps: ['read route file'],
      status: 'active',
      correlatedWith: [],
      unresolvedCorrelations: [],
    },
    {
      id: 'ws-2',
      discoveredAt: new Date().toISOString(),
      iteration: 0,
      description: 'Raw SQL with interpolated tenant input',
      surface: 'code',
      confidence: 0.85,
      novelty: 0.8,
      relatedAssets: ['src/db/repo.ts'],
      potentialCapabilities: ['rls_bypass'],
      suggestedFollowUps: ['read repository'],
      status: 'reopened',
      reactivationReason: 'shares trust boundary with ws-1',
      correlatedWith: [],
      unresolvedCorrelations: [],
    },
  );
  memory.hypotheses.push({
    id: 'ph-1',
    synthesizedAt: new Date().toISOString(),
    iteration: 0,
    description: 'Missing auth plus raw SQL could expose cross-tenant admin data',
    severity: 'critical',
    signalIds: ['ws-1', 'ws-2'],
    prerequisites: [],
    status: 'testing',
    attempts: [],
  });

  const panel = await runJudgePanel(
    [
      {
        label: 'gpt',
        adapter: new StaticAdapter(
          'openai',
          'gpt-5.4',
          JSON.stringify({
            verdict: 'confirmed_finding',
            finding: {
              description: 'Confirmed chain.',
              severity: 'critical',
              reproductionSteps: ['step 1', 'step 2'],
              remediationSuggestion: 'Fix it',
              involvedDormantReactivation: true,
            },
            promoteSignals: ['ws-1', 'ws-2'],
            dismissSignals: [],
            reactivateSignals: [],
            newCorrelations: [{ signalIdA: 'ws-1', signalIdB: 'ws-2', resolved: true }],
            partialProgress: true,
            reasoning: 'Evidence supports confirmation.',
          }),
        ),
      },
      {
        label: 'opus',
        adapter: new StaticAdapter(
          'anthropic',
          'claude-opus-4-6',
          JSON.stringify({
            verdict: 'confirmed_finding',
            finding: {
              description: 'Confirmed chain.',
              severity: 'critical',
              reproductionSteps: ['step 1', 'step 2'],
              remediationSuggestion: 'Fix it',
              involvedDormantReactivation: true,
            },
            promoteSignals: ['ws-1', 'ws-2'],
            dismissSignals: [],
            reactivateSignals: [],
            newCorrelations: [{ signalIdA: 'ws-1', signalIdB: 'ws-2', resolved: true }],
            partialProgress: true,
            reasoning: 'Same conclusion.',
          }),
        ),
      },
      {
        label: 'gemini',
        adapter: new StaticAdapter(
          'gemini',
          'gemini-3.1-pro-preview',
          JSON.stringify({
            verdict: 'needs_dormant_review',
            promoteSignals: ['ws-1'],
            dismissSignals: [],
            reactivateSignals: [{ signalId: 'ws-2', reason: 'Needs more live evidence' }],
            newCorrelations: [],
            partialProgress: true,
            reasoning: 'Needs one more confirming step.',
          }),
        ),
      },
    ],
    memory,
    memory.hypotheses[0]!,
    'Observed auth gap and raw query sink.',
  );

  assert.equal(panel.consensusVerdict, 'confirmed_finding');
  assert.equal(panel.disagreement.unanimous, false);
  assert.equal(panel.disagreement.distinctVerdicts, 2);
  assert.deepEqual(panel.disagreement.verdictSplit, { confirmed_finding: 2, needs_dormant_review: 1 });
  assert.ok(panel.disagreement.confidenceSpread > 0);
  assert.deepEqual(panel.disagreement.commonEvidenceIds.sort(), ['ws-1', 'ws-2']);
  assert.ok(panel.memberResults.every((member) => member.invocation.prompt.length > 0));

  const packet = normalizePanelForSynthesis(panel, memory.hypotheses[0]!, 'Observed auth gap and raw query sink.');
  assert.equal(packet.memberVerdicts.length, 3);
  assert.ok(packet.memberVerdicts.every((member) => !('reasoning' in member)));
  assert.deepEqual(packet.memberVerdicts[0]?.evidenceRefs.sort(), ['ws-1', 'ws-2']);
});

// ---------------------------------------------------------------------------
// Section 7.1 — source excerpt integration in judge panel
// ---------------------------------------------------------------------------

const SIMPLE_JUDGE_RESPONSE = JSON.stringify({
  verdict: 'continue',
  promoteSignals: ['ws-1'],
  dismissSignals: [],
  reactivateSignals: [],
  newCorrelations: [],
  partialProgress: true,
  reasoning: 'Source code confirms the finding.',
});

test('Section 7.1 — runJudgePanel includes source excerpts in judge prompt when hypothesis has sourceLocationRefs', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'judge-panel-'));
  try {
    // Create a source file for the excerpt fetcher to read
    await mkdir(join(dir, 'src', 'api'), { recursive: true });
    await writeFile(
      join(dir, 'src', 'api', 'handler.ts'),
      Array.from({ length: 30 }, (_, i) => `// line ${i + 1}: handler code here`).join('\n'),
      'utf8',
    );

    const memory = createEmptyMemory('camp-7.1');
    const adapter = new StaticAdapter('anthropic', 'claude-opus-4-6', SIMPLE_JUDGE_RESPONSE);
    memory.hypotheses.push({
      id: 'ph-excerpt',
      synthesizedAt: new Date().toISOString(),
      iteration: 0,
      description: 'SQL injection in handler',
      severity: 'high',
      signalIds: ['ws-1'],
      prerequisites: [],
      status: 'testing',
      attempts: [],
      sourceLocationRefs: [
        { path: 'src/api/handler.ts', startLine: 5, endLine: 15 },
      ],
    });

    const panel = await runJudgePanel(
      [{ label: 'judge-a', adapter }],
      memory,
      memory.hypotheses[0]!,
      'Probe returned 500 with traceback.',
      { workspaceRoot: dir },
    );

    assert.equal(panel.memberResults.length, 1);
    // The judge's prompt should contain the source excerpt
    const prompt = panel.memberResults[0]!.invocation.prompt;
    assert.match(prompt, /Cited Source Code/);
    assert.match(prompt, /src\/api\/handler\.ts:5-15/);
    assert.match(prompt, /line 5: handler code here/);
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('Section 7.1 — runJudgePanel omits source excerpts when hypothesis has no sourceLocationRefs', async () => {
  const memory = createEmptyMemory('camp-7.1-no-refs');
  const adapter = new StaticAdapter('anthropic', 'claude-opus-4-6', SIMPLE_JUDGE_RESPONSE);
  memory.hypotheses.push({
    id: 'ph-no-refs',
    synthesizedAt: new Date().toISOString(),
    iteration: 0,
    description: 'Hypothesis without source refs',
    severity: 'medium',
    signalIds: ['ws-1'],
    prerequisites: [],
    status: 'testing',
    attempts: [],
    // No sourceLocationRefs
  });

  const panel = await runJudgePanel(
    [{ label: 'judge-b', adapter }],
    memory,
    memory.hypotheses[0]!,
    'Probe returned 200.',
    { workspaceRoot: '/tmp/nonexistent' },
  );

  const prompt = panel.memberResults[0]!.invocation.prompt;
  assert.ok(!prompt.includes('Cited Source Code'));
});

test('Section 7.1 — runJudgePanel omits source excerpts when no workspaceRoot provided', async () => {
  const memory = createEmptyMemory('camp-7.1-no-root');
  const adapter = new StaticAdapter('anthropic', 'claude-opus-4-6', SIMPLE_JUDGE_RESPONSE);
  memory.hypotheses.push({
    id: 'ph-no-root',
    synthesizedAt: new Date().toISOString(),
    iteration: 0,
    description: 'Hypothesis with refs but no workspace',
    severity: 'medium',
    signalIds: ['ws-1'],
    prerequisites: [],
    status: 'testing',
    attempts: [],
    sourceLocationRefs: [
      { path: 'src/handler.ts', startLine: 1, endLine: 10 },
    ],
  });

  const panel = await runJudgePanel(
    [{ label: 'judge-c', adapter }],
    memory,
    memory.hypotheses[0]!,
    'Probe returned 403.',
    // No workspaceRoot in options
  );

  const prompt = panel.memberResults[0]!.invocation.prompt;
  assert.ok(!prompt.includes('Cited Source Code'));
});

// ---------------------------------------------------------------------------
// Quorum rules
//
// A panel that cannot agree must not produce a consensus verdict: the previous
// `Math.ceil(n / 2)` rule let a 1–1 split resolve to whichever verdict was
// counted first, and let a single judge count as a panel. Both turned
// disagreement into a confident finding.
// ---------------------------------------------------------------------------

function judgeContent(verdict: string): string {
  return JSON.stringify({
    verdict,
    finding:
      verdict === 'confirmed_finding'
        ? {
            description: 'Confirmed chain.',
            severity: 'high',
            reproductionSteps: ['step 1'],
            remediationSuggestion: 'Fix it',
            involvedDormantReactivation: false,
          }
        : undefined,
    promoteSignals: [],
    dismissSignals: [],
    reactivateSignals: [],
    newCorrelations: [],
    partialProgress: false,
    reasoning: `judge says ${verdict}`,
  });
}

function quorumMemory() {
  const memory = createEmptyMemory('campaign-quorum');
  memory.signals.push({
    id: 'ws-1',
    discoveredAt: new Date().toISOString(),
    iteration: 0,
    description: 'Missing auth guard on sensitive route',
    surface: 'code',
    confidence: 0.8,
    novelty: 0.7,
    relatedAssets: ['src/routes/admin.ts'],
    potentialCapabilities: ['auth_bypass'],
    suggestedFollowUps: [],
    status: 'active',
    correlatedWith: [],
    unresolvedCorrelations: [],
  });
  memory.hypotheses.push({
    id: 'ph-1',
    synthesizedAt: new Date().toISOString(),
    iteration: 0,
    description: 'Missing auth guard could expose admin data',
    severity: 'high',
    signalIds: ['ws-1'],
    prerequisites: [],
    status: 'testing',
    attempts: [],
  });
  return memory;
}

function members(verdicts: Array<'confirmed_finding' | 'continue' | 'dead_end'>) {
  const providers = ['openai', 'anthropic', 'gemini'] as const;
  return verdicts.map((verdict, index) => ({
    label: `judge-${index + 1}`,
    adapter: new StaticAdapter(providers[index % providers.length]!, `model-${index + 1}`, judgeContent(verdict)),
  }));
}

test('a two-judge panel split 1-1 produces no consensus', async () => {
  const memory = quorumMemory();
  const panel = await runJudgePanel(members(['confirmed_finding', 'dead_end']), memory, memory.hypotheses[0]!, 'no observations');
  assert.equal(panel.consensusVerdict, null);
  assert.equal(panel.disagreement.unanimous, false);
  assert.equal(panel.disagreement.distinctVerdicts, 2);
});

test('a single judge cannot claim a consensus or unanimity', async () => {
  const memory = quorumMemory();
  const panel = await runJudgePanel(members(['confirmed_finding']), memory, memory.hypotheses[0]!, 'no observations');
  assert.equal(panel.consensusVerdict, null, 'one judge is not a quorum');
  assert.equal(panel.disagreement.unanimous, false);
});

test('two agreeing judges form a consensus', async () => {
  const memory = quorumMemory();
  const panel = await runJudgePanel(members(['confirmed_finding', 'confirmed_finding']), memory, memory.hypotheses[0]!, 'no observations');
  assert.equal(panel.consensusVerdict, 'confirmed_finding');
  assert.equal(panel.disagreement.unanimous, true);
});

test('a three-judge panel resolves 2-1 but does not report unanimity', async () => {
  const memory = quorumMemory();
  const panel = await runJudgePanel(members(['confirmed_finding', 'confirmed_finding', 'dead_end']), memory, memory.hypotheses[0]!, 'no observations');
  assert.equal(panel.consensusVerdict, 'confirmed_finding');
  assert.equal(panel.disagreement.unanimous, false);
  assert.equal(panel.disagreement.dissenters.length, 1);
});
