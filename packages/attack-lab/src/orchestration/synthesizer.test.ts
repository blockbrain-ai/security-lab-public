import test from 'node:test';
import assert from 'node:assert/strict';
import type { InvokeOptions, ModelAdapter, ModelResponse } from '../providers/contracts.js';
import { synthesize } from './synthesizer.js';
import type { NormalizedPanelPacket } from './judge-panel.js';

class SynthAdapter implements ModelAdapter {
  readonly provider = 'anthropic' as const;
  readonly model = 'claude-opus-4-6';

  async invoke<T = unknown>(_options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    return {
      content: JSON.stringify({
        verdict: 'confirmed',
        reasoning: 'The evidence packet supports confirmation.',
        confidence: 0.91,
        agreedWith: ['gpt', 'opus'],
        disagreedWith: ['gemini'],
        decisiveEvidence: ['ws-1', 'ws-2'],
      }),
      usage: { inputTokens: 50, outputTokens: 80, costUsd: 0.2 },
      durationMs: 4,
      provider: this.provider,
      model: this.model,
    };
  }
}

test('synthesize produces a final verdict without embedding raw panel reasoning', async () => {
  const packet: NormalizedPanelPacket = {
    hypothesis: 'Missing auth plus raw SQL enables cross-tenant export.',
    severity: 'critical',
    memberVerdicts: [
      {
        label: 'gpt',
        provider: 'openai',
        model: 'gpt-5.4',
        verdict: 'confirmed_finding',
        confidenceScore: 0.82,
        promotedSignals: ['ws-1', 'ws-2'],
        dismissedSignals: [],
        reactivatedSignals: [],
        evidenceRefs: ['ws-1', 'ws-2'],
      },
      {
        label: 'gemini',
        provider: 'gemini',
        model: 'gemini-3.1-pro-preview',
        verdict: 'needs_dormant_review',
        confidenceScore: 0.61,
        promotedSignals: ['ws-1'],
        dismissedSignals: [],
        reactivatedSignals: ['ws-2'],
        evidenceRefs: ['ws-1'],
      },
    ],
    disagreement: {
      unanimous: false,
      verdictSplit: { confirmed_finding: 1, needs_dormant_review: 1 },
      distinctVerdicts: 2,
      dissenters: ['gemini'],
      confidenceSpread: 0.21,
      commonEvidenceIds: ['ws-1'],
      uniqueEvidenceIds: ['ws-2'],
    },
    consensusVerdict: null,
    rawEvidence: 'GET /admin/export returned data for another tenant.',
  };

  const invocation = await synthesize(new SynthAdapter(), packet);

  assert.equal(invocation.output.verdict, 'confirmed');
  assert.equal(invocation.output.outcomeType, 'contested_confirmation');
  assert.ok(invocation.prompt.includes('Confidence score: 0.82'));
  assert.ok(invocation.prompt.includes('Cited evidence refs: ws-1, ws-2'));
  assert.equal(invocation.prompt.includes('Reasoning:'), false);
});
