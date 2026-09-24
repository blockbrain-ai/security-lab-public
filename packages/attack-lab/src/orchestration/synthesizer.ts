/**
 * Synthesizer — final evidence-led synthesis over judge panel outputs.
 *
 * Bias guard: When the synthesizer model is the same as a panel member,
 * it receives only normalized verdict packets + cited evidence, NOT the
 * panel member's raw reasoning transcript. This prevents double-counting
 * one model's internal bias.
 */

import type { InvokeOptions, ModelAdapter, ModelResponse } from '../providers/contracts.js';
import type { NormalizedPanelPacket } from './judge-panel.js';
import type { RoleSessionStore } from '../autonomous/role-session-store.js';

/**
 * Brief-mode context for the synthesizer. Panel verdicts + disagreement
 * metadata + raw evidence can easily reach tens of KB on critical chains;
 * when the adapter supports native session resume we write those to disk
 * and send the worker a short pointer prompt instead.
 */
export interface SynthesizerBriefModeContext {
  store: RoleSessionStore;
  iteration: number;
  scopeId: string;
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SynthesisResult {
  verdict: 'confirmed' | 'refuted' | 'insufficient_evidence' | 'needs_more_probes';
  reasoning: string;
  confidence: number;
  /** Which panel members the synthesizer agreed with. */
  agreedWith: string[];
  /** Which panel members the synthesizer disagreed with. */
  disagreedWith: string[];
  /** Which specific evidence changed the synthesizer's decision. */
  decisiveEvidence: string[];
  /** Classification of the synthesis outcome. */
  outcomeType: 'unanimous_confirmation' | 'contested_confirmation' | 'unresolved_disagreement' | 'unanimous_refutation';
  /**
   * Whether the response actually parsed as JSON. A response that fell back to
   * raw text is reported as such instead of being counted as a success.
   */
  parseStatus: 'ok' | 'fallback_text';
}

// ---------------------------------------------------------------------------
// Synthesizer prompts
// ---------------------------------------------------------------------------

const SYNTHESIZER_SYSTEM_PROMPT = `You are a security investigation synthesizer. You receive:
1. A hypothesis about a potential vulnerability
2. Normalized verdicts from a panel of independent judge models
3. Disagreement metrics showing where the panel agreed and disagreed
4. Raw evidence from probe observations

Your job is to produce the FINAL verdict by:
- Weighing the evidence independently of any single judge's reasoning
- Identifying which specific evidence supports or refutes the hypothesis
- Resolving disagreements based on evidence quality, not judge authority
- Being explicit about what changed your mind if you disagree with the majority

IMPORTANT: You are seeing normalized verdict packets, not raw transcripts.
Evaluate the EVIDENCE, not the judges' internal reasoning patterns.

Respond with JSON:
{
  "verdict": "confirmed" | "refuted" | "insufficient_evidence" | "needs_more_probes",
  "reasoning": "your evidence-based reasoning",
  "confidence": 0.0 to 1.0,
  "agreedWith": ["labels of panel members you agree with"],
  "disagreedWith": ["labels of panel members you disagree with"],
  "decisiveEvidence": ["specific evidence items that determined your verdict"]
}`;

// ---------------------------------------------------------------------------
// Synthesis execution
// ---------------------------------------------------------------------------

export async function synthesize(
  adapter: ModelAdapter,
  packet: NormalizedPanelPacket,
  options?: {
    invokeOptions?: Partial<InvokeOptions<SynthesisResult>>;
    briefModeContext?: SynthesizerBriefModeContext;
  },
): Promise<SynthesisInvocation> {
  const wantBriefMode =
    options?.briefModeContext != null && adapter.supportsNativeSessionResume === true;

  let prompt: string;
  let briefInvokeAddition: Partial<InvokeOptions<SynthesisResult>> = {};

  if (wantBriefMode && options?.briefModeContext) {
    const { store, iteration, scopeId } = options.briefModeContext;
    const manifest = await store.writeBriefManifest({
      role: 'synthesizer',
      scopeId,
      iteration,
      whatToDecide:
        'Produce the final synthesis verdict for this hypothesis. Read ' +
        '`panel-verdicts.md` for each member, `disagreement-summary.md` for ' +
        'where they diverged, and `raw-evidence.md` for the underlying probe ' +
        'observations. Decide independently of any one judge\'s reasoning; ' +
        'weigh the evidence itself.',
      outputSchemaReminder:
        'Return ONLY valid JSON matching the SynthesisResult schema: verdict, ' +
        'reasoning, confidence, agreedWith[], disagreedWith[], decisiveEvidence[]. ' +
        'No prose outside the JSON.',
      evidence: [
        { name: 'panel-verdicts.md', content: formatPanelVerdicts(packet) },
        { name: 'disagreement-summary.md', content: formatDisagreement(packet) },
        { name: 'raw-evidence.md', content: formatRawEvidence(packet) },
      ],
    });
    prompt = [
      `You are the Security Lab synthesizer worker. Scope: ${scopeId}.`,
      '',
      `Read your brief first: ${manifest.briefPath}`,
      '',
      'Then read every evidence pointer listed in the brief:',
      ...manifest.evidencePaths.map((p) => `- ${p}`),
      '',
      'Build your context from disk. Return JSON only, matching the SynthesisResult schema.',
    ].join('\n');
    briefInvokeAddition = {
      briefMode: {
        briefPath: manifest.briefPath,
        artifactsDir: manifest.briefPath.replace(/\/[^/]+$/, '/..'),
        scopeId,
        evidencePointers: manifest.evidencePaths,
      },
    };
  } else {
    prompt = formatSynthesisPrompt(packet);
  }

  const response = await adapter.invoke({
    ...(options?.invokeOptions ?? {}),
    ...briefInvokeAddition,
    systemPrompt: SYNTHESIZER_SYSTEM_PROMPT,
    prompt,
    maxTokens: 8192,
    temperature: 0,
  });

  const output = parseSynthesisResponse(response.content, packet);

  return {
    output,
    prompt,
    systemPrompt: SYNTHESIZER_SYSTEM_PROMPT,
    response,
    // The old expression was a tautology for any non-empty reply, so a refused
    // or unparseable response was archived as a success. Report what the parser
    // actually established.
    parseSuccess: output.parseStatus === 'ok',
  };
}

function formatSynthesisPrompt(packet: NormalizedPanelPacket): string {
  const lines = [
    `## Hypothesis`,
    `${packet.hypothesis}`,
    `Severity: ${packet.severity}`,
    '',
    `## Panel Verdicts (${packet.memberVerdicts.length} members)`,
    '',
  ];

  for (const v of packet.memberVerdicts) {
    lines.push(`### ${v.label} (${v.provider}/${v.model})`);
    lines.push(`Verdict: ${v.verdict}`);
    lines.push(`Confidence score: ${v.confidenceScore.toFixed(2)}`);
    if (v.promotedSignals.length > 0) lines.push(`Promoted signals: ${v.promotedSignals.join(', ')}`);
    if (v.dismissedSignals.length > 0) lines.push(`Dismissed signals: ${v.dismissedSignals.join(', ')}`);
    if (v.reactivatedSignals.length > 0) lines.push(`Reactivated signals: ${v.reactivatedSignals.join(', ')}`);
    if (v.evidenceRefs.length > 0) lines.push(`Cited evidence refs: ${v.evidenceRefs.join(', ')}`);
    lines.push('');
  }

  lines.push('## Disagreement Summary');
  lines.push(`Unanimous: ${packet.disagreement.unanimous}`);
  lines.push(`Verdict split: ${JSON.stringify(packet.disagreement.verdictSplit)}`);
  if (packet.disagreement.dissenters.length > 0) {
    lines.push(`Dissenters: ${packet.disagreement.dissenters.join(', ')}`);
  }
  lines.push(`Consensus verdict: ${packet.consensusVerdict ?? 'none'}`);
  lines.push('');

  lines.push('## Raw Evidence');
  lines.push(packet.rawEvidence);

  return lines.join('\n');
}

function formatPanelVerdicts(packet: NormalizedPanelPacket): string {
  const lines = [`Hypothesis: ${packet.hypothesis}`, `Severity: ${packet.severity}`, ''];
  for (const v of packet.memberVerdicts) {
    lines.push(`### ${v.label} (${v.provider}/${v.model})`);
    lines.push(`Verdict: ${v.verdict}`);
    lines.push(`Confidence score: ${v.confidenceScore.toFixed(2)}`);
    if (v.promotedSignals.length > 0) lines.push(`Promoted signals: ${v.promotedSignals.join(', ')}`);
    if (v.dismissedSignals.length > 0) lines.push(`Dismissed signals: ${v.dismissedSignals.join(', ')}`);
    if (v.reactivatedSignals.length > 0) lines.push(`Reactivated signals: ${v.reactivatedSignals.join(', ')}`);
    if (v.evidenceRefs.length > 0) lines.push(`Cited evidence refs: ${v.evidenceRefs.join(', ')}`);
    lines.push('');
  }
  return lines.join('\n');
}

function formatDisagreement(packet: NormalizedPanelPacket): string {
  const lines = [
    `Unanimous: ${packet.disagreement.unanimous}`,
    `Verdict split: ${JSON.stringify(packet.disagreement.verdictSplit)}`,
  ];
  if (packet.disagreement.dissenters.length > 0) {
    lines.push(`Dissenters: ${packet.disagreement.dissenters.join(', ')}`);
  }
  lines.push(`Consensus verdict: ${packet.consensusVerdict ?? 'none'}`);
  return lines.join('\n');
}

function formatRawEvidence(packet: NormalizedPanelPacket): string {
  return packet.rawEvidence;
}

function parseSynthesisResponse(content: string, packet: NormalizedPanelPacket): SynthesisResult {
  const jsonMatch =
    content.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/) ??
    content.match(/(\{[\s\S]*\})/);

  if (jsonMatch) {
    try {
      const parsed = JSON.parse(jsonMatch[1]!);

      const verdict = parsed.verdict ?? 'insufficient_evidence';
      const agreedWith = parsed.agreedWith ?? [];
      const disagreedWith = parsed.disagreedWith ?? [];

      return {
        verdict,
        reasoning: parsed.reasoning ?? content,
        confidence: typeof parsed.confidence === 'number' ? parsed.confidence : 0.5,
        agreedWith,
        disagreedWith,
        decisiveEvidence: parsed.decisiveEvidence ?? [],
        outcomeType: classifyOutcome(verdict, packet),
        parseStatus: 'ok',
      };
    } catch {
      // Fall through
    }
  }

  return {
    verdict: 'insufficient_evidence',
    reasoning: content,
    confidence: 0.3,
    parseStatus: 'fallback_text',
    agreedWith: [],
    disagreedWith: [],
    decisiveEvidence: [],
    outcomeType: 'unresolved_disagreement',
  };
}

function classifyOutcome(
  verdict: string,
  packet: NormalizedPanelPacket,
): SynthesisResult['outcomeType'] {
  if (packet.disagreement.unanimous) {
    return verdict === 'confirmed' ? 'unanimous_confirmation' : 'unanimous_refutation';
  }
  if (verdict === 'confirmed') return 'contested_confirmation';
  return 'unresolved_disagreement';
}

export interface SynthesisInvocation {
  output: SynthesisResult;
  prompt: string;
  systemPrompt: string;
  response: ModelResponse;
  parseSuccess: boolean;
}
