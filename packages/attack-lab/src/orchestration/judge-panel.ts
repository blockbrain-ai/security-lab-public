/**
 * Judge panel — runs 2-3 judge models in parallel on the same
 * hypothesis/evidence packet, normalizes outputs, and computes
 * disagreement metadata.
 */

import type { InvokeOptions, ModelAdapter } from '../providers/contracts.js';
import type { CampaignMemory, ChainHypothesis } from '../autonomous/contracts.js';
import type { JudgeOutput } from '../autonomous/schemas.js';
import { judge as singleJudge, type JudgeInvocation, type JudgeBriefModeContext } from '../autonomous/judge.js';
import { fetchExcerpts, type SourceExcerpt } from './source-excerpt-fetcher.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PanelMember {
  adapter: ModelAdapter;
  label: string;
}

export interface PanelResult {
  memberResults: PanelMemberResult[];
  disagreement: DisagreementMetrics;
  consensusVerdict: JudgeOutput['verdict'] | null;
}

export interface PanelMemberResult {
  label: string;
  provider: string;
  model: string;
  output: JudgeOutput;
  parseSuccess: boolean;
  durationMs: number;
  invocation: JudgeInvocation;
  confidenceScore: number;
  evidenceRefs: string[];
}

export interface DisagreementMetrics {
  /** Whether all members agree on the verdict. */
  unanimous: boolean;
  /** Verdict split: { "continue": 2, "dead_end": 1 } */
  verdictSplit: Record<string, number>;
  /** Number of distinct verdicts. */
  distinctVerdicts: number;
  /** Members who dissented from majority. */
  dissenters: string[];
  /** Confidence spread (max - min if available). */
  confidenceSpread: number;
  /** Evidence IDs cited by all members. */
  commonEvidenceIds: string[];
  /** Evidence IDs cited by only some members. */
  uniqueEvidenceIds: string[];
}

// ---------------------------------------------------------------------------
// Panel execution
// ---------------------------------------------------------------------------

export async function runJudgePanel(
  members: PanelMember[],
  memory: CampaignMemory,
  hypothesis: ChainHypothesis,
  observations: string,
  options?: {
    retrievedContext?: string;
    roleTranscripts?: Record<string, string>;
    invokeOptionsByLabel?: Record<string, Partial<InvokeOptions<JudgeOutput>>>;
    /** Section 7.1 — workspace root for fetching source excerpts. */
    workspaceRoot?: string;
    /**
     * Per-member brief-mode context. When supplied AND the member's adapter
     * supports native session resume, that member receives a compact
     * pointer-style prompt and reads decision context from disk instead of
     * a 30 KB one-shot. API-only members fall back to the legacy path
     * regardless. See the recovery plan.
     */
    briefModeContextByLabel?: Record<string, JudgeBriefModeContext | undefined>;
  },
): Promise<PanelResult> {
  // Section 7.1 — fetch source excerpts for hypotheses with source location refs.
  let sourceExcerptBlock = '';
  if (options?.workspaceRoot && hypothesis.sourceLocationRefs && hypothesis.sourceLocationRefs.length > 0) {
    const excerpts = await fetchExcerpts(hypothesis.sourceLocationRefs, options.workspaceRoot);
    sourceExcerptBlock = formatExcerptsForPrompt(excerpts);
  }

  const enrichedObservations = sourceExcerptBlock
    ? `${observations}\n\n${sourceExcerptBlock}`
    : observations;

  // Run all judges in parallel
  const results = await Promise.all(
    members.map(async (member): Promise<PanelMemberResult> => {
      const start = Date.now();
      const invocation = await singleJudge(memory, member.adapter, hypothesis, enrichedObservations, {
        retrievedContext: options?.retrievedContext,
        roleTranscript: options?.roleTranscripts?.[member.label],
        invokeOptions: options?.invokeOptionsByLabel?.[member.label],
        briefModeContext: options?.briefModeContextByLabel?.[member.label],
      });
      const evidenceRefs = collectEvidenceRefs(invocation.output);
      return {
        label: member.label,
        provider: member.adapter.provider,
        model: member.adapter.model,
        output: invocation.output,
        parseSuccess: invocation.parseSuccess,
        durationMs: Date.now() - start,
        invocation,
        confidenceScore: scoreJudgeConfidence(invocation.output, invocation.parseSuccess),
        evidenceRefs,
      };
    }),
  );

  const disagreement = computeDisagreement(results);
  const consensusVerdict = findConsensus(results);

  return { memberResults: results, disagreement, consensusVerdict };
}

/**
 * Section 7.1 — format source excerpts into a prompt block for the judge.
 */
function formatExcerptsForPrompt(excerpts: SourceExcerpt[]): string {
  if (excerpts.length === 0) return '';
  const blocks = excerpts.map((e) =>
    `### Source: \`${e.label}\`\n\`\`\`\n${e.content}\n\`\`\``,
  );
  return `## Cited Source Code\n\n${blocks.join('\n\n')}`;
}

// ---------------------------------------------------------------------------
// Disagreement analysis
// ---------------------------------------------------------------------------

function computeDisagreement(results: PanelMemberResult[]): DisagreementMetrics {
  const verdictSplit: Record<string, number> = {};
  for (const r of results) {
    verdictSplit[r.output.verdict] = (verdictSplit[r.output.verdict] ?? 0) + 1;
  }

  const distinctVerdicts = Object.keys(verdictSplit).length;
  const unanimous = distinctVerdicts === 1;

  // Find majority verdict
  const majorityVerdict = Object.entries(verdictSplit)
    .sort((a, b) => b[1] - a[1])[0]?.[0];

  const dissenters = results
    .filter((r) => r.output.verdict !== majorityVerdict)
    .map((r) => r.label);

  const confidenceScores = results.map((result) => result.confidenceScore);
  const confidenceSpread = confidenceScores.length > 0
    ? Math.max(...confidenceScores) - Math.min(...confidenceScores)
    : 0;

  // Evidence overlap is based on normalized evidence references emitted by each judge.
  const allEvidenceSets = results.map((r) => new Set(r.evidenceRefs));
  const commonEvidence = allEvidenceSets.length > 0
    ? [...allEvidenceSets[0]!].filter((id) => allEvidenceSets.every((set) => set.has(id)))
    : [];
  const allUniqueEvidence = [...new Set(results.flatMap((r) => r.evidenceRefs))];
  const uniqueOnly = allUniqueEvidence.filter((id) => !commonEvidence.includes(id));

  return {
    unanimous,
    verdictSplit,
    distinctVerdicts,
    dissenters,
    confidenceSpread,
    commonEvidenceIds: commonEvidence,
    uniqueEvidenceIds: uniqueOnly,
  };
}

function findConsensus(results: PanelMemberResult[]): JudgeOutput['verdict'] | null {
  if (results.length === 0) return null;

  const verdictCounts = new Map<string, number>();
  for (const r of results) {
    verdictCounts.set(r.output.verdict, (verdictCounts.get(r.output.verdict) ?? 0) + 1);
  }

  // Majority wins
  const majority = Math.ceil(results.length / 2);
  for (const [verdict, count] of verdictCounts) {
    if (count >= majority) {
      return verdict as JudgeOutput['verdict'];
    }
  }

  return null; // No consensus
}

// ---------------------------------------------------------------------------
// Normalized panel output for synthesizer
// ---------------------------------------------------------------------------

export interface NormalizedPanelPacket {
  hypothesis: string;
  severity: string;
  memberVerdicts: Array<{
    label: string;
    provider: string;
    model: string;
    verdict: string;
    confidenceScore: number;
    promotedSignals: string[];
    dismissedSignals: string[];
    reactivatedSignals: string[];
    evidenceRefs: string[];
  }>;
  disagreement: DisagreementMetrics;
  consensusVerdict: string | null;
  rawEvidence: string;
}

export function normalizePanelForSynthesis(
  panel: PanelResult,
  hypothesis: ChainHypothesis,
  evidence: string,
): NormalizedPanelPacket {
  return {
    hypothesis: hypothesis.description,
    severity: hypothesis.severity,
    memberVerdicts: panel.memberResults.map((r) => ({
      label: r.label,
      provider: r.provider,
      model: r.model,
      verdict: r.output.verdict,
      confidenceScore: r.confidenceScore,
      promotedSignals: r.output.promoteSignals,
      dismissedSignals: r.output.dismissSignals,
      reactivatedSignals: r.output.reactivateSignals.map((s) => s.signalId),
      evidenceRefs: r.evidenceRefs,
    })),
    disagreement: panel.disagreement,
    consensusVerdict: panel.consensusVerdict,
    rawEvidence: evidence,
  };
}

function collectEvidenceRefs(output: JudgeOutput): string[] {
  const refs = new Set<string>();
  for (const signalId of output.promoteSignals) refs.add(signalId);
  for (const signalId of output.dismissSignals) refs.add(signalId);
  for (const reactivation of output.reactivateSignals) refs.add(reactivation.signalId);
  for (const correlation of output.newCorrelations) {
    refs.add(correlation.signalIdA);
    refs.add(correlation.signalIdB);
  }
  return [...refs];
}

function scoreJudgeConfidence(output: JudgeOutput, parseSuccess: boolean): number {
  let score = parseSuccess ? 0.45 : 0.2;
  if (output.partialProgress) score += 0.1;
  if (output.finding) score += 0.2;
  score += Math.min(0.15, output.promoteSignals.length * 0.03);
  score += Math.min(0.1, output.reactivateSignals.length * 0.05);
  if (output.verdict === 'dead_end') score -= 0.05;
  return Math.max(0, Math.min(1, score));
}
