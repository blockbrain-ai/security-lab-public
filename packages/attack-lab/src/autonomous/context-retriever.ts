/**
 * Context retriever — builds role-specific evidence retrieval bundles
 * tailored to the current task, graph state, and target surface.
 *
 * Replaces top-N memory snapshots with graph-aware, asset-relevant,
 * dormant-aware retrieval that surfaces the right evidence regardless
 * of recency.
 */

import type { CampaignMemory, ChainHypothesis } from './contracts.js';
import { buildIndex, searchIndex } from './memory-index.js';
import { compactSignals, compactHypotheses } from './context-compactor.js';
import { getDormantSignals, getActiveSignals, getSignalsWithUnresolvedCorrelations } from './weak-signal-ledger.js';
import { summarizeGraph } from './attack-graph.js';

// ---------------------------------------------------------------------------
// Context packs
// ---------------------------------------------------------------------------

export interface ContextPack {
  /** Content ready for model consumption. */
  content: string;
  /** Total character count. */
  charCount: number;
  /** IDs of items included in this pack. */
  includedIds: string[];
  /** IDs of items that were available but omitted. */
  omittedIds: string[];
}

// ---------------------------------------------------------------------------
// Planner context
// ---------------------------------------------------------------------------

export function plannerContextPack(
  memory: CampaignMemory,
  targetSurface: string,
  maxChars: number = 40000,
): ContextPack {
  const index = buildIndex(memory);
  const active = getActiveSignals(memory);
  const dormant = getDormantSignals(memory);
  const unresolved = getSignalsWithUnresolvedCorrelations(memory);
  const omittedIds: string[] = [];

  // Retrieve signals relevant to the current attack graph frontier
  const graphFrontier = searchIndex(index, {
    includeReopened: true,
    includeUnresolved: true,
    includeDormant: false,
    maxResults: 30,
  });

  const sections: string[] = [];
  let totalChars = 0;

  // Section 1: Target surface (always included, capped)
  const surfaceBudget = Math.min(maxChars * 0.4, targetSurface.length);
  sections.push(targetSurface.slice(0, surfaceBudget));
  totalChars += surfaceBudget;

  // Section 2: Active signals (graph-relevant first)
  const signalBudget = Math.min(maxChars * 0.2, 8000);
  const compacted = compactSignals(active, signalBudget);
  if (compacted.content) {
    sections.push(`## Active Signals (${active.length} total)\n${compacted.content}`);
    totalChars += compacted.charCount;
  }
  omittedIds.push(...compacted.omittedIds);

  // Section 3: Graph frontier / retrieved evidence
  if (graphFrontier.length > 0) {
    const frontierLines: string[] = [];
    let frontierChars = 0;
    for (const entry of graphFrontier) {
      const line = `- [${entry.id}] (${entry.type}, ${entry.status}, conf=${entry.confidence.toFixed(2)}) ${entry.text.slice(0, 160)}`;
      if (totalChars + frontierChars + line.length > maxChars) {
        omittedIds.push(entry.id);
        continue;
      }
      frontierLines.push(line);
      frontierChars += line.length + 1;
    }

    if (frontierLines.length > 0) {
      sections.push(`## Retrieved Frontier Evidence\n${frontierLines.join('\n')}`);
      totalChars += frontierChars;
    }
  }

  // Section 4: Dormant signals available for resurfacing
  if (dormant.length > 0) {
    const dormantCompact = compactSignals(dormant, 3000);
    sections.push(`## Dormant Signals (${dormant.length} — may be worth resurfacing)\n${dormantCompact.content}`);
    totalChars += dormantCompact.charCount;
    omittedIds.push(...dormantCompact.omittedIds);
  }

  // Section 5: Unresolved correlations
  if (unresolved.length > 0) {
    const unresolvedLines = unresolved.slice(0, 10).map((s) =>
      `- [${s.id}] unresolved with: ${s.unresolvedCorrelations.join(', ')}`,
    );
    const section = `## Unresolved Correlations\n${unresolvedLines.join('\n')}`;
    sections.push(section);
    totalChars += section.length;
  }

  // Section 6: Attack graph summary
  const graphSummary = summarizeGraph(memory.graph);
  if (totalChars + graphSummary.length < maxChars) {
    sections.push(`## Attack Graph\n${graphSummary}`);
    totalChars += graphSummary.length;
  }

  // Section 7: Active hypotheses
  const activeHyps = memory.hypotheses.filter((h) => h.status !== 'refuted' && h.status !== 'confirmed');
  if (activeHyps.length > 0) {
    const hypCompact = compactHypotheses(activeHyps, 4000);
    sections.push(`## Active Hypotheses (${activeHyps.length} total)\n${hypCompact.content}`);
    totalChars += hypCompact.charCount;
    omittedIds.push(...hypCompact.omittedIds);
  }

  const allIds = [
    ...compacted.includedIds,
    ...graphFrontier.map((e) => e.id),
  ];

  return {
    content: sections.join('\n\n---\n\n'),
    charCount: totalChars,
    includedIds: [...new Set(allIds)],
    omittedIds: [...new Set(omittedIds)],
  };
}

// ---------------------------------------------------------------------------
// Judge context
// ---------------------------------------------------------------------------

export function judgeContextPack(
  memory: CampaignMemory,
  hypothesis: ChainHypothesis,
  observations: string,
  maxChars: number = 20000,
): ContextPack {
  const index = buildIndex(memory);
  const includedIds: string[] = [];

  const sections: string[] = [];

  // Section 1: The hypothesis being judged
  sections.push(`## Hypothesis\n${hypothesis.description}\nSeverity: ${hypothesis.severity}\nSignals: ${hypothesis.signalIds.join(', ')}`);

  // Section 2: Observations from this round
  const obsBudget = Math.min(maxChars * 0.4, observations.length);
  sections.push(`## Probe Observations\n${observations.slice(0, obsBudget)}`);

  // Section 3: Signals involved in this hypothesis (full detail)
  const relevantSignals = memory.signals.filter((s) => hypothesis.signalIds.includes(s.id));
  for (const s of relevantSignals) {
    sections.push(`### Signal ${s.id} (${s.surface}, conf=${s.confidence.toFixed(2)}, ${s.status})\n${s.description}`);
    includedIds.push(s.id);
  }

  // Section 4: Graph-adjacent signals not in the hypothesis
  const neighbors = searchIndex(index, {
    graphNeighborOf: hypothesis.signalIds,
    includeDormant: true,
    includeReopened: true,
    includeUnresolved: true,
    maxResults: 10,
  }).filter((e) => !hypothesis.signalIds.includes(e.id));

  if (neighbors.length > 0) {
    const neighborLines = neighbors.map((n) => `- [${n.id}] (${n.type}, ${n.status}) ${n.text.slice(0, 100)}`);
    sections.push(`## Related Signals (graph-adjacent)\n${neighborLines.join('\n')}`);
    includedIds.push(...neighbors.map((n) => n.id));
  }

  // Section 5: Prior attempts on this hypothesis
  if (hypothesis.attempts.length > 0) {
    const attemptLines = hypothesis.attempts.map((a) =>
      `- Iter ${a.iteration}: ${a.verdict} — ${a.reasoning.slice(0, 200)}`,
    );
    sections.push(`## Prior Attempts (${hypothesis.attempts.length})\n${attemptLines.join('\n')}`);
  }

  // Section 6: Dormant signals that share assets
  const dormant = getDormantSignals(memory);
  const relevantDormant = dormant.filter((d) =>
    d.relatedAssets.some((asset) =>
      relevantSignals.some((rs) => rs.relatedAssets.includes(asset)),
    ),
  );
  if (relevantDormant.length > 0) {
    const dormantLines = relevantDormant.map((d) => `- [${d.id}] (${d.surface}) ${d.description}`);
    sections.push(`## Dormant Signals Sharing Assets\n${dormantLines.join('\n')}`);
    includedIds.push(...relevantDormant.map((d) => d.id));
  }

  return {
    content: sections.join('\n\n---\n\n'),
    charCount: sections.join('\n\n---\n\n').length,
    includedIds: [...new Set(includedIds)],
    omittedIds: [],
  };
}

// ---------------------------------------------------------------------------
// Synthesizer context
// ---------------------------------------------------------------------------

export function synthesizerContextPack(
  panelOutput: string,
  evidence: string,
  maxChars: number = 15000,
): ContextPack {
  // Synthesizer gets normalized panel output + raw evidence only
  // No raw model transcripts to avoid bias double-counting
  const content = `${panelOutput}\n\n---\n\n## Raw Evidence\n${evidence.slice(0, maxChars - panelOutput.length)}`;

  return {
    content,
    charCount: content.length,
    includedIds: [],
    omittedIds: [],
  };
}
