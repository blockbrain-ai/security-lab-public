/**
 * Memory index — searchable index over weak signals, hypotheses,
 * findings, and probe observations for retrieval-driven context.
 */

import type { CampaignMemory } from './contracts.js';

// ---------------------------------------------------------------------------
// Index entry
// ---------------------------------------------------------------------------

export interface IndexEntry {
  id: string;
  type: 'signal' | 'hypothesis' | 'finding';
  text: string;
  assets: string[];
  surfaces: string[];
  severity: string;
  confidence: number;
  iteration: number;
  status: string;
  isDormant: boolean;
  isReopened: boolean;
  hasUnresolvedCorrelations: boolean;
  graphNeighborIds: string[];
}

// ---------------------------------------------------------------------------
// Index building
// ---------------------------------------------------------------------------

export function buildIndex(memory: CampaignMemory): IndexEntry[] {
  const entries: IndexEntry[] = [];

  for (const signal of memory.signals) {
    const neighbors = memory.graph.edges
      .filter((e) => e.from === `signal:${signal.id}` || e.to === `signal:${signal.id}`)
      .map((e) => (e.from === `signal:${signal.id}` ? e.to : e.from))
      .filter((id) => id.startsWith('signal:'))
      .map((id) => id.replace('signal:', ''));

    entries.push({
      id: signal.id,
      type: 'signal',
      text: signal.description,
      assets: signal.relatedAssets,
      surfaces: [signal.surface],
      severity: 'medium',
      confidence: signal.confidence,
      iteration: signal.iteration,
      status: signal.status,
      isDormant: signal.status === 'dormant',
      isReopened: signal.status === 'reopened',
      hasUnresolvedCorrelations: signal.unresolvedCorrelations.length > 0,
      graphNeighborIds: neighbors,
    });
  }

  for (const hypothesis of memory.hypotheses) {
    entries.push({
      id: hypothesis.id,
      type: 'hypothesis',
      text: hypothesis.description,
      assets: hypothesis.signalIds,
      surfaces: [],
      severity: hypothesis.severity,
      confidence: 0.5,
      iteration: hypothesis.iteration,
      status: hypothesis.status,
      isDormant: hypothesis.status === 'dormant',
      isReopened: false,
      hasUnresolvedCorrelations: false,
      graphNeighborIds: hypothesis.signalIds,
    });
  }

  for (const finding of memory.findings) {
    entries.push({
      id: `finding-${finding.confirmedAt}`,
      type: 'finding',
      text: finding.description,
      assets: finding.reproductionSteps,
      surfaces: [],
      severity: finding.severity,
      confidence: 1.0,
      iteration: finding.iteration,
      status: 'confirmed',
      isDormant: false,
      isReopened: finding.involvedDormantReactivation,
      hasUnresolvedCorrelations: false,
      graphNeighborIds: [],
    });
  }

  return entries;
}

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

export function searchIndex(
  entries: IndexEntry[],
  query: {
    assets?: string[];
    surfaces?: string[];
    minConfidence?: number;
    includeDormant?: boolean;
    includeReopened?: boolean;
    includeUnresolved?: boolean;
    graphNeighborOf?: string[];
    maxResults?: number;
  },
): IndexEntry[] {
  const maxResults = query.maxResults ?? 30;

  return entries
    .filter((e) => {
      if (!query.includeDormant && e.isDormant) return false;
      if (query.minConfidence && e.confidence < query.minConfidence) return false;
      return true;
    })
    .map((e) => ({
      entry: e,
      score: scoreEntry(e, query),
    }))
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, maxResults)
    .map((item) => item.entry);
}

function scoreEntry(
  entry: IndexEntry,
  query: {
    assets?: string[];
    surfaces?: string[];
    includeReopened?: boolean;
    includeUnresolved?: boolean;
    graphNeighborOf?: string[];
  },
): number {
  let score = entry.confidence;

  // Asset overlap
  if (query.assets && query.assets.length > 0) {
    const overlap = entry.assets.filter((a) =>
      query.assets!.some((qa) => a.includes(qa) || qa.includes(a)),
    ).length;
    score += overlap * 0.3;
  }

  // Surface overlap
  if (query.surfaces && query.surfaces.length > 0) {
    const overlap = entry.surfaces.filter((s) => query.surfaces!.includes(s)).length;
    score += overlap * 0.2;
  }

  // Graph neighbor bonus
  if (query.graphNeighborOf && query.graphNeighborOf.length > 0) {
    const neighborOverlap = entry.graphNeighborIds.filter((n) =>
      query.graphNeighborOf!.includes(n),
    ).length;
    score += neighborOverlap * 0.4;
  }

  // Reopened bonus
  if (query.includeReopened && entry.isReopened) score += 0.3;

  // Unresolved correlation bonus
  if (query.includeUnresolved && entry.hasUnresolvedCorrelations) score += 0.25;

  // Severity bonus
  const severityBonus: Record<string, number> = { critical: 0.4, high: 0.3, medium: 0.1, low: 0 };
  score += severityBonus[entry.severity] ?? 0;

  return score;
}
