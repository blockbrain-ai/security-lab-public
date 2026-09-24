/**
 * Section 11.5 — Lead brief manifests.
 *
 * Generates compact per-lead briefs on disk that include the hypothesis,
 * decisive signals, exact source refs, relevant routes/surfaces, required
 * identities, suggested probe families, and current evidence gaps. These
 * briefs are the handoff artifact between the static investigation and
 * the focused persistent worker sessions.
 */

import { writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import type { ChainHypothesis, WeakSignal } from '../../autonomous/contracts.js';
import type { RankedLead } from './lead-ranker.js';
import type { SourceLocationRef } from '../../../../evidence-plane/src/source-location-ref.js';

// ---------------------------------------------------------------------------
// Brief manifest types
// ---------------------------------------------------------------------------

export interface LeadBrief {
  /** The ranked lead this brief is for. */
  hypothesisId: string;
  /** Rank position (1-based). */
  rank: number;
  /** Composite ranking score. */
  score: number;
  /** One-line hypothesis description. */
  hypothesis: string;
  /** Severity of the hypothesis. */
  severity: string;
  /** Signals that compose this hypothesis, with descriptions. */
  decisiveSignals: DecisiveSignal[];
  /** Source location references from the hypothesis. */
  sourceRefs: SourceLocationRef[];
  /** Related assets (files, endpoints, routes). */
  relatedAssets: string[];
  /** Surfaces discovered during static analysis. */
  relevantSurfaces: string[];
  /** Required identities or bootstrap requirements for probing. */
  requiredIdentities: string[];
  /** Suggested probe family and its variants. */
  suggestedProbeFamily: string;
  /** Current evidence gaps that the worker should try to fill. */
  evidenceGaps: string[];
  /** Prior attempt summaries, if any. */
  priorAttempts: PriorAttemptSummary[];
  /** Path where this brief was written. */
  briefPath?: string;
}

export interface DecisiveSignal {
  id: string;
  description: string;
  surface: string;
  confidence: number;
}

export interface PriorAttemptSummary {
  at: string;
  verdict: string;
  observation: string;
}

// ---------------------------------------------------------------------------
// Brief generation
// ---------------------------------------------------------------------------

/**
 * Build a LeadBrief from a RankedLead and its composing signals.
 */
export function buildLeadBrief(
  ranked: RankedLead,
  signals: readonly WeakSignal[],
): LeadBrief {
  const h = ranked.hypothesis;
  const signalIndex = new Map<string, WeakSignal>();
  for (const s of signals) signalIndex.set(s.id, s);

  const decisiveSignals: DecisiveSignal[] = h.signalIds
    .map((id) => signalIndex.get(id))
    .filter((s): s is WeakSignal => s != null)
    .map((s) => ({
      id: s.id,
      description: s.description,
      surface: s.surface,
      confidence: s.confidence,
    }));

  const relatedAssets = collectRelatedAssets(h, decisiveSignals.map((s) => signalIndex.get(s.id)).filter(Boolean) as WeakSignal[]);

  const relevantSurfaces = [
    ...new Set(decisiveSignals.map((s) => s.surface).filter(Boolean)),
  ];

  const requiredIdentities = extractRequiredIdentities(h);

  const evidenceGaps = identifyEvidenceGaps(h, decisiveSignals);

  const priorAttempts: PriorAttemptSummary[] = h.attempts.map((a) => ({
    at: a.at,
    verdict: a.verdict,
    observation: a.observation,
  }));

  return {
    hypothesisId: h.id,
    rank: ranked.rank,
    score: ranked.score,
    hypothesis: h.description,
    severity: h.severity,
    decisiveSignals,
    sourceRefs: h.sourceLocationRefs ?? [],
    relatedAssets,
    relevantSurfaces,
    requiredIdentities,
    suggestedProbeFamily: ranked.probeFamily,
    evidenceGaps,
    priorAttempts,
  };
}

function collectRelatedAssets(
  _hypothesis: ChainHypothesis,
  signals: readonly WeakSignal[],
): string[] {
  const assets = new Set<string>();
  for (const s of signals) {
    for (const a of s.relatedAssets) assets.add(a);
  }
  return [...assets];
}

function extractRequiredIdentities(hypothesis: ChainHypothesis): string[] {
  const identities: string[] = [];
  if (hypothesis.privilegeDelta) {
    identities.push(hypothesis.privilegeDelta.before);
    identities.push(hypothesis.privilegeDelta.after);
  }
  if (hypothesis.boundaryCrossing) {
    identities.push(`boundary:${hypothesis.boundaryCrossing.from}`);
    identities.push(`boundary:${hypothesis.boundaryCrossing.to}`);
  }
  return [...new Set(identities)];
}

function identifyEvidenceGaps(
  hypothesis: ChainHypothesis,
  signals: readonly DecisiveSignal[],
): string[] {
  const gaps: string[] = [];

  // No source location refs — worker should try to locate the vulnerable code.
  if (!hypothesis.sourceLocationRefs || hypothesis.sourceLocationRefs.length === 0) {
    gaps.push('No source location refs — worker should identify the vulnerable code path');
  }

  // No live confirmation attempts yet.
  if (hypothesis.attempts.length === 0) {
    gaps.push('No prior probe attempts — fresh confirmation needed');
  }

  // All prior attempts inconclusive.
  const allInconclusive = hypothesis.attempts.length > 0 &&
    hypothesis.attempts.every((a) => a.verdict === 'dead_end' || a.verdict === 'partial');
  if (allInconclusive) {
    gaps.push('All prior attempts were inconclusive — consider alternative probe angles');
  }

  // Low-confidence signals need corroboration.
  const lowConfidence = signals.filter((s) => s.confidence < 0.5);
  if (lowConfidence.length > 0) {
    gaps.push(`${lowConfidence.length} signal(s) below 50% confidence — needs corroboration`);
  }

  // Missing boundary crossing details.
  if (hypothesis.boundaryCrossing && !hypothesis.boundaryCrossing.mechanism) {
    gaps.push('Boundary crossing declared but mechanism not specified');
  }

  return gaps;
}

// ---------------------------------------------------------------------------
// Disk persistence
// ---------------------------------------------------------------------------

/**
 * Write brief manifests to disk under the campaign directory.
 * Returns the briefs with their `briefPath` fields populated.
 */
export async function writeBriefManifests(
  briefs: LeadBrief[],
  campaignDir: string,
): Promise<LeadBrief[]> {
  const briefDir = join(campaignDir, 'focused-lead-briefs');
  await mkdir(briefDir, { recursive: true });

  const written: LeadBrief[] = [];
  for (const brief of briefs) {
    const filename = `brief-${brief.rank}-${sanitizeId(brief.hypothesisId)}.json`;
    const briefPath = join(briefDir, filename);
    await writeFile(briefPath, JSON.stringify(brief, null, 2), 'utf-8');
    written.push({ ...brief, briefPath });
  }

  return written;
}

function sanitizeId(id: string): string {
  return id.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 60);
}

/**
 * Render a brief as a compact markdown string suitable for worker prompts.
 * This avoids giant inline prompts by keeping the brief focused.
 */
export function renderBriefForWorker(brief: LeadBrief): string {
  const lines: string[] = [];
  lines.push(`# Lead Brief: ${brief.hypothesisId} (rank ${brief.rank})`);
  lines.push('');
  lines.push(`**Hypothesis:** ${brief.hypothesis}`);
  lines.push(`**Severity:** ${brief.severity}`);
  lines.push(`**Score:** ${brief.score.toFixed(3)}`);
  lines.push(`**Probe family:** ${brief.suggestedProbeFamily}`);
  lines.push('');

  if (brief.sourceRefs.length > 0) {
    lines.push('## Source Refs');
    for (const ref of brief.sourceRefs) {
      lines.push(`- ${ref.path}:${ref.startLine}-${ref.endLine}`);
    }
    lines.push('');
  }

  if (brief.relatedAssets.length > 0) {
    lines.push('## Related Assets');
    for (const a of brief.relatedAssets) {
      lines.push(`- ${a}`);
    }
    lines.push('');
  }

  if (brief.requiredIdentities.length > 0) {
    lines.push('## Required Identities');
    for (const id of brief.requiredIdentities) {
      lines.push(`- ${id}`);
    }
    lines.push('');
  }

  if (brief.evidenceGaps.length > 0) {
    lines.push('## Evidence Gaps');
    for (const gap of brief.evidenceGaps) {
      lines.push(`- ${gap}`);
    }
    lines.push('');
  }

  if (brief.priorAttempts.length > 0) {
    lines.push('## Prior Attempts');
    for (const a of brief.priorAttempts) {
      lines.push(`- [${a.verdict}] ${a.observation}`);
    }
    lines.push('');
  }

  lines.push('## Your Task');
  lines.push('Inspect the related files and artifacts. Identify the specific code path.');
  lines.push('Request precise probes through the orchestrator to confirm or refute this hypothesis.');
  lines.push('Do not execute live probes directly — route all probe requests back.');
  return lines.join('\n');
}
