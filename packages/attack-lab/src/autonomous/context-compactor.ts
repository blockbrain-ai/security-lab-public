/**
 * Context compactor — rolls long transcripts and memory into bounded
 * summaries while preserving citations back to raw evidence/event IDs.
 */

import type { WeakSignal, ChainHypothesis } from './contracts.js';

// ---------------------------------------------------------------------------
// Compacted context packs
// ---------------------------------------------------------------------------

export interface CompactedContext {
  /** Total character count of the compacted output. */
  charCount: number;
  /** Content ready for model consumption. */
  content: string;
  /** IDs of signals/hypotheses/findings included. */
  includedIds: string[];
  /** IDs that were truncated or omitted. */
  omittedIds: string[];
}

// ---------------------------------------------------------------------------
// Compaction
// ---------------------------------------------------------------------------

export function compactSignals(
  signals: WeakSignal[],
  maxChars: number = 8000,
): CompactedContext {
  const included: string[] = [];
  const omitted: string[] = [];
  const lines: string[] = [];
  let chars = 0;

  // Sort by: reopened first, then active, then by confidence descending
  const sorted = [...signals].sort((a, b) => {
    if (a.status === 'reopened' && b.status !== 'reopened') return -1;
    if (b.status === 'reopened' && a.status !== 'reopened') return 1;
    if (a.status === 'active' && b.status !== 'active') return -1;
    if (b.status === 'active' && a.status !== 'active') return 1;
    return b.confidence - a.confidence;
  });

  for (const s of sorted) {
    const line = `[${s.id}] (${s.surface}, conf=${s.confidence.toFixed(2)}, ${s.status}) ${s.description}`;
    if (chars + line.length > maxChars) {
      omitted.push(s.id);
      continue;
    }
    lines.push(line);
    included.push(s.id);
    chars += line.length + 1;
  }

  if (omitted.length > 0) {
    lines.push(`... ${omitted.length} more signals omitted`);
  }

  return {
    charCount: chars,
    content: lines.join('\n'),
    includedIds: included,
    omittedIds: omitted,
  };
}

export function compactHypotheses(
  hypotheses: ChainHypothesis[],
  maxChars: number = 6000,
): CompactedContext {
  const included: string[] = [];
  const omitted: string[] = [];
  const lines: string[] = [];
  let chars = 0;

  // Sort by: testing first, then proposed, then by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  const sorted = [...hypotheses].sort((a, b) => {
    if (a.status === 'testing' && b.status !== 'testing') return -1;
    if (b.status === 'testing' && a.status !== 'testing') return 1;
    return (severityOrder[a.severity] ?? 3) - (severityOrder[b.severity] ?? 3);
  });

  for (const h of sorted) {
    if (h.status === 'refuted' || h.status === 'confirmed') continue; // Skip completed
    const line = `[${h.id}] (${h.severity}, ${h.status}) ${h.description.split('\n')[0]} [signals: ${h.signalIds.join(',')}]`;
    if (chars + line.length > maxChars) {
      omitted.push(h.id);
      continue;
    }
    lines.push(line);
    included.push(h.id);
    chars += line.length + 1;
  }

  if (omitted.length > 0) {
    lines.push(`... ${omitted.length} more hypotheses omitted`);
  }

  return {
    charCount: chars,
    content: lines.join('\n'),
    includedIds: included,
    omittedIds: omitted,
  };
}

/**
 * Compact a transcript summary for role memory preservation.
 */
export function compactTranscript(
  entries: Array<{ summary: string; evidenceRefs: string[] }>,
  maxChars: number = 4000,
): string {
  const lines: string[] = [];
  let chars = 0;

  // Most recent first
  for (const entry of [...entries].reverse()) {
    const line = `- ${entry.summary} [refs: ${entry.evidenceRefs.join(',')}]`;
    if (chars + line.length > maxChars) break;
    lines.unshift(line);
    chars += line.length + 1;
  }

  return lines.join('\n');
}
