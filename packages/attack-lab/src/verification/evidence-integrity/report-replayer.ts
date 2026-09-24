/**
 * Report replayer — re-runs campaign assessment from raw evidence and
 * compares the replayed verdict to the original. If they diverge,
 * either the evaluator drifted or the original report was tampered.
 */

import { createHash } from 'node:crypto';
import type { ReportReplayResult } from './contracts.js';

// ---------------------------------------------------------------------------
// Replay input
// ---------------------------------------------------------------------------

export interface ReportReplayInput {
  reportId: string;
  originalReport: { findings: Array<Record<string, unknown>> };
  rawEvidence: Array<Record<string, unknown>>;
  replayer: (
    evidence: Array<Record<string, unknown>>,
  ) => Promise<{ findings: Array<Record<string, unknown>> }>;
}

// ---------------------------------------------------------------------------
// Report replayer
// ---------------------------------------------------------------------------

export class ReportReplayer {
  async replay(input: ReportReplayInput): Promise<ReportReplayResult> {
    const replayed = await input.replayer(input.rawEvidence);

    const originalHash = hashFindings(input.originalReport.findings);
    const replayedHash = hashFindings(replayed.findings);

    const deltas = diffFindings(input.originalReport.findings, replayed.findings);

    return {
      reportId: input.reportId,
      originalVerdictHash: originalHash,
      replayedVerdictHash: replayedHash,
      matches: originalHash === replayedHash,
      deltas,
      notes:
        originalHash === replayedHash
          ? 'replayed verdict matches original — evaluator drift unlikely'
          : `replayed verdict diverges in ${deltas.length} fields — investigate evaluator drift or tamper`,
    };
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hashFindings(findings: Array<Record<string, unknown>>): string {
  // Sort by id for stable hashing
  const sorted = [...findings].sort((a, b) => String(a['id'] ?? '').localeCompare(String(b['id'] ?? '')));
  return createHash('sha256').update(JSON.stringify(sorted)).digest('hex');
}

function diffFindings(
  original: Array<Record<string, unknown>>,
  replayed: Array<Record<string, unknown>>,
): ReportReplayResult['deltas'] {
  const deltas: ReportReplayResult['deltas'] = [];
  const replayedById = new Map<string, Record<string, unknown>>();
  for (const f of replayed) replayedById.set(String(f['id'] ?? ''), f);

  for (const orig of original) {
    const id = String(orig['id'] ?? '');
    const r = replayedById.get(id);
    if (!r) {
      deltas.push({ findingId: id, field: 'existence', original: 'present', replayed: 'missing' });
      continue;
    }
    for (const key of Object.keys(orig)) {
      if (JSON.stringify(orig[key]) !== JSON.stringify(r[key])) {
        deltas.push({ findingId: id, field: key, original: orig[key], replayed: r[key] });
      }
    }
  }
  return deltas;
}
