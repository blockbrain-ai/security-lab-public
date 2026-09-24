/**
 * Section 5.2 — FocusedClosureStage.
 *
 * The focused closure stage takes the campaign hypotheses and produces a
 * *focused list* of hypotheses that are candidates for a `confirmed`
 * verdict, each carrying explicit cited evidence refs. The stage applies
 * the contract rule that `confirmed` findings must
 * cite at least one source or probe evidence ref. Hypotheses that do not
 * carry either are flagged as `unconfirmed_lead` and excluded from the
 * focused list.
 *
 * During the Section 5.2 seam-only pass (see the 2026-04-11 governance
 * amendment in the stage-extraction spec),
 * the runner continues to own the file-read focused closure loop. What
 * this stage *does* own, and applies *at runtime* during a live campaign,
 * is the citation-rule audit: it reads `memory.hypotheses` from the stage
 * context, maps each `ChainHypothesis` into the citation-rule input
 * (signalIds as source refs, flattened attempt probeIds as probe refs),
 * runs `applyEvidenceRefCitationRule()`, and emits a
 * `focused_closure_citation_audit` event reporting the focused list and
 * the `unconfirmed_lead` bucket. This satisfies the contract
 * gate that the stage "actually apply the citation rule" in a live run.
 *
 * Section 5.3 will land the file-read loop body behind the fixture-
 * campaign equivalence harness.
 */
import type { CampaignAssessment } from '../../orchestration/campaign-assessment.js';
import type { ChainHypothesis } from '../contracts.js';
import type { Stage, StageContext, StageResult } from './contracts.js';
import type { SourceLocationRef } from '../../../../evidence-plane/src/source-location-ref.js';

export interface HypothesisForClosure {
  id: string;
  description: string;
  severity: string;
  sourceRefs?: string[];
  probeRefs?: string[];
  eventRefs?: string[];
  /** Section 7.1 — typed source location refs from the hypothesis. */
  sourceLocationRefs?: SourceLocationRef[];
}

export interface FocusedClosureInput {
  hypotheses: HypothesisForClosure[];
  assessment?: CampaignAssessment;
}

export interface FocusedClosureOutput {
  /** Hypotheses carrying at least one source/probe/event ref. */
  focusedList: HypothesisForClosure[];
  /** Hypotheses that do not carry enough evidence to be confirmed. */
  unconfirmedLeads: HypothesisForClosure[];
}

/**
 * Pure citation-rule predicate. A hypothesis may enter the focused list
 * only if it cites at least one source ref, probe ref, or event ref.
 * This matches the SL1 / contract rule that `confirmed`
 * findings must cite evidence.
 */
export function hasSufficientEvidenceRefs(hypothesis: HypothesisForClosure): boolean {
  if (hypothesis.sourceRefs && hypothesis.sourceRefs.length > 0) return true;
  if (hypothesis.probeRefs && hypothesis.probeRefs.length > 0) return true;
  if (hypothesis.eventRefs && hypothesis.eventRefs.length > 0) return true;
  // Section 7.1 — typed source location refs count as source evidence.
  if (hypothesis.sourceLocationRefs && hypothesis.sourceLocationRefs.length > 0) return true;
  return false;
}

/**
 * Apply the evidence-ref citation rule to a list of hypotheses.
 * Returns the focused list (with sufficient refs) and the unconfirmed
 * leads (missing refs).
 */
export function applyEvidenceRefCitationRule(
  input: FocusedClosureInput,
): FocusedClosureOutput {
  const focusedList: HypothesisForClosure[] = [];
  const unconfirmedLeads: HypothesisForClosure[] = [];
  for (const hypothesis of input.hypotheses) {
    if (hasSufficientEvidenceRefs(hypothesis)) {
      focusedList.push(hypothesis);
    } else {
      unconfirmedLeads.push(hypothesis);
    }
  }
  return { focusedList, unconfirmedLeads };
}

/**
 * Map a `ChainHypothesis` from `CampaignMemory` into the citation-rule
 * input shape. `signalIds` count as source refs (each weak signal is
 * tracked with its own provenance), and every `attempts[].probeIds`
 * entry is flattened into the probe-ref list.
 */
export function hypothesisForClosureFromChain(hypothesis: ChainHypothesis): HypothesisForClosure {
  const probeRefs: string[] = [];
  for (const attempt of hypothesis.attempts) {
    for (const probeId of attempt.probeIds) {
      probeRefs.push(probeId);
    }
  }
  return {
    id: hypothesis.id,
    description: hypothesis.description,
    severity: hypothesis.severity,
    sourceRefs: [...hypothesis.signalIds],
    probeRefs,
    sourceLocationRefs: hypothesis.sourceLocationRefs,
  };
}

/**
 * The FocusedClosureStage — Section 5.2 seam.
 *
 * `run()` actively applies the citation rule to the campaign memory's
 * hypotheses and emits a `focused_closure_citation_audit` event with the
 * focused list ids and the `unconfirmed_lead` bucket. The stage does
 * *not* mutate campaign memory or rewrite hypothesis verdicts — the
 * runner's inline focused-closure loop still owns that path during 5.2
 * and is gated on the 5.3 fixture-campaign harness.
 */
export class FocusedClosureStage implements Stage {
  readonly name = 'focused_closure' as const;

  async run(context: StageContext): Promise<StageResult> {
    const chainHypotheses = context.memory?.hypotheses ?? [];
    const input: FocusedClosureInput = {
      hypotheses: chainHypotheses.map(hypothesisForClosureFromChain),
    };
    const { focusedList, unconfirmedLeads } = applyEvidenceRefCitationRule(input);

    const payload = {
      totalHypotheses: input.hypotheses.length,
      focusedCount: focusedList.length,
      unconfirmedLeadCount: unconfirmedLeads.length,
      focusedIds: focusedList.map((h) => h.id),
      unconfirmedLeadIds: unconfirmedLeads.map((h) => h.id),
    };

    if (context.evidenceStore) {
      await context.evidenceStore.appendEvent('focused_closure_citation_audit', payload);
    }

    return {
      stage: 'focused_closure',
      outcome: 'complete',
      events: [{ name: 'focused_closure_citation_audit', payload }],
      coverageGaps: [],
      metadata: {
        focusedList,
        unconfirmedLeads,
      },
    };
  }
}
