/**
 * Section 5.2 — AssessmentReportingStage.
 *
 * The assessment and reporting stages always run together and share a
 * context (the campaign summary → executive assessment → investigation
 * report chain). Section 5.2 gives them a single named module so the
 * runner's coordinator loop carries a stable seam, even though the
 * physical body move of `runCampaignAssessmentStage()` and the final
 * report rendering block is deferred to Section 5.3 — see the
 * 2026-04-11 governance amendment in
 * the stage-extraction spec.
 *
 * During Section 5.2, this stage is **actively invoked** by
 * `executeCampaignPipeline()` at the natural boundary just before the
 * inline assessment code path. `run()` emits an
 * `assessment_stage_seam` event to mark the entry and returns a stage
 * result with the event in `events[]` so the runner is free to forward
 * or flush it. The runner continues to own the assessment panel
 * invocation, the synthesizer fallback, the focused-closure-triggered
 * reassessment, and the final report rendering until Section 5.3 lands
 * the body move behind the fixture-campaign equivalence harness.
 */
import type { SourceLocationRef } from '../../../../evidence-plane/src/source-location-ref.js';
import { formatSourceRef } from '../../../../evidence-plane/src/source-location-ref.js';
import type { Stage, StageContext, StageResult } from './contracts.js';

/** CLI-backed provider identifiers that can read local files. */
const CLI_BACKED_PROVIDERS = new Set(['claude_code', 'codex_cli', 'bounded_local', 'pi_cli']);

/**
 * Collect all unique `SourceLocationRef` objects from confirmed hypotheses
 * in the campaign memory.
 */
function collectCitedSourceRefs(context: StageContext): SourceLocationRef[] {
  const hypotheses = context.memory?.hypotheses ?? [];
  const refs: SourceLocationRef[] = [];
  const seen = new Set<string>();
  for (const h of hypotheses) {
    if (!h.sourceLocationRefs) continue;
    for (const ref of h.sourceLocationRefs) {
      const key = formatSourceRef(ref);
      if (!seen.has(key)) {
        seen.add(key);
        refs.push(ref);
      }
    }
  }
  return refs;
}

export class AssessmentReportingStage implements Stage {
  readonly name = 'assessment' as const;

  async run(context: StageContext): Promise<StageResult> {
    // Section 7.1 — collect cited file paths for CLI-backed adapters.
    const citedRefs = collectCitedSourceRefs(context);
    const citedFilePaths = [...new Set(citedRefs.map((r) => r.path))];

    const reporterProvider = context.adapters.reporter?.provider ?? context.adapters.synthesizer?.provider;
    const isCliBacked = reporterProvider != null && CLI_BACKED_PROVIDERS.has(reporterProvider);

    const payload: Record<string, unknown> = {
      phase: context.state?.phase ?? 'unknown',
      hypothesisCount: context.memory?.hypotheses?.length ?? 0,
      citedSourceFileCount: citedFilePaths.length,
      assessmentAdapterIsCliBacked: isCliBacked,
    };

    // When the adapter is CLI-backed, include the list of cited file paths
    // so the assessment worker can read them and verify consistency.
    if (isCliBacked && citedFilePaths.length > 0) {
      payload.citedFilePaths = citedFilePaths;
    }

    if (context.evidenceStore) {
      await context.evidenceStore.appendEvent('assessment_stage_seam', payload);
    }

    return {
      stage: 'assessment',
      outcome: 'complete',
      events: [{ name: 'assessment_stage_seam', payload }],
      coverageGaps: [],
      metadata: {
        citedFilePaths: isCliBacked ? citedFilePaths : [],
        isCliBacked,
      },
    };
  }
}
