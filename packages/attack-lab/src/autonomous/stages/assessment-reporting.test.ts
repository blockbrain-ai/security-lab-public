/**
 * Section 5.2 — boundary tests for the AssessmentReportingStage seam.
 *
 * During Section 5.2 the assessment + reporting stage module is an
 * active named boundary marker. The runner pipeline still owns the
 * authoritative assessment panel / synthesizer fallback / report
 * render, but the stage module is invoked at the seam from
 * `executeCampaignPipeline()` and emits an `assessment_stage_seam`
 * event. Future sections migrate the bodies in without disturbing the
 * pipeline contract, so these tests pin the seam-level contract.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AssessmentReportingStage } from './assessment-reporting.js';
import type { StageContext } from './contracts.js';

interface AppendedEvent {
  stage: string;
  payload: Record<string, unknown>;
}

function stubContext(
  log: AppendedEvent[],
  overrides?: Partial<StageContext>,
): StageContext {
  return {
    memory: { hypotheses: [] },
    state: { phase: 'assessing' },
    evidenceStore: {
      appendEvent: async (stage: string, payload: Record<string, unknown>) => {
        log.push({ stage, payload });
      },
    },
    adapters: {
      reporter: undefined,
      synthesizer: undefined,
    },
    ...overrides,
  } as unknown as StageContext;
}

test('AssessmentReportingStage exposes the assessment stage name', () => {
  const stage = new AssessmentReportingStage();
  assert.equal(stage.name, 'assessment');
});

test('AssessmentReportingStage.run emits an assessment_stage_seam event', async () => {
  const stage = new AssessmentReportingStage();
  const log: AppendedEvent[] = [];
  const result = await stage.run(stubContext(log));

  assert.equal(result.stage, 'assessment');
  assert.equal(result.outcome, 'complete');
  assert.equal(result.events.length, 1);
  assert.equal(result.events[0]?.name, 'assessment_stage_seam');
  assert.deepEqual(result.coverageGaps, []);

  assert.equal(log.length, 1);
  assert.equal(log[0]?.stage, 'assessment_stage_seam');
  assert.equal(log[0]?.payload['phase'], 'assessing');
  assert.equal(log[0]?.payload['hypothesisCount'], 0);
  assert.equal(log[0]?.payload['citedSourceFileCount'], 0);
});

// ---------------------------------------------------------------------------
// Section 7.1 — CLI-backed assessment file access
// ---------------------------------------------------------------------------

test('AssessmentReportingStage passes cited file paths for CLI-backed adapters', async () => {
  const stage = new AssessmentReportingStage();
  const log: AppendedEvent[] = [];
  const ctx = stubContext(log, {
    memory: {
      hypotheses: [
        {
          id: 'h1',
          sourceLocationRefs: [
            { path: 'src/handler.ts', startLine: 10, endLine: 20 },
            { path: 'src/db.ts', startLine: 5 },
          ],
        },
        {
          id: 'h2',
          sourceLocationRefs: [
            { path: 'src/handler.ts', startLine: 10, endLine: 20 }, // duplicate path
          ],
        },
      ],
    } as unknown as StageContext['memory'],
    adapters: {
      reporter: { provider: 'claude_code' },
      synthesizer: undefined,
    } as unknown as StageContext['adapters'],
  });
  const result = await stage.run(ctx);

  assert.equal(result.metadata['isCliBacked'], true);
  const citedPaths = result.metadata['citedFilePaths'] as string[];
  assert.ok(citedPaths.includes('src/handler.ts'));
  assert.ok(citedPaths.includes('src/db.ts'));

  const eventPayload = log[0]?.payload;
  assert.equal(eventPayload?.['assessmentAdapterIsCliBacked'], true);
  assert.ok(Array.isArray(eventPayload?.['citedFilePaths']));
});

test('AssessmentReportingStage treats bounded_local as CLI-backed', async () => {
  const stage = new AssessmentReportingStage();
  const log: AppendedEvent[] = [];
  const ctx = stubContext(log, {
    memory: {
      hypotheses: [
        {
          id: 'h1',
          sourceLocationRefs: [
            { path: 'src/auth.ts', startLine: 1, endLine: 10 },
          ],
        },
      ],
    } as unknown as StageContext['memory'],
    adapters: {
      reporter: { provider: 'bounded_local' },
      synthesizer: undefined,
    } as unknown as StageContext['adapters'],
  });
  const result = await stage.run(ctx);

  assert.equal(result.metadata['isCliBacked'], true);
  const citedPaths = result.metadata['citedFilePaths'] as string[];
  assert.ok(citedPaths.includes('src/auth.ts'));
});

test('AssessmentReportingStage treats pi_cli as CLI-backed', async () => {
  const stage = new AssessmentReportingStage();
  const log: AppendedEvent[] = [];
  const ctx = stubContext(log, {
    memory: {
      hypotheses: [
        {
          id: 'h1',
          sourceLocationRefs: [
            { path: 'src/proxy.ts', startLine: 5, endLine: 15 },
          ],
        },
      ],
    } as unknown as StageContext['memory'],
    adapters: {
      reporter: { provider: 'pi_cli' },
      synthesizer: undefined,
    } as unknown as StageContext['adapters'],
  });
  const result = await stage.run(ctx);

  assert.equal(result.metadata['isCliBacked'], true);
  const citedPaths = result.metadata['citedFilePaths'] as string[];
  assert.ok(citedPaths.includes('src/proxy.ts'));
});

test('AssessmentReportingStage does not pass file paths for non-CLI adapters', async () => {
  const stage = new AssessmentReportingStage();
  const log: AppendedEvent[] = [];
  const ctx = stubContext(log, {
    memory: {
      hypotheses: [
        {
          id: 'h1',
          sourceLocationRefs: [{ path: 'src/handler.ts', startLine: 10 }],
        },
      ],
    } as unknown as StageContext['memory'],
    adapters: {
      reporter: undefined,
      synthesizer: { provider: 'anthropic' },
    } as unknown as StageContext['adapters'],
  });
  const result = await stage.run(ctx);

  assert.equal(result.metadata['isCliBacked'], false);
  assert.deepEqual(result.metadata['citedFilePaths'], []);
  assert.equal(log[0]?.payload['citedFilePaths'], undefined);
});
