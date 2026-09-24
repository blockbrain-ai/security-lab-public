/**
 * Section 7.1 — end-to-end integration test for source provenance.
 *
 * Proves that a source ref produced by the SourceCorrelationWorker flows
 * through the full pipeline:
 *   SourceCorrelationWorker → hypothesis.sourceLocationRefs →
 *   finding.sourceLocationRefs → FocusedClosureStage (citation rule) →
 *   report rendering (Cited source section)
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  SourceCorrelationWorker,
  SourceCorrelationBudget,
} from '../verification/local-live/source-correlation-worker.js';
import type { ModelAdapter, ModelResponse, InvokeOptions } from '../providers/contracts.js';
import type { LiveExecutionResult } from '../verification/local-live/contracts.js';
import type { ChainHypothesis, ChainFinding } from '../autonomous/contracts.js';
import {
  applyEvidenceRefCitationRule,
  hypothesisForClosureFromChain,
} from '../autonomous/stages/focused-closure.js';
import {
  renderInvestigationReport,
  type InvestigationReportData,
} from '../../../evidence-plane/src/investigation-report.js';
// SourceLocationRef is used transitively via ChainHypothesis.sourceLocationRefs

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

class StubAdapter implements ModelAdapter {
  readonly provider = 'test';
  readonly model = 'stub';

  constructor(private readonly response: string) {}

  async invoke<T = unknown>(_options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    return {
      content: this.response,
      usage: { inputTokens: 0, outputTokens: 0, costUsd: 0 },
      durationMs: 0,
      provider: this.provider,
      model: this.model,
    };
  }
}

function buildProbeResult(): LiveExecutionResult {
  return {
    probeId: 'p-e2e',
    findingId: 'f-e2e',
    identityId: 'anonymous',
    origin: 'hypothesis',
    request: { method: 'GET', url: 'http://localhost/api/approvals/1', headers: {} },
    response: { status: 500, headers: {}, body: 'SQL error', durationMs: 12 },
    rollbackExecuted: false,
    verdict: 'confirmed',
    reasoning: 'SQL traceback leaked',
  };
}

// ---------------------------------------------------------------------------
// Integration test
// ---------------------------------------------------------------------------

test('Section 7.1 — end-to-end: source ref flows from SourceCorrelationWorker through hypothesis → finding → focused closure → report', async () => {
  // ------- Step 1: SourceCorrelationWorker produces typed sourceLocationRefs -------
  const adapter = new StubAdapter(
    '```json\n' +
    JSON.stringify({
      sourceRefs: ['src/api/routes/approvals.ts:42-58', 'src/db/queries.ts:10'],
      analysis: 'The handler interpolates tenant input into raw SQL.',
      consistencyVerdict: 'consistent',
      consistencyReasoning: 'The 500 error is consistent with a SQL syntax failure.',
    }) +
    '\n```',
  );
  const worker = new SourceCorrelationWorker(adapter, new SourceCorrelationBudget(10));
  const correlation = await worker.correlate({
    probeResult: buildProbeResult(),
    repoRoot: '/home/user/project',
    hypothesis: 'SQL injection in approval handler',
    findingId: 'f-e2e',
  });

  // Verify the worker produced typed refs
  assert.equal(correlation.sourceLocationRefs.length, 2);
  assert.equal(correlation.sourceLocationRefs[0]!.path, 'src/api/routes/approvals.ts');
  assert.equal(correlation.sourceLocationRefs[0]!.startLine, 42);
  assert.equal(correlation.sourceLocationRefs[0]!.endLine, 58);

  // ------- Step 2: Thread refs into hypothesis -------
  const hypothesis: ChainHypothesis = {
    id: 'ph-e2e-1',
    synthesizedAt: new Date().toISOString(),
    iteration: 1,
    description: 'SQL injection in approval handler allows cross-tenant data access',
    severity: 'critical',
    signalIds: ['ws-1', 'ws-2'],
    prerequisites: [],
    status: 'confirmed',
    attempts: [
      {
        at: new Date().toISOString(),
        iteration: 1,
        probeIds: ['p-e2e'],
        observation: 'SQL traceback leaked',
        verdict: 'confirmed',
        reasoning: 'Confirmed SQL injection.',
      },
    ],
    // This is the key — thread sourceLocationRefs from the worker into the hypothesis
    sourceLocationRefs: correlation.sourceLocationRefs,
  };

  // ------- Step 3: Propagate refs to finding -------
  const finding: ChainFinding = {
    confirmedAt: new Date().toISOString(),
    iteration: 1,
    description: hypothesis.description,
    severity: 'critical',
    reproductionSteps: ['Send crafted tenant input to /api/approvals/1'],
    remediationSuggestion: 'Use parameterized queries instead of string interpolation.',
    involvedDormantReactivation: false,
    // Propagate from hypothesis (as the runner does)
    sourceLocationRefs: hypothesis.sourceLocationRefs,
  };
  hypothesis.finding = finding;

  // ------- Step 4: Focused closure validates the hypothesis -------
  const closureInput = hypothesisForClosureFromChain(hypothesis);
  assert.ok(closureInput.sourceLocationRefs);
  assert.equal(closureInput.sourceLocationRefs!.length, 2);

  const { focusedList, unconfirmedLeads } = applyEvidenceRefCitationRule({
    hypotheses: [closureInput],
  });
  assert.equal(focusedList.length, 1);
  assert.equal(unconfirmedLeads.length, 0);

  // Also verify that a hypothesis WITHOUT source/probe/event refs would be rejected
  const bareHypothesis: ChainHypothesis = {
    ...hypothesis,
    id: 'ph-bare',
    signalIds: [],
    sourceLocationRefs: undefined,
    attempts: [],
  };
  const bareResult = applyEvidenceRefCitationRule({
    hypotheses: [hypothesisForClosureFromChain(bareHypothesis)],
  });
  assert.equal(bareResult.focusedList.length, 0);
  assert.equal(bareResult.unconfirmedLeads.length, 1);

  // ------- Step 5: Report renders the Cited source section -------
  const reportData: InvestigationReportData = {
    campaignId: 'camp-e2e-provenance',
    targetId: 'fixture-target',
    targetLabel: 'Fixture Target',
    targetKind: 'webapp',
    environment: 'fixture',
    mode: 'declared',
    startedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    iterations: 1,
    totalCostUsd: 0.10,
    signalsFound: 2,
    signalsDormant: 0,
    signalsReactivated: 0,
    hypothesesTested: 1,
    chainHypothesesTested: 1,
    directHypothesesTested: 0,
    hypothesesConfirmed: 1,
    hypothesesRefuted: 0,
    maxChainLength: 2,
    chainLengthDistribution: { '2': 1 },
    findings: [
      {
        severity: finding.severity,
        description: finding.description,
        reproductionSteps: finding.reproductionSteps,
        remediationSuggestion: finding.remediationSuggestion,
        involvedDormantReactivation: finding.involvedDormantReactivation,
        confirmedAt: finding.confirmedAt,
        sourceLocationRefs: finding.sourceLocationRefs,
      },
    ],
    topSignals: [],
    refutedHypotheses: [],
    telemetrySummary: 'cost=$0.10',
  };

  const markdown = renderInvestigationReport(reportData);

  // Verify the report contains the Cited source section with the exact refs
  assert.match(markdown, /\*\*Cited source:\*\*/);
  assert.match(markdown, /`src\/api\/routes\/approvals\.ts:42-58`/);
  assert.match(markdown, /`src\/db\/queries\.ts:10`/);

  // Verify the finding itself is rendered
  assert.match(markdown, /\[CRITICAL\]/);
  assert.match(markdown, /SQL injection in approval handler/);
  assert.match(markdown, /Use parameterized queries/);
});
