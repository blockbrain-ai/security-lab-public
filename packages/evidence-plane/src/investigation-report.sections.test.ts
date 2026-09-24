/**
 * Rendering coverage for the optional investigation-report sections and their
 * fallback branches (entity inventory, probe families, assertion
 * classification, sequences, browser families, focused leads, lanes).
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  renderInvestigationReport,
  type InvestigationReportData,
  type VerificationLaneRecord,
} from './investigation-report.js';

function baseData(overrides: Partial<InvestigationReportData> = {}): InvestigationReportData {
  return {
    campaignId: 'campaign-sections',
    targetId: 'fixture',
    targetLabel: 'Fixture',
    targetKind: 'code',
    environment: 'sandbox',
    mode: 'declared',
    startedAt: '2026-04-11T00:00:00.000Z',
    completedAt: '2026-04-11T00:05:00.000Z',
    iterations: 2,
    totalCostUsd: 3.5,
    signalsFound: 2,
    signalsDormant: 1,
    signalsReactivated: 1,
    hypothesesTested: 4,
    chainHypothesesTested: 1,
    directHypothesesTested: 3,
    hypothesesConfirmed: 2,
    hypothesesRefuted: 1,
    maxChainLength: 2,
    chainLengthDistribution: { '1': 1, '2': 1 },
    findings: [],
    topSignals: [],
    refutedHypotheses: [],
    telemetrySummary: 'planner=1',
    ...overrides,
  };
}

function lane(overrides: Partial<VerificationLaneRecord> = {}): VerificationLaneRecord {
  return {
    attempted: 3,
    meaningfulAttempts: 2,
    confirmed: 1,
    refuted: 1,
    inconclusive: 1,
    blocked: 0,
    skipped: 0,
    authFailed: 0,
    notApplicable: 0,
    notAuthorized: 0,
    rateLimited: 0,
    autoStopped: 0,
    timeout: 0,
    runtimeError: 0,
    compileError: 0,
    costUsd: 0.25,
    durationMs: 61_000,
    status: 'complete',
    required: true,
    coverageGaps: [],
    ...overrides,
  };
}

test('renders every optional coverage section and lane detail', () => {
  const report = renderInvestigationReport(baseData({
    executionStatus: 'complete',
    runMode: 'serious-end-to-end',
    requiredCoverageSatisfied: true,
    meaningfulAttempts: 9,
    endToEndCostUsd: 4.25,
    endToEndDurationMs: 185_000,
    portfolioId: 'ultimate',
    plannerModel: 'openai/gpt-5.4',
    judgeModel: 'anthropic/claude-opus-4-6',
    judgePanelModels: ['openai/gpt-5.4'],
    synthesizerModel: 'anthropic/claude-opus-4-6',
    knowledgeBasePath: '/tmp/kb',
    priorKnowledgeUsed: true,
    assessmentParseStatus: 'parsed_json',
    coverageGaps: [
      { lane: 'hosted', code: 'optional_gap', message: 'Optional hosted probe skipped', severity: 'complete', required: false },
    ],
    targetCoverage: {
      coverage: 'manifest-only',
      supportedProbeKinds: [],
      detectedStack: { language: 'python', framework: 'flask', manifestFiles: ['requirements.txt'] },
    },
    liveConfirmation: {
      enabled: true,
      status: 'completed',
      targetId: 'fixture-live',
      confirmedFindings: 1,
      runDir: '/tmp/live',
      totalCostUsd: 0.5,
      durationMs: 90_000,
    },
    childCampaigns: [
      {
        lane: 'local-live',
        campaignId: 'child-1',
        status: 'completed',
        targetId: 'fixture-live',
        runDir: '/tmp/child-1',
        totalCostUsd: 0.75,
        durationMs: 120_000,
      },
    ],
    modelActivity: [{ role: 'plan', provider: 'openai', model: 'gpt-5.4', calls: 2, costUsd: 0.4 }],
    verificationLanes: {
      executionStatus: 'degraded',
      requiredCoverageSatisfied: false,
      meaningfulAttempts: 7,
      experimentsPath: '/tmp/experiments.jsonl',
      testSynthesis: lane({ status: 'degraded' }),
      monitoringStress: lane({
        confirmedRisk: 1,
        needsReview: 2,
        approvedDrift: 0,
        runs: 3,
        degraded: 1,
        harmfulSeen: 1,
        auditTrailPath: '/tmp/audit.jsonl',
        coverageGaps: ['legacy monitoring gap'],
        notes: ['legacy note'],
        rateLimited: 1,
        autoStopped: 1,
        timeout: 1,
        compileError: 1,
        runtimeError: 1,
      }),
      browser: lane({
        status: 'incomplete',
        browserExploitFamilies: {
          totalBrowserProbes: 2,
          byFamily: { xss: { probes: 2, variants: ['reflected'], confirmed: 1, refuted: 1, inconclusive: 0 } },
        },
      }),
      hosted: lane({
        status: 'blocked',
        sequenceExecution: {
          sequencesExecuted: 0,
          totalStepsExecuted: 0,
          sequencesConfirmed: 0,
          sequencesRefuted: 0,
          sequencesInconclusive: 0,
          differentialsExecuted: 2,
          differentialsWithEscalation: 1,
          statePassthroughCount: 0,
          rollbacksExecuted: 0,
        },
      }),
      supplyChain: lane({
        status: 'complete',
        adaptiveProbes: {
          hypothesis: { attempted: 1, confirmed: 1, refuted: 0, inconclusive: 0 },
          adaptive: { attempted: 1, confirmed: 0, refuted: 1, inconclusive: 0 },
          canary: { attempted: 1, matchedSafe: 1, matchedExploitable: 0 },
          surprisesDetected: 2,
          followupsGenerated: 1,
          midRoundHypothesesSynthesized: 1,
        },
        sequenceExecution: {
          sequencesExecuted: 2,
          totalStepsExecuted: 5,
          sequencesConfirmed: 1,
          sequencesRefuted: 1,
          sequencesInconclusive: 0,
          differentialsExecuted: 1,
          differentialsWithEscalation: 0,
          statePassthroughCount: 2,
          rollbacksExecuted: 1,
        },
        mythos: {
          enabled: true,
          invocations: 3,
          probesExecuted: 2,
          hypothesesProposed: 1,
          findingsProposed: 1,
          findingsRejected: 0,
          nonHypothesisProbes: 1,
          budgetExhausted: 'probe_budget_exhausted',
          sourceCorrelations: 2,
          sourceRefsCollected: 3,
        },
      }),
      coverageGaps: [
        { lane: 'hosted', code: 'missing_hosted_auth', message: 'No hosted credentials', severity: 'incomplete', required: true },
      ],
    },
    probeCoverageGaps: [
      { code: 'missing_canary', count: 2, probeIds: ['p1'] },
      { code: 'unmapped_reason_code', count: 1 },
    ],
    entityInventorySummary: {
      totalEntries: 4,
      byKind: { user: 2, org: 2 },
      byProvenance: { derived: 3, seeded: 1 },
      unresolvedParameters: ['userId'],
    },
    probeFamilyCoverage: {
      totalFamilyProbes: 3,
      byFamily: {
        authz: { probes: 2, variants: ['direct', 'indirect'] },
        empty: { probes: 1, variants: [] },
      },
    },
    assertionClassification: {
      totalClassified: 5,
      byReason: { matched_safe: 3, suppressed: 2 },
      byRouteKind: { http: 4, cli: 1 },
      suppressedCount: 2,
    },
    sequenceExecution: {
      sequencesExecuted: 1,
      totalStepsExecuted: 3,
      sequencesConfirmed: 1,
      sequencesRefuted: 0,
      sequencesInconclusive: 0,
      differentialsExecuted: 1,
      differentialsWithEscalation: 1,
      statePassthroughCount: 1,
      rollbacksExecuted: 1,
    },
    browserExploitFamilies: {
      totalBrowserProbes: 3,
      byFamily: { xss: { probes: 3, variants: ['reflected', 'stored'], confirmed: 2, refuted: 1, inconclusive: 0 } },
    },
    focusedLeadConfirmation: {
      sessionsRun: 1,
      confirmed: 1,
      refuted: 0,
      narrowed: 1,
      needsBrowser: 1,
      needsHumanSetup: 1,
      insufficientEvidence: 1,
      totalProbesExecuted: 4,
      leads: [
        { hypothesisId: 'ph-1', rank: 1, severity: 'high', probeFamily: 'authz', status: 'confirmed', totalProbes: 2 },
      ],
    },
    executiveAssessment: {
      overallVerdict: 'confirmed_vulnerabilities_present',
      confidence: 0.77,
      summary: 'Confirmed one boundary crossing.',
      confirmedVulnerabilities: [
        {
          title: 'Boundary crossing',
          severity: 'critical',
          description: 'A low-privilege identity reached another tenant.',
          evidenceRefs: ['finding-1'],
          requiredConditions: ['Requires two tenants', 'Requires a shared cache'],
          sourceLocationRefs: [{ path: 'src/api/routes.ts', startLine: 10, endLine: 20 }],
        },
      ],
      validatedRisks: [],
      configurationRisks: [],
      unconfirmedLeads: [],
      suppressedClaims: [],
      nextActions: ['Patch the route guard'],
      source: 'synthesized',
      reviewerModels: ['openai/gpt-5.4'],
      synthesizerModel: 'anthropic/claude-opus-4-6',
    },
  }));

  assert.match(report, /## Target Coverage/);
  assert.match(report, /Manifest files were detected but no dependencies could be parsed/);
  assert.match(report, /### Live Confirmation/);
  assert.match(report, /Run dir: \/tmp\/live/);
  assert.match(report, /### Child Campaigns/);
  assert.match(report, /### Activated Model Activity/);
  assert.match(report, /Monitoring stress \(legacy\)/);
  assert.match(report, /Rate limited: 1 \| Auto-stopped: 1/);
  assert.match(report, /Probe origins — hypothesis: 1/);
  assert.match(report, /Sequence execution — sequences: 2/);
  assert.match(report, /Mythos budget exhausted: probe_budget_exhausted/);
  assert.match(report, /Mythos source correlation — worker calls: 2/);
  assert.match(report, /Browser exploit families — total: 2/);
  assert.match(report, /## Probe-Level Coverage Gaps/);
  assert.match(report, /No remediation hint available\./);
  assert.match(report, /## Entity Inventory/);
  assert.match(report, /Unresolved parameters/);
  assert.match(report, /## Probe Family Coverage/);
  assert.match(report, /_none_/);
  assert.match(report, /## Assertion-Based Classification/);
  assert.match(report, /## Sequence & Identity-Differential Execution/);
  assert.match(report, /Privilege escalation detected: 1/);
  assert.match(report, /## Browser Exploit Family Coverage/);
  assert.match(report, /## Focused Lead Confirmation/);
  assert.match(report, /### Per-Lead Results/);
  assert.match(report, /## Confirmed Vulnerabilities/);
  assert.match(report, /Boundary crossing/);
  assert.match(report, /Requires two tenants; Requires a shared cache/);
  assert.match(report, /## Assessment Breakdown/);
  assert.match(report, /No validated architectural risks\./);
  assert.match(report, /No configuration-sensitive risks\./);
  assert.match(report, /No high-priority unconfirmed leads\./);
  assert.match(report, /No suppressed claims\./);
  assert.match(report, /Recommended Next Actions/);
});

test('renders target coverage variants and omits the section for full coverage', () => {
  const none = renderInvestigationReport(baseData({
    targetCoverage: { coverage: 'none', supportedProbeKinds: [] },
  }));
  assert.match(none, /\*\*Coverage: none\*\*/);
  assert.match(none, /No recognizable stack or manifest files were found/);

  const partial = renderInvestigationReport(baseData({
    targetCoverage: { coverage: 'partial', supportedProbeKinds: ['dependency_scan'] },
  }));
  assert.match(partial, /non-Node target/);
  assert.match(partial, /Supported probe kinds:/);

  const full = renderInvestigationReport(baseData({
    targetCoverage: { coverage: 'full', supportedProbeKinds: ['code_read'] },
  }));
  assert.doesNotMatch(full, /## Target Coverage/);
});

test('renders incomplete execution status without structured gaps', () => {
  const report = renderInvestigationReport(baseData({
    executionStatus: 'incomplete',
    coverageGaps: [],
  }));

  assert.match(report, /What's missing/);
  assert.match(report, /no structured coverage gaps were recorded/);
});

test('renders dormant lineage findings and reopened signals', () => {
  const report = renderInvestigationReport(baseData({
    signalsReactivated: 2,
    findings: [
      {
        severity: 'medium',
        description: 'Dormant clue became actionable\nwith a second line',
        reproductionSteps: ['read the log'],
        remediationSuggestion: 'rotate the secret',
        involvedDormantReactivation: true,
        confirmedAt: '2026-04-11T00:02:00.000Z',
      },
    ],
    topSignals: [
      { id: 'ws-2', surface: 'log', confidence: 0.4, status: 'reopened', description: 'Reopened clue' },
      { id: 'ws-3', surface: 'code', confidence: 0.6, status: 'active', description: 'Active clue' },
    ],
  }));

  assert.match(report, /### Findings From Reopened Signals/);
  assert.match(report, /### Reopened Signals Still Active/);
  assert.match(report, /Reopened clue/);
  // Runner-level findings (no executive assessment) render the full body.
  assert.match(report, /## Findings/);
  assert.match(report, /with a second line/);
  assert.match(report, /read the log/);
});

test('renders runner-level candidate findings downgraded by an executive assessment', () => {
  const report = renderInvestigationReport(baseData({
    findings: [
      {
        severity: 'low',
        description: 'Candidate finding not upheld',
        reproductionSteps: [],
        remediationSuggestion: 'review manually',
        involvedDormantReactivation: true,
        confirmedAt: '2026-04-11T00:02:00.000Z',
      },
    ],
    executiveAssessment: {
      overallVerdict: 'no_material_findings',
      confidence: 0.5,
      summary: 'Nothing upheld.',
      confirmedVulnerabilities: [],
      validatedRisks: [],
      configurationRisks: [],
      unconfirmedLeads: [],
      suppressedClaims: [],
      nextActions: [],
      source: 'fallback',
      reviewerModels: [],
    },
  }));

  assert.match(report, /No campaign-level confirmed vulnerabilities\./);
  assert.match(report, /Runner-Level Candidate Findings \(Not Upheld By Final Assessment\)/);
  assert.match(report, /Candidate finding not upheld/);
  assert.match(report, /involved dormant reactivation/);
  assert.doesNotMatch(report, /## Assessment Breakdown[\s\S]*Recommended Next Actions/);
});

test('renders the no-assessment findings and empty-section fallbacks', () => {
  const noAssessmentNoFindings = renderInvestigationReport(baseData({ signalsReactivated: 0 }));
  assert.match(noAssessmentNoFindings, /No confirmed vulnerabilities were produced by this run/);
  assert.match(noAssessmentNoFindings, /No active signals\./);
  assert.match(noAssessmentNoFindings, /No refuted hypotheses\./);
  assert.match(noAssessmentNoFindings, /No dormant signals were reactivated/);
  assert.match(noAssessmentNoFindings, /## Findings\n\nNo confirmed findings\./);

  const findingsOnly = renderInvestigationReport(baseData({
    findings: [
      {
        severity: 'unknown-severity',
        description: 'Unknown severity finding',
        reproductionSteps: [],
        remediationSuggestion: 'none',
        involvedDormantReactivation: false,
        confirmedAt: '2026-04-11T00:02:00.000Z',
      },
    ],
  }));
  assert.match(findingsOnly, /The run produced confirmed findings/);
  assert.match(findingsOnly, /\[UNKNOWN-SEVERITY\] Unknown severity finding/);

  const unmappedVerdict = renderInvestigationReport(baseData({
    executiveAssessment: {
      overallVerdict: 'an_unmapped_verdict',
      confidence: 0.1,
      summary: 'Unmapped.',
      confirmedVulnerabilities: [],
      validatedRisks: [],
      configurationRisks: [],
      unconfirmedLeads: [],
      suppressedClaims: [],
      nextActions: [],
      source: 'fallback',
      reviewerModels: [],
    },
  }));
  assert.match(unmappedVerdict, /Outcome: an_unmapped_verdict/);
});

test('omits optional sections when their summaries are absent or empty', () => {
  const report = renderInvestigationReport(baseData({
    executionStatus: 'degraded',
    coverageGaps: [
      { lane: 'local-live', code: 'gap', message: 'Required gap', severity: 'degraded', required: true },
    ],
    verificationLanes: undefined,
    entityInventorySummary: { totalEntries: 0, byKind: {}, byProvenance: {}, unresolvedParameters: [] },
    probeFamilyCoverage: { totalFamilyProbes: 0, byFamily: {} },
    assertionClassification: { totalClassified: 0, byReason: {}, byRouteKind: {}, suppressedCount: 0 },
    sequenceExecution: {
      sequencesExecuted: 0,
      totalStepsExecuted: 0,
      sequencesConfirmed: 0,
      sequencesRefuted: 0,
      sequencesInconclusive: 0,
      differentialsExecuted: 0,
      differentialsWithEscalation: 0,
      statePassthroughCount: 0,
      rollbacksExecuted: 0,
    },
    browserExploitFamilies: { totalBrowserProbes: 0, byFamily: {} },
    focusedLeadConfirmation: {
      sessionsRun: 0,
      confirmed: 0,
      refuted: 0,
      narrowed: 0,
      needsBrowser: 0,
      needsHumanSetup: 0,
      insufficientEvidence: 0,
      totalProbesExecuted: 0,
      leads: [],
    },
  }));

  assert.doesNotMatch(report, /## Verification Lanes/);
  assert.doesNotMatch(report, /## Entity Inventory/);
  assert.doesNotMatch(report, /## Probe Family Coverage/);
  assert.doesNotMatch(report, /## Assertion-Based Classification/);
  assert.doesNotMatch(report, /## Sequence & Identity-Differential Execution/);
  assert.doesNotMatch(report, /## Browser Exploit Family Coverage/);
  assert.doesNotMatch(report, /## Focused Lead Confirmation/);
  assert.match(report, /local-live \(required\)/);
});
