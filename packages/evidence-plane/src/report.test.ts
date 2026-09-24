import test from 'node:test';
import assert from 'node:assert/strict';
import { renderConsoleSummary, renderMarkdownReport } from './report.js';
import { renderInvestigationReport } from './investigation-report.js';
import type { InvestigationReportData } from './investigation-report.js';
import type { RunSummary } from './contracts.js';

function lane(overrides: Partial<NonNullable<InvestigationReportData['verificationLanes']>['testSynthesis']> = {}) {
  return {
    attempted: 0,
    meaningfulAttempts: 0,
    confirmed: 0,
    refuted: 0,
    inconclusive: 0,
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
    costUsd: 0,
    durationMs: 0,
    status: 'complete' as const,
    required: false,
    coverageGaps: [],
    ...overrides,
  };
}

test('renderMarkdownReport and renderConsoleSummary include scenario outcomes and captures', () => {
  const summary: RunSummary = {
    runId: 'run-1',
    runfileId: 'fixture-pack',
    runfileName: 'Fixture Pack',
    mode: 'declared',
    startedAt: '2026-04-10T00:00:00.000Z',
    completedAt: '2026-04-10T00:01:00.000Z',
    scenarioCount: 1,
    passed: 1,
    failed: 0,
    targetEnvironments: ['sandbox'],
    orchestration: {
      planner: 'claude',
      executor: 'native',
      judge: 'gpt',
      reporter: 'markdown',
    },
    records: [
      {
        scenarioId: 'sc-1',
        title: 'Authz drift',
        targetId: 'fixture',
        severity: 'high',
        passed: true,
        scores: {
          attempt: 'yes',
          block: 'full',
          outcome: 'contained',
          stealth: 'low',
        },
        residualRisk: null,
        steps: [
          {
            scenarioId: 'sc-1',
            scenarioTitle: 'Authz drift',
            stepId: 'step-1',
            stepTitle: 'GET /private',
            targetId: 'fixture',
            severity: 'high',
            observation: {
              kind: 'http_request',
              statusCode: 403,
              durationMs: 10,
            },
            verdict: {
              observedSafetyState: 'blocked',
              expectationMet: true,
              replayable: true,
              residualRisk: null,
              blockSource: 'target',
            },
            captures: {
              userId: 'anon',
            },
          },
        ],
      },
    ],
  };

  const markdown = renderMarkdownReport(summary);
  const consoleLines = renderConsoleSummary(summary).join('\n');

  assert.match(markdown, /Security Lab Report/i);
  assert.match(markdown, /Captures: userId=anon/i);
  assert.match(consoleLines, /sc-1: PASS/i);
});

test('renderMarkdownReport includes residual risk, block source, and shell exit details', () => {
  const summary: RunSummary = {
    runId: 'run-2',
    runfileId: 'failure-pack',
    runfileName: 'Failure Pack',
    mode: 'declared',
    startedAt: '2026-04-10T00:00:00.000Z',
    completedAt: '2026-04-10T00:01:00.000Z',
    scenarioCount: 1,
    passed: 0,
    failed: 1,
    targetEnvironments: ['sandbox', 'staging'],
    orchestration: {
      planner: 'gpt-5.4',
      executor: 'native',
      judge: 'opus',
      reporter: 'markdown',
    },
    records: [
      {
        scenarioId: 'sc-2',
        title: 'Persistence foothold',
        targetId: 'fixture',
        severity: 'critical',
        passed: false,
        scores: {
          attempt: 'yes',
          block: 'partial',
          outcome: 'unexpected',
          stealth: 'medium',
        },
        residualRisk: 'A startup foothold may survive restart.',
        steps: [
          {
            scenarioId: 'sc-2',
            scenarioTitle: 'Persistence foothold',
            stepId: 'step-1',
            stepTitle: 'Inspect launchd',
            targetId: 'fixture',
            severity: 'critical',
            observation: {
              kind: 'shell',
              exitCode: 1,
              stderr: 'launchd entry present',
              durationMs: 12,
            },
            verdict: {
              observedSafetyState: 'error',
              expectationMet: false,
              replayable: true,
              residualRisk: 'Persistence foothold still reachable.',
              blockSource: 'runtime',
            },
            captures: {},
          },
        ],
      },
    ],
  };

  const markdown = renderMarkdownReport(summary);
  const consoleLines = renderConsoleSummary(summary).join('\n');

  assert.match(markdown, /Residual risk: A startup foothold may survive restart\./);
  assert.match(markdown, /Block source: runtime/);
  assert.match(markdown, /Exit code: 1/);
  assert.match(consoleLines, /sc-2: FAIL/i);
});

test('renderInvestigationReport includes findings, dormant reactivation, and telemetry', () => {
  const report: InvestigationReportData = {
    campaignId: 'campaign-1',
    targetId: 'fixture-local',
    targetLabel: 'Fixture Local',
    targetKind: 'http',
    environment: 'sandbox',
    mode: 'blind',
    startedAt: '2026-04-10T00:00:00.000Z',
    completedAt: '2026-04-10T00:05:00.000Z',
    iterations: 6,
    totalCostUsd: 1.23,
    signalsFound: 4,
    signalsDormant: 1,
    signalsReactivated: 1,
    hypothesesTested: 2,
    chainHypothesesTested: 1,
    directHypothesesTested: 1,
    hypothesesConfirmed: 1,
    hypothesesRefuted: 1,
    maxChainLength: 3,
    chainLengthDistribution: { '3': 1 },
    findings: [
      {
        severity: 'critical',
        description: 'Prompt-smuggle plus proof-leak chain crossed a trust boundary.',
        reproductionSteps: ['Seed prompt-smuggle clue', 'Reopen dormant signal', 'Read leaked proof artifact'],
        remediationSuggestion: 'Tighten proof export boundaries and sanitize business data.',
        involvedDormantReactivation: true,
        confirmedAt: '2026-04-10T00:04:00.000Z',
      },
    ],
    topSignals: [
      {
        id: 'ws-1',
        surface: 'prompt',
        confidence: 0.9,
        status: 'reopened',
        description: 'Dormant business-data clue became actionable later.',
      },
    ],
    refutedHypotheses: ['A weaker lockfile-only chain did not cross a boundary.'],
    telemetrySummary: 'planner=1 judge=1 cost=$1.23',
  };

  const markdown = renderInvestigationReport(report);
  assert.match(markdown, /\[CRITICAL\]/);
  assert.match(markdown, /involved dormant reactivation/i);
  assert.match(markdown, /What Was Tried And Failed/i);
  assert.match(markdown, /Longest composed chain \| 3/);
  assert.match(markdown, /Chain length distribution \| 3:1/);
  assert.match(markdown, /planner=1 judge=1 cost=\$1.23/i);
});

test('renderInvestigationReport includes portfolio metadata and empty-state branches', () => {
  const report: InvestigationReportData = {
    campaignId: 'campaign-2',
    targetId: 'fixture-static',
    targetLabel: 'Fixture Static',
    targetKind: 'code',
    environment: 'sandbox',
    mode: 'declared',
    startedAt: '2026-04-10T00:00:00.000Z',
    completedAt: '2026-04-10T00:02:00.000Z',
    iterations: 2,
    totalCostUsd: 0.42,
    signalsFound: 0,
    signalsDormant: 0,
    signalsReactivated: 0,
    hypothesesTested: 0,
    chainHypothesesTested: 0,
    directHypothesesTested: 0,
    hypothesesConfirmed: 0,
    hypothesesRefuted: 0,
    maxChainLength: 0,
    chainLengthDistribution: {},
    findings: [],
    topSignals: [],
    refutedHypotheses: [],
    telemetrySummary: 'planner=2 judge=0 cost=$0.42',
    portfolioId: 'ultimate',
    plannerModel: 'openai/gpt-5.4',
    judgeModel: 'openai/gpt-5.4',
    judgePanelModels: ['openai/gpt-5.4', 'anthropic/claude-opus-4-6', 'gemini/gemini-3.1-pro-preview'],
    synthesizerModel: 'anthropic/claude-opus-4-6',
    knowledgeBasePath: '/tmp/kb.json',
    priorKnowledgeUsed: true,
    liveConfirmation: {
      enabled: true,
      status: 'completed',
      targetId: 'fixture-local',
      confirmedFindings: 1,
      runDir: '/tmp/live-run',
      sourceCampaignId: 'campaign-2',
    },
  };

  const markdown = renderInvestigationReport(report);
  assert.match(markdown, /Portfolio: ultimate/);
  assert.match(markdown, /Judge panel: openai\/gpt-5\.4, anthropic\/claude-opus-4-6, gemini\/gemini-3\.1-pro/);
  assert.match(markdown, /Live Confirmation/);
  assert.match(markdown, /No confirmed findings\./);
  assert.match(markdown, /No active signals\./);
  assert.match(markdown, /No dormant signals were reactivated during this campaign\./);
});

test('renderInvestigationReport renders executive assessment, model activity, and downgraded runner findings', () => {
  const report: InvestigationReportData = {
    campaignId: 'campaign-3',
    targetId: 'fixture-static',
    targetLabel: 'Fixture Static',
    targetKind: 'code',
    environment: 'sandbox',
    mode: 'declared',
    startedAt: '2026-04-10T00:00:00.000Z',
    completedAt: '2026-04-10T00:03:00.000Z',
    iterations: 4,
    totalCostUsd: 2.12,
    signalsFound: 6,
    signalsDormant: 2,
    signalsReactivated: 1,
    hypothesesTested: 3,
    chainHypothesesTested: 2,
    directHypothesesTested: 1,
    hypothesesConfirmed: 1,
    hypothesesRefuted: 2,
    maxChainLength: 4,
    chainLengthDistribution: { '2': 1, '4': 1 },
    findings: [
      {
        severity: 'high',
        description: 'Runner believed a header-only tenant path was exploitable.',
        reproductionSteps: ['Read auth middleware', 'Trace header flow'],
        remediationSuggestion: 'Bind org headers to authenticated identity.',
        involvedDormantReactivation: false,
        confirmedAt: '2026-04-10T00:02:30.000Z',
      },
    ],
    topSignals: [
      {
        id: 'ws-10',
        surface: 'code',
        confidence: 0.82,
        status: 'active',
        description: 'JWT appears optional when BOS_JWT_SECRET is unset.',
        relatedAssets: ['src/api/server.ts'],
      },
    ],
    refutedHypotheses: ['Header-only path was not live-confirmed.'],
    telemetrySummary: 'planner=2 judge=3 reporter=1 cost=$2.12',
    portfolioId: 'production',
    plannerModel: 'anthropic/claude-sonnet-4-6',
    judgeModel: 'anthropic/claude-sonnet-4-6',
    judgePanelModels: ['openai/gpt-5.4', 'anthropic/claude-opus-4-6'],
    synthesizerModel: 'anthropic/claude-opus-4-6',
    priorKnowledgeUsed: true,
    modelActivity: [
      { role: 'plan', provider: 'anthropic', model: 'claude-sonnet-4-6', calls: 2, costUsd: 0.5 },
      { role: 'reporter', provider: 'anthropic', model: 'claude-opus-4-6', calls: 1, costUsd: 0.7 },
    ],
    executiveAssessment: {
      overallVerdict: 'validated_architectural_risks_only',
      confidence: 0.89,
      summary: 'The run surfaced architectural risk, but the candidate exploit was not upheld as a confirmed vulnerability.',
      confirmedVulnerabilities: [],
      validatedRisks: [
        {
          title: 'Optional JWT configuration',
          severity: 'high',
          description: 'Auth becomes opt-in when BOS_JWT_SECRET is unset.',
          evidenceRefs: ['ws-10'],
          requiredConditions: ['Applies when BOS_JWT_SECRET is unset.'],
        },
      ],
      configurationRisks: [
        {
          title: 'Header-only org flow in degraded mode',
          severity: 'medium',
          description: 'The org header path requires stronger identity binding in degraded auth mode.',
          evidenceRefs: ['ws-10'],
          requiredConditions: ['Requires degraded auth configuration.'],
        },
      ],
      unconfirmedLeads: [
        {
          title: 'Tenant impersonation chain',
          severity: 'high',
          description: 'Static chain needs live confirmation before reporting.',
          evidenceRefs: ['ws-10'],
          requiredConditions: ['Requires live confirmation.'],
        },
      ],
      suppressedClaims: [
        {
          claim: 'Header-only tenant impersonation is confirmed.',
          reason: 'Static evidence did not prove runtime exploitability.',
          evidenceRefs: ['ws-10'],
        },
      ],
      nextActions: ['Run a bounded live confirmation pass against a local target instance.'],
      source: 'synthesized',
      reviewerModels: ['openai/gpt-5.4', 'anthropic/claude-opus-4-6'],
      synthesizerModel: 'anthropic/claude-opus-4-6',
    },
  };

  const markdown = renderInvestigationReport(report);

  assert.match(markdown, /Executive verdict \| validated architectural or configuration risks only/i);
  assert.match(markdown, /Campaign-level confirmed vulnerabilities \| 0/i);
  assert.match(markdown, /Assessment source: synthesized/i);
  assert.match(markdown, /Activated Model Activity/i);
  assert.match(markdown, /No campaign-level confirmed vulnerabilities\./);
  assert.match(markdown, /Runner-Level Candidate Findings \(Not Upheld By Final Assessment\)/i);
  assert.match(markdown, /Validated Architectural Risks/i);
  assert.match(markdown, /Configuration-Sensitive Risks/i);
  assert.match(markdown, /High-Priority Unconfirmed Leads/i);
  assert.match(markdown, /Suppressed Or Overstated Claims/i);
  assert.match(markdown, /Recommended Next Actions/i);
  assert.match(markdown, /assets=src\/api\/server\.ts/i);
});

test('renderInvestigationReport renders campaign-level confirmed vulnerabilities from executive assessment', () => {
  const report: InvestigationReportData = {
    campaignId: 'campaign-4',
    targetId: 'fixture-local',
    targetLabel: 'Fixture Local',
    targetKind: 'http',
    environment: 'staging',
    mode: 'declared',
    startedAt: '2026-04-10T00:00:00.000Z',
    completedAt: '2026-04-10T00:04:00.000Z',
    iterations: 3,
    totalCostUsd: 4.2,
    signalsFound: 5,
    signalsDormant: 0,
    signalsReactivated: 0,
    hypothesesTested: 2,
    chainHypothesesTested: 2,
    directHypothesesTested: 0,
    hypothesesConfirmed: 1,
    hypothesesRefuted: 1,
    maxChainLength: 5,
    chainLengthDistribution: { '5': 1 },
    findings: [],
    topSignals: [],
    refutedHypotheses: [],
    telemetrySummary: 'planner=1 judge=2 reporter=2 cost=$4.20',
    executiveAssessment: {
      overallVerdict: 'confirmed_vulnerabilities_present',
      confidence: 0.96,
      summary: 'A confirmed vulnerability was reproduced and upheld by the campaign-level synthesis.',
      confirmedVulnerabilities: [
        {
          title: 'Unauthenticated proof export leak',
          severity: 'critical',
          description: 'The proof export route leaked sensitive data without auth in staging.',
          evidenceRefs: ['finding-1', 'ws-4'],
          requiredConditions: ['Confirmed against staging target.'],
        },
      ],
      validatedRisks: [],
      configurationRisks: [],
      unconfirmedLeads: [],
      suppressedClaims: [],
      nextActions: ['Patch the export route and rerun the regression pack.'],
      source: 'review_panel',
      reviewerModels: ['openai/gpt-5.4', 'anthropic/claude-opus-4-6'],
      synthesizerModel: null,
    },
  };

  const markdown = renderInvestigationReport(report);

  assert.match(markdown, /## Confirmed Vulnerabilities/);
  assert.match(markdown, /\[CRITICAL\] Unauthenticated proof export leak/);
  assert.match(markdown, /\*\*Evidence refs:\*\* finding-1, ws-4/);
  assert.match(markdown, /\*\*Conditions:\*\* Confirmed against staging target\./);
  assert.doesNotMatch(markdown, /Runner-Level Candidate Findings/);
});

test('renderInvestigationReport renders verification lanes, confirmed vulnerabilities, and suppressed claims', () => {
  const report: InvestigationReportData = {
    campaignId: 'campaign-verified',
    targetId: 'bos-hosted',
    targetLabel: 'Fixture Hosted',
    targetKind: 'hosted',
    environment: 'hosted_authorized',
    mode: 'blind',
    startedAt: '2026-04-10T00:00:00.000Z',
    completedAt: '2026-04-10T00:10:00.000Z',
    iterations: 4,
    totalCostUsd: 4.5,
    signalsFound: 8,
    signalsDormant: 2,
    signalsReactivated: 1,
    hypothesesTested: 5,
    chainHypothesesTested: 4,
    directHypothesesTested: 1,
    hypothesesConfirmed: 1,
    hypothesesRefuted: 4,
    maxChainLength: 4,
    chainLengthDistribution: { '3': 2, '4': 1 },
    findings: [],
    topSignals: [],
    refutedHypotheses: [],
    telemetrySummary: 'planner=2 panel=3 synth=1 cost=$4.5',
    portfolioId: 'production',
    plannerModel: 'anthropic/claude-sonnet-4-6',
    judgePanelModels: ['openai/gpt-5.4', 'anthropic/claude-opus-4-6'],
    synthesizerModel: 'anthropic/claude-opus-4-6',
    priorKnowledgeUsed: true,
    knowledgeBasePath: '/tmp/knowledge-base.json',
    liveConfirmation: {
      enabled: true,
      status: 'completed',
      targetId: 'fixture-staging',
      confirmedFindings: 1,
      runDir: '/tmp/live-confirmation',
      sourceCampaignId: 'campaign-source',
    },
    verificationLanes: {
      testSynthesis: lane({ attempted: 3, meaningfulAttempts: 3, confirmed: 1, refuted: 1, inconclusive: 1 }),
      // Section 8.2: monitoring stress data is now part of localLive
      localLive: lane({ attempted: 4, meaningfulAttempts: 3, confirmed: 1, refuted: 2, rateLimited: 1, runs: 3, degraded: 1, harmfulSeen: 1 }),
      hosted: lane({ attempted: 2, meaningfulAttempts: 2, confirmed: 1, refuted: 1, auditTrailPath: '/tmp/audit.jsonl' }),
      supplyChain: lane({ attempted: 2, meaningfulAttempts: 2, confirmedRisk: 1, needsReview: 0, approvedDrift: 1 }),
      experimentsPath: '/tmp/experiments.jsonl',
    },
    modelActivity: [
      { role: 'planner', provider: 'anthropic', model: 'claude-sonnet-4-6', calls: 2, costUsd: 0.4 },
      { role: 'synthesizer', provider: 'anthropic', model: 'claude-opus-4-6', calls: 1, costUsd: 1.2 },
    ],
    executiveAssessment: {
      overallVerdict: 'confirmed_vulnerabilities_present',
      confidence: 0.91,
      summary: 'Hosted verification confirmed a real boundary crossing.',
      confirmedVulnerabilities: [
        {
          title: 'Boundary crossing via canary identity',
          severity: 'critical',
          description: 'A low-privilege identity reached another tenant resource.',
          evidenceRefs: ['exp-1', 'audit-2'],
          requiredConditions: ['staging canary identities present'],
        },
      ],
      validatedRisks: [
        {
          title: 'Weak trust boundary',
          severity: 'medium',
          description: 'The auth architecture remains brittle.',
          evidenceRefs: [],
          requiredConditions: [],
        },
      ],
      configurationRisks: [],
      unconfirmedLeads: [],
      suppressedClaims: [
        {
          claim: 'All unauthenticated routes are exploitable',
          reason: 'Static evidence did not confirm exposure.',
          evidenceRefs: ['signal-1'],
        },
      ],
      nextActions: ['Patch the route guard', 'Replay the hosted regression pack'],
      source: 'campaign_assessment_panel',
      reviewerModels: ['openai/gpt-5.4', 'anthropic/claude-opus-4-6'],
      synthesizerModel: 'anthropic/claude-opus-4-6',
    },
  };

  const markdown = renderInvestigationReport(report);
  assert.match(markdown, /## Verification Lanes/);
  assert.match(markdown, /Audit trail: \/tmp\/audit\.jsonl/);
  assert.match(markdown, /Verification experiments: \/tmp\/experiments\.jsonl/);
  assert.match(markdown, /## Confirmed Vulnerabilities/);
  assert.match(markdown, /Boundary crossing via canary identity/);
  assert.match(markdown, /### Suppressed Or Overstated Claims/);
  assert.match(markdown, /Replay the hosted regression pack/);
});

test('renderInvestigationReport uses a provisional verdict label when execution is incomplete', () => {
  const markdown = renderInvestigationReport({
    campaignId: 'campaign-incomplete',
    targetId: 'fixture-static',
    targetLabel: 'Fixture Static',
    targetKind: 'code',
    environment: 'sandbox',
    mode: 'declared',
    startedAt: '2026-04-10T00:00:00.000Z',
    completedAt: '2026-04-10T00:02:00.000Z',
    iterations: 0,
    totalCostUsd: 0.2,
    signalsFound: 0,
    signalsDormant: 0,
    signalsReactivated: 0,
    hypothesesTested: 0,
    chainHypothesesTested: 0,
    directHypothesesTested: 0,
    hypothesesConfirmed: 0,
    hypothesesRefuted: 0,
    maxChainLength: 0,
    chainLengthDistribution: {},
    findings: [],
    topSignals: [],
    refutedHypotheses: [],
    telemetrySummary: 'planner=0',
    executionStatus: 'incomplete',
    requiredCoverageSatisfied: false,
    coverageGaps: [
      {
        lane: 'local-live',
        code: 'missing_identities',
        message: 'Missing required local-live identities.',
        severity: 'incomplete',
      },
    ],
    executiveAssessment: {
      overallVerdict: 'no_material_findings',
      confidence: 0.55,
      summary: 'No confirmed vulnerabilities were established.',
      confirmedVulnerabilities: [],
      validatedRisks: [],
      configurationRisks: [],
      unconfirmedLeads: [],
      suppressedClaims: [],
      nextActions: ['Provide the canary identities and rerun.'],
      source: 'review_panel',
      reviewerModels: ['openai/gpt-5.4'],
      synthesizerModel: null,
      parseStatus: 'parsed_json',
    },
  });

  assert.match(markdown, /Outcome: provisional — execution incomplete or degraded/);
  assert.match(markdown, /Execution gaps prevented a fully closed verification result/);
});

test('renderInvestigationReport renders detailed verification gaps, child campaigns, and lane notes', () => {
  const markdown = renderInvestigationReport({
    campaignId: 'campaign-detailed',
    targetId: 'bos-end-to-end',
    targetLabel: 'Fixture End To End',
    targetKind: 'hosted',
    environment: 'hosted_authorized',
    mode: 'blind',
    startedAt: '2026-04-10T00:00:00.000Z',
    completedAt: '2026-04-10T00:20:00.000Z',
    iterations: 5,
    totalCostUsd: 3.5,
    signalsFound: 2,
    signalsDormant: 0,
    signalsReactivated: 0,
    hypothesesTested: 1,
    chainHypothesesTested: 1,
    directHypothesesTested: 0,
    hypothesesConfirmed: 0,
    hypothesesRefuted: 1,
    maxChainLength: 2,
    chainLengthDistribution: { '2': 1 },
    findings: [],
    topSignals: [],
    refutedHypotheses: ['Guard implementation was not fully read before verification closed.'],
    telemetrySummary: 'planner=1 reporter=1 cost=$3.50',
    executionStatus: 'degraded',
    requiredCoverageSatisfied: false,
    meaningfulAttempts: 4,
    endToEndCostUsd: 6.75,
    endToEndDurationMs: 180000,
    assessmentParseStatus: 'fallback_panel:summary_conflict',
    coverageGaps: [
      {
        lane: 'hosted',
        code: 'missing_identity',
        message: 'Hosted user_b_low token was not configured.',
        severity: 'degraded',
        required: true,
      },
    ],
    liveConfirmation: {
      enabled: true,
      status: 'completed',
      targetId: 'fixture-local-live',
      confirmedFindings: 0,
      runDir: '/tmp/live-confirmation-detailed',
      totalCostUsd: 1.25,
      durationMs: 61000,
    },
    childCampaigns: [
      {
        lane: 'local-live',
        campaignId: 'child-local-1',
        status: 'completed',
        targetId: 'fixture-local-live',
        runDir: '/tmp/child-local-1',
        totalCostUsd: 1.25,
        durationMs: 61000,
      },
    ],
    verificationLanes: {
      executionStatus: 'degraded',
      requiredCoverageSatisfied: false,
      meaningfulAttempts: 4,
      coverageGaps: [
        {
          lane: 'local-live',
          code: 'linux_sidecar_missing',
          message: 'Linux sidecar was unavailable for /proc verification.',
          severity: 'degraded',
          required: true,
        },
      ],
      experimentsPath: '/tmp/verification-experiments.jsonl',
      testSynthesis: lane({
        attempted: 3,
        meaningfulAttempts: 2,
        blocked: 1,
        rateLimited: 1,
        autoStopped: 1,
        timeout: 1,
        runtimeError: 1,
        compileError: 1,
        coverageGaps: ['Counter-review was unavailable for one synthesized test.'],
        notes: ['One synthesized test stalled with no output.'],
        status: 'degraded',
        required: true,
        auditTrailPath: '/tmp/test-synthesis-audit.jsonl',
      }),
      localLive: lane({
        attempted: 4,
        meaningfulAttempts: 2,
        refuted: 2,
        authFailed: 1,
        notApplicable: 1,
        costUsd: 0.5,
        durationMs: 65000,
        status: 'degraded',
        required: true,
        // Section 8.2: monitoring stress data folded into local-live
        runs: 3,
        degraded: 2,
        harmfulSeen: 1,
      }),
      supplyChain: lane({
        attempted: 2,
        meaningfulAttempts: 2,
        confirmedRisk: 1,
        needsReview: 1,
        approvedDrift: 0,
        costUsd: 0.33,
        durationMs: 15000,
      }),
    },
    executiveAssessment: {
      overallVerdict: 'no_material_findings',
      confidence: 0.74,
      summary: 'No confirmed vulnerabilities were established, but the run is incomplete for some required verification lanes.',
      confirmedVulnerabilities: [],
      validatedRisks: [],
      configurationRisks: [],
      unconfirmedLeads: [],
      suppressedClaims: [],
      nextActions: ['Configure hosted canary credentials and rerun the strict hosted lane.'],
      source: 'campaign_assessment_panel',
      reviewerModels: ['openai/gpt-5.4', 'anthropic/claude-opus-4-6'],
      synthesizerModel: 'anthropic/claude-opus-4-6',
      parseStatus: 'fallback_panel:summary_conflict',
    },
  });

  assert.match(markdown, /End-to-end cost \| \$6\.7500/);
  assert.match(markdown, /End-to-end duration \| 3m 0s/);
  assert.match(markdown, /### Child Campaigns/);
  assert.match(markdown, /local-live: child-local-1, status=completed, target=fixture-local-live, cost=\$1\.2500, duration=1m 1s/);
  assert.match(markdown, /Run dir: \/tmp\/child-local-1/);
  assert.match(markdown, /Verification experiments: \/tmp\/verification-experiments\.jsonl/);
  assert.match(markdown, /Coverage gaps:/);
  assert.match(markdown, /Counter-review was unavailable for one synthesized test\./);
  assert.match(markdown, /Notes:/);
  assert.match(markdown, /One synthesized test stalled with no output\./);
  assert.match(markdown, /Rate limited: 1 \| Auto-stopped: 1 \| Timeout: 1 \| Compile error: 1 \| Runtime error: 1/);
  assert.match(markdown, /Confirmed risk: 1 \| Needs review: 1 \| Approved drift: 0/);
  assert.match(markdown, /Runs: 3 \| Monitoring degraded: 2 \| Harmful seen: 1/);
  assert.match(markdown, /Execution status: degraded/);
  assert.match(markdown, /Assessment parse status: fallback_panel:summary_conflict/);
  assert.match(markdown, /Status: completed/);
  assert.match(markdown, /Cost: \$1\.2500/);
  assert.match(markdown, /Duration: 1m 1s/);
  assert.match(markdown, /provisional — execution incomplete or degraded/i);
});

test('renderInvestigationReport falls back to runner findings when no executive assessment exists', () => {
  const markdown = renderInvestigationReport({
    campaignId: 'campaign-runner-only',
    targetId: 'fixture-alt-local',
    targetLabel: 'Fixture Alt Local',
    targetKind: 'code',
    environment: 'sandbox',
    mode: 'declared',
    startedAt: '2026-04-10T00:00:00.000Z',
    completedAt: '2026-04-10T00:01:00.000Z',
    iterations: 1,
    totalCostUsd: 0.75,
    signalsFound: 1,
    signalsDormant: 0,
    signalsReactivated: 0,
    hypothesesTested: 1,
    chainHypothesesTested: 0,
    directHypothesesTested: 1,
    hypothesesConfirmed: 1,
    hypothesesRefuted: 0,
    maxChainLength: 0,
    chainLengthDistribution: {},
    findings: [
      {
        severity: 'medium',
        description: 'A runner-only finding was produced without campaign synthesis.',
        reproductionSteps: ['Read the route file', 'Observe the permissive branch'],
        remediationSuggestion: 'Add a follow-up campaign-level review before acting.',
        involvedDormantReactivation: false,
        confirmedAt: '2026-04-10T00:00:45.000Z',
      },
    ],
    topSignals: [],
    refutedHypotheses: [],
    telemetrySummary: 'planner=1 judge=1 cost=$0.75',
  });

  assert.match(markdown, /The run produced confirmed findings\. Review the findings section for details\./);
  assert.match(markdown, /## Findings/);
  assert.match(markdown, /\[MEDIUM\] A runner-only finding was produced without campaign synthesis\./);
  assert.match(markdown, /\*\*Reproduction steps:\*\*/);
  assert.match(markdown, /\*\*Remediation:\*\* Add a follow-up campaign-level review before acting\./);
});

// ---------------------------------------------------------------------------
// Section 7.1 — source location ref rendering
// ---------------------------------------------------------------------------

test('renderInvestigationReport renders Cited source section for findings with sourceLocationRefs', () => {
  const markdown = renderInvestigationReport({
    campaignId: 'camp-7.1-source',
    targetId: 'test',
    targetLabel: 'Test Target',
    targetKind: 'webapp',
    environment: 'fixture',
    mode: 'declared',
    startedAt: '2026-04-10T00:00:00.000Z',
    completedAt: '2026-04-10T00:01:00.000Z',
    iterations: 1,
    totalCostUsd: 0.5,
    signalsFound: 1,
    signalsDormant: 0,
    signalsReactivated: 0,
    hypothesesTested: 1,
    chainHypothesesTested: 1,
    directHypothesesTested: 0,
    hypothesesConfirmed: 1,
    hypothesesRefuted: 0,
    maxChainLength: 1,
    chainLengthDistribution: { '1': 1 },
    findings: [
      {
        severity: 'high',
        description: 'SQL injection in approval handler',
        reproductionSteps: ['Send crafted input'],
        remediationSuggestion: 'Use parameterized queries',
        involvedDormantReactivation: false,
        confirmedAt: '2026-04-10T00:00:30.000Z',
        sourceLocationRefs: [
          { path: 'src/api/routes/approvals.ts', startLine: 42, endLine: 58 },
          { path: 'src/db/queries.ts', startLine: 10 },
        ],
      },
    ],
    topSignals: [],
    refutedHypotheses: [],
    telemetrySummary: 'cost=$0.50',
  });

  assert.match(markdown, /\*\*Cited source:\*\*/);
  assert.match(markdown, /`src\/api\/routes\/approvals\.ts:42-58`/);
  assert.match(markdown, /`src\/db\/queries\.ts:10`/);
});

test('renderInvestigationReport does not render Cited source when no sourceLocationRefs', () => {
  const markdown = renderInvestigationReport({
    campaignId: 'camp-7.1-nosource',
    targetId: 'test',
    targetLabel: 'Test Target',
    targetKind: 'webapp',
    environment: 'fixture',
    mode: 'declared',
    startedAt: '2026-04-10T00:00:00.000Z',
    completedAt: '2026-04-10T00:01:00.000Z',
    iterations: 1,
    totalCostUsd: 0.5,
    signalsFound: 1,
    signalsDormant: 0,
    signalsReactivated: 0,
    hypothesesTested: 1,
    chainHypothesesTested: 1,
    directHypothesesTested: 0,
    hypothesesConfirmed: 1,
    hypothesesRefuted: 0,
    maxChainLength: 1,
    chainLengthDistribution: { '1': 1 },
    findings: [
      {
        severity: 'medium',
        description: 'Pre-7.1 finding without source refs',
        reproductionSteps: ['Step 1'],
        remediationSuggestion: 'Fix it',
        involvedDormantReactivation: false,
        confirmedAt: '2026-04-10T00:00:30.000Z',
        // No sourceLocationRefs — pre-7.1 campaign data
      },
    ],
    topSignals: [],
    refutedHypotheses: [],
    telemetrySummary: 'cost=$0.50',
  });

  assert.ok(!markdown.includes('Cited source'));
});

test('renderInvestigationReport renders Cited source for executive assessment confirmed vulnerabilities', () => {
  const markdown = renderInvestigationReport({
    campaignId: 'camp-7.1-assessment',
    targetId: 'test',
    targetLabel: 'Test Target',
    targetKind: 'webapp',
    environment: 'fixture',
    mode: 'declared',
    startedAt: '2026-04-10T00:00:00.000Z',
    completedAt: '2026-04-10T00:01:00.000Z',
    iterations: 1,
    totalCostUsd: 0.5,
    signalsFound: 1,
    signalsDormant: 0,
    signalsReactivated: 0,
    hypothesesTested: 1,
    chainHypothesesTested: 1,
    directHypothesesTested: 0,
    hypothesesConfirmed: 1,
    hypothesesRefuted: 0,
    maxChainLength: 1,
    chainLengthDistribution: { '1': 1 },
    findings: [],
    topSignals: [],
    refutedHypotheses: [],
    telemetrySummary: 'cost=$0.50',
    executiveAssessment: {
      overallVerdict: 'confirmed_vulnerabilities_present',
      confidence: 0.9,
      summary: 'SQL injection confirmed.',
      confirmedVulnerabilities: [
        {
          title: 'SQL Injection',
          severity: 'high',
          description: 'User input reaches raw SQL query.',
          evidenceRefs: ['exp-1'],
          requiredConditions: [],
          sourceLocationRefs: [
            { path: 'src/api/routes/approvals.ts', startLine: 42, endLine: 58 },
          ],
        },
      ],
      validatedRisks: [],
      configurationRisks: [],
      unconfirmedLeads: [],
      suppressedClaims: [],
      nextActions: [],
      source: 'synthesizer',
      reviewerModels: ['claude'],
    },
  });

  assert.match(markdown, /\*\*Cited source:\*\*/);
  assert.match(markdown, /`src\/api\/routes\/approvals\.ts:42-58`/);
});

test('renderInvestigationReport renders legacy monitoring-stress verification details and model activity table', () => {
  const markdown = renderInvestigationReport({
    campaignId: 'camp-legacy-monitoring',
    targetId: 'fixture',
    targetLabel: 'Fixture',
    targetKind: 'http',
    environment: 'local_live',
    mode: 'blind',
    startedAt: '2026-04-10T00:00:00.000Z',
    completedAt: '2026-04-10T00:02:00.000Z',
    iterations: 2,
    totalCostUsd: 0.88,
    signalsFound: 1,
    signalsDormant: 0,
    signalsReactivated: 0,
    hypothesesTested: 1,
    chainHypothesesTested: 1,
    directHypothesesTested: 0,
    hypothesesConfirmed: 0,
    hypothesesRefuted: 1,
    maxChainLength: 3,
    chainLengthDistribution: { '3': 1 },
    findings: [],
    topSignals: [],
    refutedHypotheses: ['legacy runtime chain'],
    telemetrySummary: 'fixture',
    executionStatus: 'degraded',
    runMode: 'smoke',
    coverageGaps: [{ lane: 'local-live', code: 'missing_canary', message: 'Missing seeded identity', severity: 'degraded' }],
    childCampaigns: [
      {
        lane: 'local-live',
        campaignId: 'child-monitoring',
        status: 'completed',
        targetId: 'fixture-live',
        runDir: '/tmp/child-monitoring',
        totalCostUsd: 0.11,
        durationMs: 1200,
      },
    ],
    modelActivity: [
      { role: 'plan', provider: 'openai', model: 'gpt-5.4', calls: 2, costUsd: 0.12 },
    ],
    verificationLanes: {
      executionStatus: 'degraded',
      requiredCoverageSatisfied: false,
      meaningfulAttempts: 4,
      experimentsPath: '/tmp/experiments.jsonl',
      monitoringStress: lane({
        attempted: 2,
        meaningfulAttempts: 2,
        degraded: 1,
        harmfulSeen: 1,
        runs: 2,
        status: 'degraded',
        required: false,
        coverageGaps: ['Legacy monitoring signal'],
      }),
      coverageGaps: [{ lane: 'local-live', code: 'lane_gap', message: 'Missing seeded identity', severity: 'degraded' }],
    },
  });

  assert.match(markdown, /### Child Campaigns/);
  assert.match(markdown, /local-live: child-monitoring, status=completed, target=fixture-live, cost=\$0\.1100, duration=1s/);
  assert.match(markdown, /### Activated Model Activity/);
  assert.match(markdown, /\| plan \| openai\/gpt-5\.4 \| 2 \| \$0\.1200 \|/);
  assert.match(markdown, /Monitoring stress \(legacy\)/);
  assert.match(markdown, /Verification experiments: \/tmp\/experiments\.jsonl/);
});

test('renderInvestigationReport covers executive-assessment fallback and findings-only branches', () => {
  const noAssessmentNoFindings = renderInvestigationReport({
    campaignId: 'camp-no-assessment',
    targetId: 'fixture',
    targetLabel: 'Fixture',
    targetKind: 'code',
    environment: 'sandbox',
    mode: 'declared',
    startedAt: '2026-04-10T00:00:00.000Z',
    completedAt: '2026-04-10T00:01:00.000Z',
    iterations: 1,
    totalCostUsd: 0.01,
    signalsFound: 0,
    signalsDormant: 0,
    signalsReactivated: 0,
    hypothesesTested: 0,
    chainHypothesesTested: 0,
    directHypothesesTested: 0,
    hypothesesConfirmed: 0,
    hypothesesRefuted: 0,
    maxChainLength: 0,
    chainLengthDistribution: {},
    findings: [],
    topSignals: [],
    refutedHypotheses: [],
    telemetrySummary: 'none',
  });
  assert.match(noAssessmentNoFindings, /No confirmed vulnerabilities were produced by this run/);

  const findingsOnly = renderInvestigationReport({
    campaignId: 'camp-findings-only',
    targetId: 'fixture',
    targetLabel: 'Fixture',
    targetKind: 'code',
    environment: 'sandbox',
    mode: 'declared',
    startedAt: '2026-04-10T00:00:00.000Z',
    completedAt: '2026-04-10T00:01:00.000Z',
    iterations: 1,
    totalCostUsd: 0.2,
    signalsFound: 1,
    signalsDormant: 0,
    signalsReactivated: 0,
    hypothesesTested: 1,
    chainHypothesesTested: 0,
    directHypothesesTested: 1,
    hypothesesConfirmed: 1,
    hypothesesRefuted: 0,
    maxChainLength: 0,
    chainLengthDistribution: {},
    findings: [
      {
        severity: 'high',
        description: 'A direct chain was confirmed.\nWith supporting details.',
        reproductionSteps: ['Start service', 'Trigger vulnerable path'],
        remediationSuggestion: 'Remove the exposed path.',
        involvedDormantReactivation: false,
        confirmedAt: '2026-04-10T00:00:30.000Z',
      },
    ],
    topSignals: [],
    refutedHypotheses: [],
    telemetrySummary: 'one finding',
  });
  assert.match(findingsOnly, /The run produced confirmed findings/);
  assert.match(findingsOnly, /## Findings/);
  assert.match(findingsOnly, /\*\*Reproduction steps:\*\*/);
  assert.match(findingsOnly, /With supporting details\./);
});

test('renderInvestigationReport covers manifest-only and none target-coverage variants', () => {
  const manifestOnly = renderInvestigationReport({
    campaignId: 'camp-target-manifest-only',
    targetId: 'fixture',
    targetLabel: 'Fixture',
    targetKind: 'code',
    environment: 'sandbox',
    mode: 'declared',
    startedAt: '2026-04-10T00:00:00.000Z',
    completedAt: '2026-04-10T00:01:00.000Z',
    iterations: 1,
    totalCostUsd: 0.05,
    signalsFound: 0,
    signalsDormant: 0,
    signalsReactivated: 0,
    hypothesesTested: 0,
    chainHypothesesTested: 0,
    directHypothesesTested: 0,
    hypothesesConfirmed: 0,
    hypothesesRefuted: 0,
    maxChainLength: 0,
    chainLengthDistribution: {},
    findings: [],
    topSignals: [],
    refutedHypotheses: [],
    telemetrySummary: 'none',
    targetCoverage: {
      coverage: 'manifest-only',
      supportedProbeKinds: [],
    },
  });

  const none = renderInvestigationReport({
    campaignId: 'camp-target-none',
    targetId: 'fixture',
    targetLabel: 'Fixture',
    targetKind: 'code',
    environment: 'sandbox',
    mode: 'declared',
    startedAt: '2026-04-10T00:00:00.000Z',
    completedAt: '2026-04-10T00:01:00.000Z',
    iterations: 1,
    totalCostUsd: 0.05,
    signalsFound: 0,
    signalsDormant: 0,
    signalsReactivated: 0,
    hypothesesTested: 0,
    chainHypothesesTested: 0,
    directHypothesesTested: 0,
    hypothesesConfirmed: 0,
    hypothesesRefuted: 0,
    maxChainLength: 0,
    chainLengthDistribution: {},
    findings: [],
    topSignals: [],
    refutedHypotheses: [],
    telemetrySummary: 'none',
    targetCoverage: {
      coverage: 'none',
      supportedProbeKinds: [],
    },
  });

  assert.match(manifestOnly, /## Target Coverage/);
  assert.match(manifestOnly, /\*\*Coverage: manifest-only\*\*/);
  assert.match(manifestOnly, /Manifest files were detected but no dependencies could be parsed/);
  assert.match(none, /\*\*Coverage: none\*\*/);
  assert.match(none, /No recognizable stack or manifest files were found/);
});

test('renderInvestigationReport renders assessment metadata and omits verification section when verification lanes are absent', () => {
  const markdown = renderInvestigationReport({
    campaignId: 'camp-assessment-metadata',
    targetId: 'fixture',
    targetLabel: 'Fixture',
    targetKind: 'http',
    environment: 'sandbox',
    mode: 'declared',
    startedAt: '2026-04-10T00:00:00.000Z',
    completedAt: '2026-04-10T00:01:00.000Z',
    iterations: 1,
    totalCostUsd: 0.4,
    signalsFound: 1,
    signalsDormant: 0,
    signalsReactivated: 0,
    hypothesesTested: 1,
    chainHypothesesTested: 1,
    directHypothesesTested: 0,
    hypothesesConfirmed: 0,
    hypothesesRefuted: 1,
    maxChainLength: 2,
    chainLengthDistribution: { '2': 1 },
    findings: [
      {
        severity: 'low',
        description: 'A detailed runner finding.\nWith a second line for the report body.',
        reproductionSteps: ['Read route file', 'Observe guard branch'],
        remediationSuggestion: 'Tighten the route guard.',
        involvedDormantReactivation: false,
        confirmedAt: '2026-04-10T00:00:30.000Z',
      },
    ],
    topSignals: [],
    refutedHypotheses: [],
    telemetrySummary: 'planner=1',
    executionStatus: 'incomplete',
    assessmentParseStatus: 'parsed_json',
    coverageGaps: [
      {
        lane: 'local-live',
        code: 'linux_runtime_unavailable',
        message: 'Linux runtime was unavailable for runtime probes.',
        severity: 'incomplete',
      },
    ],
    executiveAssessment: {
      overallVerdict: 'no_material_findings',
      confidence: 0.51,
      summary: 'No confirmed vulnerabilities were established.',
      confirmedVulnerabilities: [],
      validatedRisks: [],
      configurationRisks: [],
      unconfirmedLeads: [],
      suppressedClaims: [],
      nextActions: ['Enable the Linux runtime and rerun local-live.'],
      source: 'review_panel',
      reviewerModels: ['openai/gpt-5.4', 'gemini/gemini-3.1-pro'],
      synthesizerModel: 'anthropic/claude-opus-4-6',
    },
  });

  assert.doesNotMatch(markdown, /## Verification Lanes/);
  assert.match(markdown, /Outcome: provisional — execution incomplete or degraded/);
  assert.match(markdown, /Reviewer models: openai\/gpt-5\.4, gemini\/gemini-3\.1-pro/);
  assert.match(markdown, /Final synthesizer: anthropic\/claude-opus-4-6/);
  assert.match(markdown, /Assessment parse status: parsed_json/);
  assert.match(markdown, /Execution gaps prevented a fully closed verification result:/);
  assert.match(markdown, /Linux runtime was unavailable for runtime probes\./);
  assert.match(markdown, /Runner-Level Candidate Findings \(Not Upheld By Final Assessment\)/);
  assert.match(markdown, /A detailed runner finding\./);
});
