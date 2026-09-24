/**
 * Injection regression tests: target-controlled strings must render inert in
 * the Markdown investigation report (no forged sections, no broken tables, no
 * code-span breakout, no raw HTML).
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { renderInvestigationReport, type InvestigationReportData } from './investigation-report.js';

function baseData(overrides: Partial<InvestigationReportData> = {}): InvestigationReportData {
  return {
    campaignId: 'campaign-injection',
    targetId: 'hostile-target',
    targetLabel: 'Hostile Target',
    targetKind: 'code',
    environment: 'sandbox',
    mode: 'declared',
    startedAt: '2026-04-11T00:00:00.000Z',
    completedAt: '2026-04-11T00:01:00.000Z',
    iterations: 1,
    totalCostUsd: 0.01,
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
    findings: [],
    topSignals: [],
    refutedHypotheses: [],
    telemetrySummary: 'planner=1',
    ...overrides,
  };
}

const INJECTED_SECTION = 'Injected Section';
const SECTION_PAYLOAD = `benign first line\n## ${INJECTED_SECTION}\n- forged bullet`;
const HTML_PAYLOAD = '<img src=x onerror=alert(1)>';

test('a newline plus a heading in a finding description cannot forge a report section', () => {
  const report = renderInvestigationReport(baseData({
    findings: [
      {
        severity: 'high',
        description: SECTION_PAYLOAD,
        reproductionSteps: [`step one\n## ${INJECTED_SECTION}`],
        remediationSuggestion: SECTION_PAYLOAD,
        involvedDormantReactivation: true,
        confirmedAt: '2026-04-11T00:00:30.000Z',
      },
    ],
  }));

  assert.ok(!/^## Injected Section$/m.test(report), 'forged section heading rendered');
  assert.ok(!/^- forged bullet$/m.test(report), 'forged list item rendered');
  assert.match(report, /\\## Injected Section/);
  assert.match(report, /\\- forged bullet/);
});

test('a hostile executive-assessment summary cannot forge a report section', () => {
  const report = renderInvestigationReport(baseData({
    executiveAssessment: {
      overallVerdict: 'confirmed_vulnerabilities_present',
      confidence: 0.9,
      summary: SECTION_PAYLOAD,
      confirmedVulnerabilities: [],
      validatedRisks: [],
      configurationRisks: [],
      unconfirmedLeads: [],
      suppressedClaims: [
        { claim: SECTION_PAYLOAD, reason: `reason\n## ${INJECTED_SECTION}`, evidenceRefs: ['ws-1'] },
      ],
      nextActions: [`action\n## ${INJECTED_SECTION}`],
      source: 'synthesized',
      reviewerModels: [],
    },
  }));

  assert.ok(!/^## Injected Section$/m.test(report), 'forged section heading rendered');
  assert.ok(!report.includes(`Summary: ## ${INJECTED_SECTION}`));
  assert.match(report, /\\## Injected Section/);
});

test('a pipe in target-controlled table content cannot break the table', () => {
  const report = renderInvestigationReport(baseData({
    signalRowsNeverUsed: undefined,
    probeCoverageGaps: [{ code: 'gap|code', count: 2 }],
    entityInventorySummary: {
      totalEntries: 3,
      byKind: { 'user|admin': 1 },
      byProvenance: { 'derive|d': 2 },
      unresolvedParameters: ['param|name'],
    },
    probeFamilyCoverage: {
      totalFamilyProbes: 2,
      byFamily: { 'fam|ily': { probes: 2, variants: ['var|iant'] } },
    },
  } as Partial<InvestigationReportData>));

  assert.match(report, /\| `gap\\\|code` \| 2 \|/);
  assert.match(report, /\| `user\\\|admin` \| 1 \|/);
  assert.match(report, /`param\\\|name`/);

  // Each table row keeps the expected number of unescaped cell separators.
  const gapRow = report.split('\n').find((line) => line.includes('gap\\|code'));
  assert.equal(gapRow?.split(/(?<!\\)\|/).length, 5);
});

test('a backtick inside a cited source path cannot break out of the code span', () => {
  const report = renderInvestigationReport(baseData({
    findings: [
      {
        severity: 'high',
        description: 'Backtick path',
        reproductionSteps: [],
        remediationSuggestion: 'none',
        involvedDormantReactivation: false,
        confirmedAt: '2026-04-11T00:00:30.000Z',
        sourceLocationRefs: [{ path: 'src/a`b.ts', startLine: 1 }],
      },
    ],
  }));

  assert.match(report, /``src\/a`b\.ts:1``/);
  // The widened fence is what keeps the ref inert: a single-backtick fence
  // would have terminated early and rendered the remainder as prose.
  const citedLine = report.split('\n').find((line) => line.includes('src/a`b.ts:1'));
  assert.equal(citedLine, '- ``src/a`b.ts:1``');
});

test('raw HTML in target-controlled strings is escaped everywhere it renders', () => {
  const report = renderInvestigationReport(baseData({
    targetLabel: HTML_PAYLOAD,
    findings: [
      {
        severity: 'high',
        description: `desc ${HTML_PAYLOAD}`,
        reproductionSteps: [`step ${HTML_PAYLOAD}`],
        remediationSuggestion: `fix ${HTML_PAYLOAD}`,
        involvedDormantReactivation: false,
        confirmedAt: '2026-04-11T00:00:30.000Z',
      },
    ],
    topSignals: [
      {
        id: 'ws-1',
        surface: 'code',
        confidence: 0.5,
        status: 'active',
        description: `signal ${HTML_PAYLOAD}`,
        relatedAssets: [`asset ${HTML_PAYLOAD}`],
      },
    ],
    refutedHypotheses: [`refuted ${HTML_PAYLOAD}`],
    telemetrySummary: `telemetry ${HTML_PAYLOAD}`,
  }));

  assert.ok(!report.includes('<img'), 'raw HTML survived into the report');
  assert.ok(report.includes('&lt;img src=x onerror=alert(1)&gt;'));
});

test('target-controlled values that start a line cannot open a block construct', () => {
  const report = renderInvestigationReport(baseData({
    portfolioId: '# Not A Heading',
    knowledgeBasePath: '---',
    refutedHypotheses: ['1. not an ordered item'],
  }));

  assert.ok(!/^# Not A Heading$/m.test(report));
  assert.match(report, /\\# Not A Heading/);
  assert.match(report, /\\---/);
  assert.match(report, /1\\\. not an ordered item/);
});
