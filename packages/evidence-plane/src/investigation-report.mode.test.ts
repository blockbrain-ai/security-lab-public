/**
 * Section 3.2 — report rendering tests for the Run Mode and Execution Status
 * sections. These sections must always be visible and must never conflate the
 * executionStatus with the security overallVerdict.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { renderInvestigationReport } from './investigation-report.js';
import type { InvestigationReportData } from './investigation-report.js';

function baseData(overrides: Partial<InvestigationReportData> = {}): InvestigationReportData {
  return {
    campaignId: 'campaign-mode-test',
    targetId: 'mode-target',
    targetLabel: 'Mode Target',
    targetKind: 'code',
    environment: 'sandbox',
    mode: 'declared',
    startedAt: '2026-04-11T00:00:00.000Z',
    completedAt: '2026-04-11T00:01:00.000Z',
    iterations: 0,
    totalCostUsd: 0,
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
    telemetrySummary: 'planner=0 judge=0 cost=$0',
    ...overrides,
  };
}

test('run mode and execution status sections appear prominently for a smoke run', () => {
  const report = renderInvestigationReport(baseData({
    runMode: 'smoke',
    executionStatus: 'complete',
  }));

  assert.match(report, /## Run Mode/);
  assert.match(report, /\*\*Run mode:\*\* `smoke`/);
  assert.match(report, /## Execution Status/);
  assert.match(report, /\*\*Execution status:\*\* `complete`/);
  assert.match(report, /Coverage confirmation/);

  // Run Mode section must appear before the Executive Assessment section so
  // operators cannot miss the rigor level when skimming.
  const runModeIndex = report.indexOf('## Run Mode');
  const execAssessmentIndex = report.indexOf('## Executive Assessment');
  assert.ok(runModeIndex >= 0);
  assert.ok(execAssessmentIndex >= 0);
  assert.ok(runModeIndex < execAssessmentIndex);
});

test("serious-local incomplete run shows 'what's missing' list", () => {
  const report = renderInvestigationReport(baseData({
    runMode: 'serious-local',
    executionStatus: 'incomplete',
    coverageGaps: [
      {
        lane: 'local-live',
        code: 'missing_required_identity',
        message: 'Missing required local-live identities: user_a_low',
        severity: 'incomplete',
        required: true,
      },
    ],
  }));

  assert.match(report, /\*\*Run mode:\*\* `serious-local`/);
  assert.match(report, /\*\*Execution status:\*\* `incomplete`/);
  assert.match(report, /What's missing/);
  assert.match(report, /Missing required local-live identities/);
  assert.match(report, /local-live \(required\)/);
});

test('execution status is never conflated with the security verdict', () => {
  const report = renderInvestigationReport(baseData({
    runMode: 'serious-end-to-end',
    executionStatus: 'incomplete',
    coverageGaps: [
      {
        lane: 'hosted',
        code: 'missing_required_hosted_auth',
        message: 'No hosted credentials configured',
        severity: 'incomplete',
        required: true,
      },
    ],
    executiveAssessment: {
      overallVerdict: 'no_material_findings',
      confidence: 0.9,
      summary: 'No vulnerabilities discovered.',
      confirmedVulnerabilities: [],
      validatedRisks: [],
      configurationRisks: [],
      unconfirmedLeads: [],
      suppressedClaims: [],
      nextActions: [],
      source: 'test',
      reviewerModels: [],
    },
  }));

  // Execution Status section must explicitly disclaim that it is not a
  // security verdict. This prevents operators from reading "incomplete" as
  // "no findings means secure".
  assert.match(report, /run-integrity signal/i);
  assert.match(report, /not a security verdict/i);

  // Executive assessment section must still render the verdict, but it is a
  // separate section, never combined with executionStatus.
  const execStatusIdx = report.indexOf('## Execution Status');
  const execAssessIdx = report.indexOf('## Executive Assessment');
  assert.ok(execStatusIdx >= 0 && execAssessIdx >= 0);
  assert.ok(execStatusIdx < execAssessIdx);
});

test('defaults: runMode missing defaults to smoke in rendering', () => {
  const report = renderInvestigationReport(baseData());
  assert.match(report, /\*\*Run mode:\*\* `smoke`/);
});
