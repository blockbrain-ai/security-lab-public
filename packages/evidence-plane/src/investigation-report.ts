/**
 * Investigation-specific report renderer — produces a comprehensive
 * markdown report of an autonomous investigation campaign.
 */

import {
  COVERAGE_GAP_REMEDIATION_HINTS,
  type CoverageGapReasonCode,
} from './events/coverage-gap-events.js';
import { escapeMarkdownBlock, escapeMarkdownLine, renderCodeSpan } from './markdown-escape.js';
import type { SourceLocationRef } from './source-location-ref.js';
import { formatSourceRef } from './source-location-ref.js';

// ---------------------------------------------------------------------------
// Types (investigation-specific additions to RunSummary)
// ---------------------------------------------------------------------------

export type ExecutionStatusRecord = 'complete' | 'degraded' | 'incomplete' | 'blocked';

export type RunModeRecord = 'smoke' | 'serious-local' | 'serious-end-to-end';

export interface InvestigationReportData {
  campaignId: string;
  status?: string | null;
  targetId: string;
  targetLabel: string;
  targetKind: string;
  environment: string;
  mode: string;
  startedAt: string;
  completedAt: string;
  iterations: number;
  totalCostUsd: number;
  signalsFound: number;
  signalsDormant: number;
  signalsReactivated: number;
  hypothesesTested: number;
  chainHypothesesTested: number;
  directHypothesesTested: number;
  hypothesesConfirmed: number;
  hypothesesRefuted: number;
  maxChainLength: number;
  chainLengthDistribution: Record<string, number>;
  findings: FindingRecord[];
  topSignals: SignalRecord[];
  refutedHypotheses: string[];
  telemetrySummary: string;
  executionStatus?: ExecutionStatusRecord;
  /** Run mode (Section 3.2): smoke, serious-local, or serious-end-to-end. */
  runMode?: RunModeRecord;
  coverageGaps?: CoverageGapRecord[];
  laneStats?: Record<string, LaneStatRecord>;
  laneCosts?: Record<string, number>;
  meaningfulAttempts?: number;
  childCampaigns?: ChildCampaignRecord[];
  requiredCoverageSatisfied?: boolean;
  assessmentParseStatus?: string;
  // Compatibility aliases for tooling that still expects the assessment
  // as flattened top-level fields in summary.json.
  assessmentVerdict?: string | null;
  assessmentConfidence?: number | null;
  assessmentSummary?: string | null;
  endToEndCostUsd?: number;
  endToEndDurationMs?: number;
  portfolioId?: string | null;
  plannerModel?: string | null;
  judgeModel?: string | null;
  judgePanelModels?: string[];
  synthesizerModel?: string | null;
  knowledgeBasePath?: string | null;
  priorKnowledgeUsed?: boolean;
  liveConfirmation?: {
    enabled: boolean;
    status: string;
    targetId: string | null;
    confirmedFindings: number;
    runDir?: string;
    campaignId?: string;
    sourceCampaignId?: string;
    totalCostUsd?: number;
    durationMs?: number;
  };
  verificationLanes?: {
    testSynthesis?: VerificationLaneRecord;
    localLive?: VerificationLaneRecord;
    hosted?: VerificationLaneRecord;
    /** Section 12.1 — browser lane stats. */
    browser?: VerificationLaneRecord;
    supplyChain?: VerificationLaneRecord;
    monitoringStress?: VerificationLaneRecord;
    executionStatus?: ExecutionStatusRecord;
    coverageGaps?: CoverageGapRecord[];
    laneCosts?: Record<string, number>;
    meaningfulAttempts?: number;
    childCampaigns?: ChildCampaignRecord[];
    requiredCoverageSatisfied?: boolean;
    experimentsPath?: string;
  };
  // Compatibility aliases for older summary readers.
  localLive?: VerificationLaneRecord | null;
  testSynthesis?: VerificationLaneRecord | null;
  modelActivity?: ModelActivityRecord[];
  executiveAssessment?: ExecutiveAssessmentRecord | null;
  campaignAssessment?: ExecutiveAssessmentRecord | null;
  executiveVerdict?: string | null;
  targetCoverage?: {
    coverage: 'full' | 'partial' | 'manifest-only' | 'none';
    supportedProbeKinds: string[];
    detectedStack?: {
      language: string;
      framework: string;
      manifestFiles: string[];
    };
  };
  /** Probe-level coverage gaps (Section 3.1) with structured reason codes. */
  probeCoverageGaps?: ProbeCoverageGapRecord[];
  /** Section 11.1 — entity inventory summary for probe parameter resolution. */
  entityInventorySummary?: EntityInventorySummaryRecord;
  /** Section 11.2 — probe family coverage summary. */
  probeFamilyCoverage?: ProbeFamilyCoverageRecord;
  /** Section 11.3 — assertion-based classification summary. */
  assertionClassification?: AssertionClassificationSummaryRecord;
  /** Section 11.4 — sequence and identity-differential execution summary. */
  sequenceExecution?: SequenceExecutionSummaryRecord;
  /** Section 12.2 — browser exploit family coverage summary. */
  browserExploitFamilies?: BrowserExploitFamilySummaryRecord;
  /** Section 11.5 — focused lead confirmation summary. */
  focusedLeadConfirmation?: FocusedLeadConfirmationSummaryRecord;
}

/** Section 12.2 — browser-native exploit family coverage. */
export interface BrowserExploitFamilySummaryRecord {
  totalBrowserProbes: number;
  byFamily: Record<string, {
    probes: number;
    variants: string[];
    confirmed: number;
    refuted: number;
    inconclusive: number;
  }>;
}

/** Section 11.5 — focused lead confirmation session summary. */
export interface FocusedLeadConfirmationSummaryRecord {
  sessionsRun: number;
  confirmed: number;
  refuted: number;
  narrowed: number;
  needsBrowser: number;
  needsHumanSetup: number;
  insufficientEvidence: number;
  totalProbesExecuted: number;
  leads: Array<{
    hypothesisId: string;
    rank: number;
    severity: string;
    probeFamily: string;
    status: string;
    totalProbes: number;
  }>;
}

export interface EntityInventorySummaryRecord {
  totalEntries: number;
  byKind: Record<string, number>;
  byProvenance: Record<string, number>;
  unresolvedParameters: string[];
}

/** Section 11.2 — per-family probe coverage. */
export interface ProbeFamilyCoverageRecord {
  /** Total probes tagged with a family. */
  totalFamilyProbes: number;
  /** Breakdown by family ID. */
  byFamily: Record<string, { probes: number; variants: string[] }>;
}

/** Section 11.3 — assertion-based classification breakdown. */
export interface AssertionClassificationSummaryRecord {
  /** Total probes that went through assertion classification. */
  totalClassified: number;
  /** Breakdown by classification reason. */
  byReason: Record<string, number>;
  /** Breakdown by detected route kind. */
  byRouteKind: Record<string, number>;
  /** Probes suppressed (not counted as meaningful attempts). */
  suppressedCount: number;
}

/** Section 11.4 — sequence and identity-differential execution summary. */
export interface SequenceExecutionSummaryRecord {
  /** Total sequences executed. */
  sequencesExecuted: number;
  /** Total sequence steps executed across all sequences. */
  totalStepsExecuted: number;
  /** Sequences that produced a confirmed verdict. */
  sequencesConfirmed: number;
  /** Sequences that produced a refuted verdict. */
  sequencesRefuted: number;
  /** Sequences with inconclusive outcome. */
  sequencesInconclusive: number;
  /** Total identity differentials executed. */
  differentialsExecuted: number;
  /** Differentials that detected privilege escalation. */
  differentialsWithEscalation: number;
  /** Steps where extracted outputs were consumed by later steps. */
  statePassthroughCount: number;
  /** Rollbacks executed after sequences. */
  rollbacksExecuted: number;
}

export interface ProbeCoverageGapRecord {
  code: string;
  count: number;
  probeIds?: string[];
  identityIds?: string[];
}

export interface FindingRecord {
  severity: string;
  description: string;
  reproductionSteps: string[];
  remediationSuggestion: string;
  involvedDormantReactivation: boolean;
  confirmedAt: string;
  /** Section 7.1 — file:line source refs supporting this finding. */
  sourceLocationRefs?: SourceLocationRef[];
}

export interface SignalRecord {
  id: string;
  surface: string;
  confidence: number;
  status: string;
  description: string;
  relatedAssets?: string[];
}

export interface AssessmentItemRecord {
  title: string;
  severity: string;
  description: string;
  evidenceRefs: string[];
  requiredConditions: string[];
  /** Section 7.1 — file:line source refs supporting this assessment item. */
  sourceLocationRefs?: SourceLocationRef[];
}

export interface SuppressedClaimRecord {
  claim: string;
  reason: string;
  evidenceRefs: string[];
}

export interface ExecutiveAssessmentRecord {
  overallVerdict: string;
  confidence: number;
  summary: string;
  confirmedVulnerabilities: AssessmentItemRecord[];
  validatedRisks: AssessmentItemRecord[];
  configurationRisks: AssessmentItemRecord[];
  unconfirmedLeads: AssessmentItemRecord[];
  suppressedClaims: SuppressedClaimRecord[];
  nextActions: string[];
  source: string;
  reviewerModels: string[];
  synthesizerModel?: string | null;
  parseStatus?: string;
}

export interface CoverageGapRecord {
  lane: string;
  code: string;
  message: string;
  severity: ExecutionStatusRecord;
  required?: boolean;
}

export interface ChildCampaignRecord {
  lane: string;
  campaignId: string;
  status: string;
  targetId?: string | null;
  runDir?: string;
  sourceCampaignId?: string;
  totalCostUsd?: number;
  durationMs?: number;
}

export interface VerificationLaneRecord {
  attempted: number;
  meaningfulAttempts: number;
  confirmed: number;
  refuted: number;
  inconclusive: number;
  blocked: number;
  skipped: number;
  authFailed: number;
  notApplicable: number;
  notAuthorized: number;
  rateLimited: number;
  autoStopped: number;
  timeout: number;
  runtimeError: number;
  compileError: number;
  costUsd: number;
  durationMs: number;
  status: ExecutionStatusRecord;
  required: boolean;
  coverageGaps: string[];
  notes?: string[];
  auditTrailPath?: string;
  childCampaigns?: ChildCampaignRecord[];
  confirmedRisk?: number;
  needsReview?: number;
  approvedDrift?: number;
  runs?: number;
  degraded?: number;
  harmfulSeen?: number;
  /** Section 6.1 — probe origin breakdown for the local-live lane. */
  adaptiveProbes?: {
    hypothesis: { attempted: number; confirmed: number; refuted: number; inconclusive: number };
    adaptive: { attempted: number; confirmed: number; refuted: number; inconclusive: number };
    canary: { attempted: number; matchedSafe: number; matchedExploitable: number };
    surprisesDetected: number;
    followupsGenerated: number;
    midRoundHypothesesSynthesized: number;
  };
  /** Section 11.4 — sequence and identity-differential execution tally. */
  sequenceExecution?: SequenceExecutionSummaryRecord;
  /** Section 6.2 — Mythos creativity sub-lane tally. */
  mythos?: {
    enabled: boolean;
    invocations: number;
    probesExecuted: number;
    hypothesesProposed: number;
    findingsProposed: number;
    findingsRejected: number;
    nonHypothesisProbes: number;
    budgetExhausted: 'probe_budget_exhausted' | 'time_budget_exhausted' | null;
    sourceCorrelations: number;
    sourceRefsCollected: number;
  };
  /** Section 12.2 — browser exploit family coverage for the browser lane. */
  browserExploitFamilies?: BrowserExploitFamilySummaryRecord;
}

export interface LaneStatRecord {
  attempted: number;
  meaningfulAttempts: number;
  status: ExecutionStatusRecord;
}

export interface ModelActivityRecord {
  role: string;
  provider: string;
  model: string;
  calls: number;
  costUsd: number;
}

// ---------------------------------------------------------------------------
// Renderer
// ---------------------------------------------------------------------------

export function renderInvestigationReport(data: InvestigationReportData): string {
  const sections: string[] = [
    renderHeader(data),
    renderRunModeSection(data),
    renderExecutionStatusSection(data),
    renderTargetCoverage(data),
    renderSummary(data),
    renderExecutiveAssessment(data),
    renderPortfolio(data),
    renderVerification(data),
    renderProbeCoverageGaps(data),
    renderEntityInventorySummary(data),
    renderProbeFamilyCoverage(data),
    renderAssertionClassificationSummary(data),
    renderSequenceExecutionSummary(data),
    renderBrowserExploitFamilySummary(data),
    renderFocusedLeadConfirmationSummary(data),
    renderFindings(data),
    renderAssessmentBreakdown(data),
    renderDormantLineage(data),
    renderSignals(data),
    renderRefuted(data),
    renderTelemetry(data),
    renderFooter(),
  ];

  return sections.filter((s) => s.length > 0).join('\n\n---\n\n');
}

function renderHeader(data: InvestigationReportData): string {
  return `# Security Lab Investigation Report

**Campaign:** ${escapeMarkdownLine(data.campaignId)}
**Target:** ${escapeMarkdownLine(data.targetLabel)} (${escapeMarkdownLine(data.targetId)})
**Kind:** ${escapeMarkdownLine(data.targetKind)}
**Environment:** ${escapeMarkdownLine(data.environment)}
**Mode:** ${escapeMarkdownLine(data.mode)}
**Started:** ${escapeMarkdownLine(data.startedAt)}
**Completed:** ${escapeMarkdownLine(data.completedAt)}
**Iterations:** ${data.iterations}
**Total Cost:** $${data.totalCostUsd.toFixed(4)}`;
}

/**
 * Section 3.2 — prominent run-mode banner.
 *
 * Always visible so an operator can immediately tell what rigor level this run
 * committed to. A serious run is trustworthy to act on; a smoke run is not.
 */
function renderRunModeSection(data: InvestigationReportData): string {
  const mode = data.runMode ?? 'smoke';
  const description =
    mode === 'smoke'
      ? 'Low-ceremony run. Degrades honestly when prerequisites are missing. Do not act on findings without a serious run.'
      : mode === 'serious-local'
        ? 'High-ceremony run. Fails closed on missing local verification coverage.'
        : 'High-ceremony run. Fails closed on missing local or hosted verification coverage.';
  return `## Run Mode

**Run mode:** ${renderCodeSpan(mode)}

${description}`;
}

/**
 * Section 3.2 — prominent execution-status banner.
 *
 * Always visible and kept separate from the security verdict so that
 * `executionStatus` can never be confused with `overallVerdict`.
 */
function renderExecutionStatusSection(data: InvestigationReportData): string {
  const status = data.executionStatus ?? 'complete';
  const lines: string[] = ['## Execution Status', ''];
  lines.push(`**Execution status:** ${renderCodeSpan(status)}`);
  lines.push('');
  lines.push('_This is a run-integrity signal, not a security verdict. The overall security finding verdict is reported separately in the Executive Assessment section._');

  if (status === 'complete') {
    lines.push('');
    lines.push('### Coverage confirmation');
    if (data.coverageGaps && data.coverageGaps.length > 0) {
      lines.push('All required verification coverage was satisfied. Minor non-required gaps:');
      for (const gap of data.coverageGaps) {
        lines.push(`- [${escapeMarkdownLine(gap.severity)}] ${escapeMarkdownLine(gap.lane)}: ${escapeMarkdownBlock(gap.message)}`);
      }
    } else {
      lines.push('All required verification coverage was satisfied. No coverage gaps recorded.');
    }
  } else {
    lines.push('');
    lines.push("### What's missing");
    if (data.coverageGaps && data.coverageGaps.length > 0) {
      for (const gap of data.coverageGaps) {
        const requiredTag = gap.required === false ? '' : ' (required)';
        lines.push(`- [${escapeMarkdownLine(gap.severity)}] ${escapeMarkdownLine(gap.lane)}${requiredTag}: ${escapeMarkdownBlock(gap.message)}`);
      }
    } else {
      lines.push('- Execution status is not complete but no structured coverage gaps were recorded. Inspect the evidence events (events.jsonl) for stage-level failures.');
    }
  }

  return lines.join('\n');
}

function renderTargetCoverage(data: InvestigationReportData): string {
  if (!data.targetCoverage || data.targetCoverage.coverage === 'full') {
    return '';
  }

  const { coverage, supportedProbeKinds, detectedStack } = data.targetCoverage;
  const lines = ['## Target Coverage', ''];
  lines.push(`**Coverage: ${escapeMarkdownLine(coverage)}**`);
  lines.push('');

  if (detectedStack) {
    lines.push(`Detected stack: ${escapeMarkdownLine(detectedStack.language)}/${escapeMarkdownLine(detectedStack.framework)}`);
    lines.push(`Manifest files: ${detectedStack.manifestFiles.map((file) => escapeMarkdownLine(file)).join(', ')}`);
    lines.push('');
  }

  if (supportedProbeKinds.length > 0) {
    lines.push('Supported probe kinds:');
    for (const kind of supportedProbeKinds) {
      lines.push(`- ${escapeMarkdownLine(kind)}`);
    }
    lines.push('');
  }

  if (coverage === 'partial') {
    lines.push('This is a non-Node target. Only dependency scanning is fully supported. Route extraction, auth detection, and config scanning are not available for this stack. See docs/TARGET-ONBOARDING.md for details.');
  } else if (coverage === 'manifest-only') {
    lines.push('Manifest files were detected but no dependencies could be parsed. Only manifest presence is known.');
  } else if (coverage === 'none') {
    lines.push('No recognizable stack or manifest files were found. The scanner could not extract meaningful surface data from this target.');
  }

  return lines.join('\n');
}

function renderSummary(data: InvestigationReportData): string {
  const lines = [
    '## Summary',
    '',
    '| Metric | Value |',
    '|--------|-------|',
    `| Signals found | ${data.signalsFound} |`,
    `| Signals dormant | ${data.signalsDormant} |`,
    `| Dormant signals reactivated | ${data.signalsReactivated} |`,
    `| Hypotheses tested | ${data.hypothesesTested} |`,
    `| Composed chains tested | ${data.chainHypothesesTested} |`,
    `| Direct hypotheses tested | ${data.directHypothesesTested} |`,
    `| Chains confirmed | ${data.hypothesesConfirmed} |`,
    `| Chains refuted | ${data.hypothesesRefuted} |`,
    `| Longest composed chain | ${data.maxChainLength > 0 ? data.maxChainLength : 'N/A'} |`,
    `| Chain length distribution | ${formatChainLengthDistribution(data.chainLengthDistribution)} |`,
  ];

  if (data.executiveAssessment) {
    const summaryVerdict =
      data.executionStatus && data.executionStatus !== 'complete' && data.executiveAssessment.overallVerdict === 'no_material_findings'
        ? 'provisional — execution incomplete or degraded'
        : formatVerdictLabel(data.executiveAssessment.overallVerdict);
    lines.push(`| Executive verdict | ${escapeMarkdownLine(summaryVerdict)} |`);
    lines.push(`| Campaign-level confirmed vulnerabilities | ${data.executiveAssessment.confirmedVulnerabilities.length} |`);
  }
  if (data.executionStatus) {
    lines.push(`| Execution status | ${escapeMarkdownLine(data.executionStatus)} |`);
  }
  if (data.requiredCoverageSatisfied != null) {
    lines.push(`| Required coverage satisfied | ${data.requiredCoverageSatisfied ? 'yes' : 'no'} |`);
  }
  if (data.meaningfulAttempts != null) {
    lines.push(`| Meaningful verification attempts | ${data.meaningfulAttempts} |`);
  }

  lines.push(`| Total cost | $${data.totalCostUsd.toFixed(4)} |`);
  if (data.endToEndCostUsd != null) {
    lines.push(`| End-to-end cost | $${data.endToEndCostUsd.toFixed(4)} |`);
  }
  if (data.endToEndDurationMs != null) {
    lines.push(`| End-to-end duration | ${formatDuration(data.endToEndDurationMs)} |`);
  }
  lines.push(`| Cost per finding | $${data.hypothesesConfirmed > 0 ? (data.totalCostUsd / data.hypothesesConfirmed).toFixed(4) : 'N/A'} |`);
  return lines.join('\n');
}

function renderPortfolio(data: InvestigationReportData): string {
  const lines = ['## Portfolio & Context', ''];

  lines.push(`Portfolio: ${escapeMarkdownLine(data.portfolioId ?? 'default')}`);
  if (data.plannerModel) lines.push(`Planner: ${escapeMarkdownLine(data.plannerModel)}`);
  if (data.judgeModel) lines.push(`Judge: ${escapeMarkdownLine(data.judgeModel)}`);
  if (data.judgePanelModels && data.judgePanelModels.length > 0) {
    lines.push(`Judge panel: ${data.judgePanelModels.map((model) => escapeMarkdownLine(model)).join(', ')}`);
  }
  if (data.synthesizerModel) lines.push(`Synthesizer: ${escapeMarkdownLine(data.synthesizerModel)}`);
  lines.push(`Prior knowledge consulted: ${data.priorKnowledgeUsed ? 'yes' : 'no'}`);
  if (data.knowledgeBasePath) lines.push(`Knowledge base: ${escapeMarkdownLine(data.knowledgeBasePath)}`);
  if (data.executiveAssessment) {
    lines.push(`Assessment source: ${escapeMarkdownLine(data.executiveAssessment.source)}`);
  }

  if (data.liveConfirmation) {
    lines.push('');
    lines.push('### Live Confirmation');
    lines.push(`Enabled: ${data.liveConfirmation.enabled ? 'yes' : 'no'}`);
    lines.push(`Status: ${escapeMarkdownLine(data.liveConfirmation.status)}`);
    lines.push(`Target: ${escapeMarkdownLine(data.liveConfirmation.targetId ?? 'N/A')}`);
    lines.push(`Confirmed findings: ${data.liveConfirmation.confirmedFindings}`);
    if (data.liveConfirmation.totalCostUsd != null) {
      lines.push(`Cost: $${data.liveConfirmation.totalCostUsd.toFixed(4)}`);
    }
    if (data.liveConfirmation.durationMs != null) {
      lines.push(`Duration: ${formatDuration(data.liveConfirmation.durationMs)}`);
    }
    if (data.liveConfirmation.runDir) {
      lines.push(`Run dir: ${escapeMarkdownLine(data.liveConfirmation.runDir)}`);
    }
  }

  if (data.childCampaigns && data.childCampaigns.length > 0) {
    lines.push('');
    lines.push('### Child Campaigns');
    for (const child of data.childCampaigns) {
      const parts = [
        `${escapeMarkdownLine(child.lane)}: ${escapeMarkdownLine(child.campaignId)}`,
        `status=${escapeMarkdownLine(child.status)}`,
      ];
      if (child.targetId) parts.push(`target=${escapeMarkdownLine(child.targetId)}`);
      if (child.totalCostUsd != null) parts.push(`cost=$${child.totalCostUsd.toFixed(4)}`);
      if (child.durationMs != null) parts.push(`duration=${formatDuration(child.durationMs)}`);
      lines.push(`- ${parts.join(', ')}`);
      if (child.runDir) {
        lines.push(`  Run dir: ${escapeMarkdownLine(child.runDir)}`);
      }
    }
  }

  if (data.modelActivity && data.modelActivity.length > 0) {
    lines.push('');
    lines.push('### Activated Model Activity');
    lines.push('');
    lines.push('| Role | Model | Calls | Cost |');
    lines.push('|------|-------|-------|------|');
    for (const activity of data.modelActivity) {
      lines.push(
        `| ${escapeMarkdownLine(activity.role)} | ` +
          `${escapeMarkdownLine(activity.provider)}/${escapeMarkdownLine(activity.model)} | ` +
          `${activity.calls} | $${activity.costUsd.toFixed(4)} |`,
      );
    }
  }

  return lines.join('\n');
}

function renderVerification(data: InvestigationReportData): string {
  if (!data.verificationLanes) {
    return '';
  }

  const lines = ['## Verification Lanes', ''];
  const { verificationLanes } = data;
  if (verificationLanes.executionStatus) {
    lines.push(`Execution status: ${escapeMarkdownLine(verificationLanes.executionStatus)}`);
  }
  if (verificationLanes.requiredCoverageSatisfied != null) {
    lines.push(`Required coverage satisfied: ${verificationLanes.requiredCoverageSatisfied ? 'yes' : 'no'}`);
  }
  if (verificationLanes.meaningfulAttempts != null) {
    lines.push(`Meaningful attempts: ${verificationLanes.meaningfulAttempts}`);
  }
  appendLane(lines, 'Test synthesis', verificationLanes.testSynthesis);
  appendLane(lines, 'Local live', verificationLanes.localLive);
  // Section 8.2 — monitoring stress is now a subsection of local-live.
  // The runs/degraded/harmfulSeen fields on localLive carry the data.
  // For backward compat, render any legacy standalone monitoringStress
  // lane from pre-8.2 campaigns.
  if (verificationLanes.monitoringStress && !verificationLanes.localLive) {
    appendLane(lines, 'Monitoring stress (legacy)', verificationLanes.monitoringStress);
  }
  appendLane(lines, 'Browser', verificationLanes.browser);
  appendLane(lines, 'Hosted', verificationLanes.hosted);
  appendLane(lines, 'Supply chain', verificationLanes.supplyChain);
  if (verificationLanes.coverageGaps && verificationLanes.coverageGaps.length > 0) {
    lines.push('');
    lines.push('### Coverage Gaps');
    for (const gap of verificationLanes.coverageGaps) {
      lines.push(`- [${escapeMarkdownLine(gap.severity)}] ${escapeMarkdownLine(gap.lane)}: ${escapeMarkdownBlock(gap.message)}`);
    }
  }
  if (verificationLanes.experimentsPath) {
    lines.push(`Verification experiments: ${escapeMarkdownLine(verificationLanes.experimentsPath)}`);
  }
  return lines.join('\n');
}

function renderExecutiveAssessment(data: InvestigationReportData): string {
  const assessment = data.executiveAssessment;
  if (!assessment) {
    if (data.findings.length === 0) {
      return `## Executive Assessment

No confirmed vulnerabilities were produced by this run. Treat the remaining sections as investigative evidence and unconfirmed leads, not as a final security verdict.`;
    }

    return `## Executive Assessment

The run produced confirmed findings. Review the findings section for details.`;
  }

  const lines = ['## Executive Assessment', ''];
  const verdictLabel =
    data.executionStatus && data.executionStatus !== 'complete' && assessment.overallVerdict === 'no_material_findings'
      ? 'provisional — execution incomplete or degraded'
      : formatVerdictLabel(assessment.overallVerdict);
  lines.push(`Outcome: ${escapeMarkdownLine(verdictLabel)}`);
  lines.push(`Confidence: ${assessment.confidence.toFixed(2)}`);
  lines.push(`Summary: ${escapeMarkdownBlock(assessment.summary)}`);
  if (data.executionStatus) {
    lines.push(`Execution status: ${escapeMarkdownLine(data.executionStatus)}`);
  }
  if (data.assessmentParseStatus) {
    lines.push(`Assessment parse status: ${escapeMarkdownLine(data.assessmentParseStatus)}`);
  }
  if (assessment.reviewerModels.length > 0) {
    lines.push(`Reviewer models: ${assessment.reviewerModels.map((model) => escapeMarkdownLine(model)).join(', ')}`);
  }
  if (assessment.synthesizerModel) {
    lines.push(`Final synthesizer: ${escapeMarkdownLine(assessment.synthesizerModel)}`);
  }
  lines.push('');
  lines.push('Interpretation guard: weak signals and tested chains below are evidence inputs. Only "Findings" and "Assessment Breakdown" carry campaign-level verdict weight.');
  if (data.executionStatus && data.executionStatus !== 'complete' && data.coverageGaps && data.coverageGaps.length > 0) {
    lines.push('');
    lines.push('Execution gaps prevented a fully closed verification result:');
    for (const gap of data.coverageGaps) {
      lines.push(`- [${escapeMarkdownLine(gap.severity)}] ${escapeMarkdownLine(gap.lane)}: ${escapeMarkdownBlock(gap.message)}`);
    }
  }
  return lines.join('\n');
}

function renderFindings(data: InvestigationReportData): string {
  const assessment = data.executiveAssessment;

  if (assessment) {
    const lines = ['## Confirmed Vulnerabilities', ''];
    if (assessment.confirmedVulnerabilities.length === 0) {
      lines.push('No campaign-level confirmed vulnerabilities.');
      if (data.findings.length > 0) {
        lines.push('');
        lines.push('### Runner-Level Candidate Findings (Not Upheld By Final Assessment)');
        lines.push('These candidate findings were generated during the run but were not upheld by the campaign-level report review.');
        for (const finding of data.findings) {
          const dormant = finding.involvedDormantReactivation ? ' (involved dormant reactivation)' : '';
          lines.push(
            `- **[${escapeMarkdownLine(finding.severity.toUpperCase())}]** ` +
              `${escapeMarkdownLine(finding.description.split('\n')[0] ?? '')}${dormant}`,
          );
          lines.push(`  Remediation: ${escapeMarkdownBlock(finding.remediationSuggestion)}`);
          lines.push(`  Confirmed at runner stage: ${escapeMarkdownLine(finding.confirmedAt)}`);
        }
      }
      return lines.join('\n');
    }

    for (const item of assessment.confirmedVulnerabilities) {
      lines.push(`### [${escapeMarkdownLine(item.severity.toUpperCase())}] ${escapeMarkdownLine(item.title)}`);
      lines.push('');
      lines.push(escapeMarkdownBlock(item.description));
      if (item.requiredConditions.length > 0) {
        lines.push('');
        lines.push(`**Conditions:** ${item.requiredConditions.map((condition) => escapeMarkdownBlock(condition)).join('; ')}`);
      }
      if (item.evidenceRefs.length > 0) {
        lines.push(`**Evidence refs:** ${item.evidenceRefs.map((ref) => escapeMarkdownLine(ref)).join(', ')}`);
      }
      renderCitedSource(lines, item.sourceLocationRefs);
      lines.push('');
    }
    return lines.join('\n');
  }

  if (data.findings.length === 0) {
    return '## Findings\n\nNo confirmed findings.';
  }

  const lines = ['## Findings', ''];
  const sorted = [...data.findings].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));

  for (const f of sorted) {
    const dormant = f.involvedDormantReactivation ? ' (involved dormant reactivation)' : '';
    lines.push(`### [${escapeMarkdownLine(f.severity.toUpperCase())}] ${escapeMarkdownLine(f.description.split('\n')[0] ?? '')}${dormant}`);
    lines.push('');
    lines.push(escapeMarkdownBlock(f.description));
    lines.push('');
    lines.push('**Reproduction steps:**');
    for (const step of f.reproductionSteps) {
      lines.push(`1. ${escapeMarkdownBlock(step)}`);
    }
    lines.push('');
    lines.push(`**Remediation:** ${escapeMarkdownBlock(f.remediationSuggestion)}`);
    lines.push(`**Confirmed:** ${escapeMarkdownLine(f.confirmedAt)}`);
    renderCitedSource(lines, f.sourceLocationRefs);
    lines.push('');
  }

  return lines.join('\n');
}

function renderAssessmentBreakdown(data: InvestigationReportData): string {
  const assessment = data.executiveAssessment;
  if (!assessment) {
    return '';
  }

  const sections: string[] = ['## Assessment Breakdown'];

  sections.push(renderAssessmentItems('Validated Architectural Risks', assessment.validatedRisks, 'No validated architectural risks.'));
  sections.push(renderAssessmentItems('Configuration-Sensitive Risks', assessment.configurationRisks, 'No configuration-sensitive risks.'));
  sections.push(renderAssessmentItems('High-Priority Unconfirmed Leads', assessment.unconfirmedLeads, 'No high-priority unconfirmed leads.'));
  sections.push(renderSuppressedClaims(assessment.suppressedClaims));

  if (assessment.nextActions.length > 0) {
    sections.push('### Recommended Next Actions');
    for (const action of assessment.nextActions) {
      sections.push(`- ${escapeMarkdownBlock(action)}`);
    }
  }

  return sections.join('\n\n');
}

function renderSignals(data: InvestigationReportData): string {
  if (data.topSignals.length === 0) {
    return '## Evidence Leads\n\nNo active signals.';
  }

  const lines = ['## Evidence Leads (Top 20 — not final verdicts)', ''];
  for (const s of data.topSignals.slice(0, 20)) {
    const assets = s.relatedAssets && s.relatedAssets.length > 0
      ? ` | assets=${s.relatedAssets.map((asset) => escapeMarkdownLine(asset)).join(', ')}`
      : '';
    lines.push(
      `- **[${escapeMarkdownLine(s.id)}]** (${escapeMarkdownLine(s.surface)}, conf=${s.confidence.toFixed(2)}, ` +
        `${escapeMarkdownLine(s.status)}) ${escapeMarkdownBlock(s.description)}${assets}`,
    );
  }

  return lines.join('\n');
}

function renderDormantLineage(data: InvestigationReportData): string {
  const lines = ['## Dormant Signal Lineage', ''];

  if (data.signalsReactivated === 0) {
    lines.push('No dormant signals were reactivated during this campaign.');
    return lines.join('\n');
  }

  lines.push(`**${data.signalsReactivated}** dormant signal(s) were reopened during this campaign.`);
  lines.push('');

  // Show findings that involved dormant reactivation
  const dormantFindings = data.findings.filter((f) => f.involvedDormantReactivation);
  if (dormantFindings.length > 0) {
    lines.push('### Findings From Reopened Signals');
    for (const f of dormantFindings) {
      lines.push(
        `- **[${escapeMarkdownLine(f.severity.toUpperCase())}]** ` +
          `${escapeMarkdownLine(f.description.split('\n')[0] ?? '')}`,
      );
      lines.push(`  Confirmed: ${escapeMarkdownLine(f.confirmedAt)}`);
    }
    lines.push('');
  }

  // Show reopened signals that contributed to active hypotheses
  const reopenedSignals = data.topSignals.filter((s) => s.status === 'reopened');
  if (reopenedSignals.length > 0) {
    lines.push('### Reopened Signals Still Active');
    for (const s of reopenedSignals) {
      lines.push(
        `- **[${escapeMarkdownLine(s.id)}]** (${escapeMarkdownLine(s.surface)}, ` +
          `conf=${s.confidence.toFixed(2)}) ${escapeMarkdownBlock(s.description)}`,
      );
    }
  }

  return lines.join('\n');
}

function renderRefuted(data: InvestigationReportData): string {
  if (data.refutedHypotheses.length === 0) {
    return '## What Was Tried And Failed\n\nNo refuted hypotheses.';
  }

  const lines = ['## What Was Tried And Failed', '', 'These chains were tested and not confirmed in this run. Do not report them as findings without further evidence.', ''];
  for (const h of data.refutedHypotheses.slice(0, 20)) {
    lines.push(`- ${escapeMarkdownBlock(h)}`);
  }

  return lines.join('\n');
}

function renderTelemetry(data: InvestigationReportData): string {
  return `## Cost & Telemetry\n\n${escapeMarkdownBlock(data.telemetrySummary)}`;
}

function renderProbeCoverageGaps(data: InvestigationReportData): string {
  if (!data.probeCoverageGaps || data.probeCoverageGaps.length === 0) {
    return '';
  }

  const totalGaps = data.probeCoverageGaps.reduce((sum, g) => sum + g.count, 0);
  const lines = [
    '## Probe-Level Coverage Gaps',
    '',
    `**Coverage gaps: ${totalGaps}**`,
    '',
    'These gaps indicate probes that could not execute for a specific reason. They are NOT findings and NOT refutations — they show what was observed but could not be tested.',
    '',
    '| Reason | Count | Remediation |',
    '|--------|-------|-------------|',
  ];

  for (const gap of data.probeCoverageGaps) {
    const hint = COVERAGE_GAP_REMEDIATION_HINTS[gap.code as CoverageGapReasonCode] ?? 'No remediation hint available.';
    lines.push(`| ${renderCodeSpan(gap.code)} | ${gap.count} | ${hint} |`);
  }

  return lines.join('\n');
}

/**
 * Section 11.1 — render the entity inventory summary.
 */
function renderEntityInventorySummary(data: InvestigationReportData): string {
  if (!data.entityInventorySummary) {
    return '';
  }
  const inv = data.entityInventorySummary;
  if (inv.totalEntries === 0 && inv.unresolvedParameters.length === 0) {
    return '';
  }

  const lines = [
    '## Entity Inventory',
    '',
    `**Total entities: ${inv.totalEntries}**`,
    '',
  ];

  if (Object.keys(inv.byKind).length > 0) {
    lines.push('| Kind | Count |');
    lines.push('|------|-------|');
    for (const [kind, count] of Object.entries(inv.byKind)) {
      lines.push(`| ${renderCodeSpan(kind)} | ${count} |`);
    }
    lines.push('');
  }

  if (Object.keys(inv.byProvenance).length > 0) {
    lines.push('| Provenance | Count |');
    lines.push('|------------|-------|');
    for (const [prov, count] of Object.entries(inv.byProvenance)) {
      lines.push(`| ${renderCodeSpan(prov)} | ${count} |`);
    }
    lines.push('');
  }

  if (inv.unresolvedParameters.length > 0) {
    lines.push(`**Unresolved parameters:** ${inv.unresolvedParameters.map((p) => renderCodeSpan(p)).join(', ')}`);
    lines.push('');
    lines.push('Probes requiring these parameters were degraded to coverage gaps and not counted as meaningful attempts.');
    lines.push('');
  }

  return lines.join('\n');
}

/**
 * Section 11.2 — render probe family coverage summary.
 */
function renderProbeFamilyCoverage(data: InvestigationReportData): string {
  if (!data.probeFamilyCoverage) {
    return '';
  }
  const cov = data.probeFamilyCoverage;
  if (cov.totalFamilyProbes === 0) {
    return '';
  }

  const lines = [
    '## Probe Family Coverage',
    '',
    `**Total family-shaped probes: ${cov.totalFamilyProbes}**`,
    '',
  ];

  const families = Object.entries(cov.byFamily);
  if (families.length > 0) {
    lines.push('| Family | Probes | Variants Exercised |');
    lines.push('|--------|--------|--------------------|');
    for (const [family, info] of families) {
      const variantList = info.variants.length > 0
        ? info.variants.map((v) => renderCodeSpan(v)).join(', ')
        : '_none_';
      lines.push(`| ${renderCodeSpan(family)} | ${info.probes} | ${variantList} |`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

/**
 * Section 11.3 — render assertion-based classification summary.
 */
function renderAssertionClassificationSummary(data: InvestigationReportData): string {
  if (!data.assertionClassification) {
    return '';
  }
  const cls = data.assertionClassification;
  if (cls.totalClassified === 0) {
    return '';
  }

  const lines = [
    '## Assertion-Based Classification',
    '',
    `**Total classified: ${cls.totalClassified}** | **Suppressed (non-meaningful): ${cls.suppressedCount}**`,
    '',
  ];

  const reasons = Object.entries(cls.byReason);
  if (reasons.length > 0) {
    lines.push('| Classification Reason | Count |');
    lines.push('|-----------------------|-------|');
    for (const [reason, count] of reasons) {
      lines.push(`| ${renderCodeSpan(reason)} | ${count} |`);
    }
    lines.push('');
  }

  const routeKinds = Object.entries(cls.byRouteKind);
  if (routeKinds.length > 0) {
    lines.push('| Route Kind | Count |');
    lines.push('|------------|-------|');
    for (const [kind, count] of routeKinds) {
      lines.push(`| ${renderCodeSpan(kind)} | ${count} |`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

/**
 * Section 11.4 — render sequence and identity-differential execution summary.
 */
function renderSequenceExecutionSummary(data: InvestigationReportData): string {
  if (!data.sequenceExecution) {
    return '';
  }
  const seq = data.sequenceExecution;
  if (seq.sequencesExecuted === 0 && seq.differentialsExecuted === 0) {
    return '';
  }

  const lines = [
    '## Sequence & Identity-Differential Execution',
    '',
  ];

  if (seq.sequencesExecuted > 0) {
    lines.push(`**Multi-step sequences: ${seq.sequencesExecuted}** (${seq.totalStepsExecuted} total steps)`);
    lines.push('');
    lines.push('| Metric | Count |');
    lines.push('|--------|-------|');
    lines.push(`| Confirmed | ${seq.sequencesConfirmed} |`);
    lines.push(`| Refuted | ${seq.sequencesRefuted} |`);
    lines.push(`| Inconclusive | ${seq.sequencesInconclusive} |`);
    lines.push(`| State passthrough (step→step) | ${seq.statePassthroughCount} |`);
    lines.push(`| Rollbacks executed | ${seq.rollbacksExecuted} |`);
    lines.push('');
  }

  if (seq.differentialsExecuted > 0) {
    lines.push(`**Identity differentials: ${seq.differentialsExecuted}** | Privilege escalation detected: ${seq.differentialsWithEscalation}`);
    lines.push('');
  }

  return lines.join('\n');
}

/**
 * Section 12.2 — browser exploit family coverage summary.
 */
function renderBrowserExploitFamilySummary(data: InvestigationReportData): string {
  const summary = data.browserExploitFamilies;
  if (!summary || summary.totalBrowserProbes === 0) {
    return '';
  }

  const lines = [
    '## Browser Exploit Family Coverage',
    '',
    `**Total browser-native probes: ${summary.totalBrowserProbes}**`,
    '',
    '| Family | Probes | Variants | Confirmed | Refuted | Inconclusive |',
    '|--------|--------|----------|-----------|---------|--------------|',
  ];

  for (const [familyId, entry] of Object.entries(summary.byFamily)) {
    lines.push(
      `| ${escapeMarkdownLine(familyId)} | ${entry.probes} | ` +
        `${entry.variants.map((variant) => escapeMarkdownLine(variant)).join(', ')} | ` +
        `${entry.confirmed} | ${entry.refuted} | ${entry.inconclusive} |`,
    );
  }
  lines.push('');

  return lines.join('\n');
}

/**
 * Section 11.5 — Focused lead confirmation summary.
 */
function renderFocusedLeadConfirmationSummary(data: InvestigationReportData): string {
  const summary = data.focusedLeadConfirmation;
  if (!summary || summary.sessionsRun === 0) {
    return '';
  }

  const lines = [
    '## Focused Lead Confirmation',
    '',
    `**Sessions:** ${summary.sessionsRun} | **Total probes:** ${summary.totalProbesExecuted}`,
    '',
    '| Status | Count |',
    '|--------|-------|',
    `| Confirmed | ${summary.confirmed} |`,
    `| Refuted | ${summary.refuted} |`,
    `| Narrowed | ${summary.narrowed} |`,
    `| Needs browser | ${summary.needsBrowser} |`,
    `| Needs human setup | ${summary.needsHumanSetup} |`,
    `| Insufficient evidence | ${summary.insufficientEvidence} |`,
    '',
  ];

  if (summary.leads.length > 0) {
    lines.push('### Per-Lead Results');
    lines.push('');
    lines.push('| Rank | Hypothesis | Severity | Family | Status | Probes |');
    lines.push('|------|-----------|----------|--------|--------|--------|');
    for (const lead of summary.leads) {
      lines.push(
        `| ${lead.rank} | ${escapeMarkdownLine(lead.hypothesisId)} | ${escapeMarkdownLine(lead.severity)} | ` +
          `${escapeMarkdownLine(lead.probeFamily)} | ${escapeMarkdownLine(lead.status)} | ${lead.totalProbes} |`,
      );
    }
    lines.push('');
  }

  return lines.join('\n');
}

/**
 * Section 7.1 — render a "Cited source" subsection for source location refs.
 */
function renderCitedSource(lines: string[], refs?: SourceLocationRef[]): void {
  if (!refs || refs.length === 0) return;
  lines.push('');
  lines.push('**Cited source:**');
  for (const ref of refs) {
    lines.push(`- ${renderCodeSpan(formatSourceRef(ref))}`);
  }
}

function renderFooter(): string {
  return `*Generated by Security Lab autonomous investigator.*`;
}

function formatChainLengthDistribution(distribution: Record<string, number>): string {
  const entries = Object.entries(distribution)
    .map(([length, count]) => [Number(length), count] as const)
    .sort((left, right) => left[0] - right[0]);

  if (entries.length === 0) {
    return 'N/A';
  }

  return entries.map(([length, count]) => `${length}:${count}`).join(', ');
}

function appendLane(lines: string[], label: string, lane?: VerificationLaneRecord): void {
  if (!lane) {
    return;
  }

  lines.push('');
  lines.push(`### ${label}`);
  lines.push(`Status: ${escapeMarkdownLine(lane.status)}${lane.required ? ' (required)' : ''}`);
  lines.push(`Attempts: ${lane.attempted} total, ${lane.meaningfulAttempts} meaningful`);
  lines.push(`Confirmed: ${lane.confirmed} | Refuted: ${lane.refuted} | Inconclusive: ${lane.inconclusive}`);
  lines.push(`Blocked: ${lane.blocked} | Skipped: ${lane.skipped} | Auth failed: ${lane.authFailed} | Not authorized: ${lane.notAuthorized} | Not applicable: ${lane.notApplicable}`);
  if (lane.rateLimited > 0 || lane.autoStopped > 0 || lane.timeout > 0 || lane.compileError > 0 || lane.runtimeError > 0) {
    lines.push(`Rate limited: ${lane.rateLimited} | Auto-stopped: ${lane.autoStopped} | Timeout: ${lane.timeout} | Compile error: ${lane.compileError} | Runtime error: ${lane.runtimeError}`);
  }
  if (lane.confirmedRisk != null || lane.needsReview != null || lane.approvedDrift != null) {
    lines.push(`Confirmed risk: ${lane.confirmedRisk ?? 0} | Needs review: ${lane.needsReview ?? 0} | Approved drift: ${lane.approvedDrift ?? 0}`);
  }
  if (lane.runs != null || lane.degraded != null || lane.harmfulSeen != null) {
    lines.push(`Runs: ${lane.runs ?? 0} | Monitoring degraded: ${lane.degraded ?? 0} | Harmful seen: ${lane.harmfulSeen ?? 0}`);
  }
  if (lane.adaptiveProbes) {
    const ap = lane.adaptiveProbes;
    lines.push(
      `Probe origins — hypothesis: ${ap.hypothesis.attempted} (confirmed ${ap.hypothesis.confirmed}, refuted ${ap.hypothesis.refuted}, inconclusive ${ap.hypothesis.inconclusive}) | adaptive: ${ap.adaptive.attempted} (confirmed ${ap.adaptive.confirmed}, refuted ${ap.adaptive.refuted}, inconclusive ${ap.adaptive.inconclusive}) | canary: ${ap.canary.attempted} (safe ${ap.canary.matchedSafe}, exploitable ${ap.canary.matchedExploitable})`,
    );
    lines.push(
      `Adaptive exploration — surprises detected: ${ap.surprisesDetected} | follow-ups generated: ${ap.followupsGenerated} | mid-round hypotheses: ${ap.midRoundHypothesesSynthesized}`,
    );
  }
  if (lane.sequenceExecution) {
    const se = lane.sequenceExecution;
    if (se.sequencesExecuted > 0 || se.differentialsExecuted > 0) {
      const parts: string[] = [];
      if (se.sequencesExecuted > 0) {
        parts.push(`sequences: ${se.sequencesExecuted} (${se.totalStepsExecuted} steps, confirmed ${se.sequencesConfirmed}, refuted ${se.sequencesRefuted}, state-passthrough ${se.statePassthroughCount}, rollbacks ${se.rollbacksExecuted})`);
      }
      if (se.differentialsExecuted > 0) {
        parts.push(`identity differentials: ${se.differentialsExecuted} (escalation detected ${se.differentialsWithEscalation})`);
      }
      lines.push(`Sequence execution — ${parts.join(' | ')}`);
    }
  }
  if (lane.mythos) {
    const m = lane.mythos;
    const state = m.enabled ? 'enabled' : 'disabled';
    lines.push(
      `Mythos exploration (${state}) — invocations: ${m.invocations} | probes: ${m.probesExecuted} | non-hypothesis probes: ${m.nonHypothesisProbes} | hypotheses proposed: ${m.hypothesesProposed} | findings proposed: ${m.findingsProposed} (rejected ${m.findingsRejected})`,
    );
    if (m.sourceCorrelations > 0 || m.sourceRefsCollected > 0) {
      lines.push(
        `Mythos source correlation — worker calls: ${m.sourceCorrelations} | source refs collected: ${m.sourceRefsCollected}`,
      );
    }
    if (m.budgetExhausted) {
      lines.push(`Mythos budget exhausted: ${m.budgetExhausted}`);
    }
  }
  if (lane.browserExploitFamilies && lane.browserExploitFamilies.totalBrowserProbes > 0) {
    const bef = lane.browserExploitFamilies;
    const familyParts = Object.entries(bef.byFamily).map(
      ([id, f]) => `${escapeMarkdownLine(id)}: ${f.probes} (confirmed ${f.confirmed}, refuted ${f.refuted})`,
    );
    lines.push(`Browser exploit families — total: ${bef.totalBrowserProbes} | ${familyParts.join(' | ')}`);
  }
  lines.push(`Cost: $${lane.costUsd.toFixed(4)} | Duration: ${formatDuration(lane.durationMs)}`);
  if (lane.auditTrailPath) {
    lines.push(`Audit trail: ${escapeMarkdownLine(lane.auditTrailPath)}`);
  }
  if (lane.coverageGaps.length > 0) {
    lines.push('Coverage gaps:');
    for (const gap of lane.coverageGaps) {
      lines.push(`- ${escapeMarkdownBlock(gap)}`);
    }
  }
  if (lane.notes && lane.notes.length > 0) {
    lines.push('Notes:');
    for (const note of lane.notes) {
      lines.push(`- ${escapeMarkdownBlock(note)}`);
    }
  }
}

function formatDuration(durationMs: number): string {
  if (!Number.isFinite(durationMs) || durationMs <= 0) {
    return '0s';
  }
  const totalSeconds = Math.round(durationMs / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (minutes === 0) {
    return `${seconds}s`;
  }
  return `${minutes}m ${seconds}s`;
}

function severityRank(severity: string): number {
  switch (severity) {
    case 'critical': return 4;
    case 'high': return 3;
    case 'medium': return 2;
    case 'low': return 1;
    default: return 0;
  }
}

function renderAssessmentItems(title: string, items: AssessmentItemRecord[], emptyLabel: string): string {
  if (items.length === 0) {
    return `### ${title}\n\n${emptyLabel}`;
  }

  const lines = [`### ${title}`, ''];
  for (const item of items) {
    lines.push(`- **[${escapeMarkdownLine(item.severity.toUpperCase())}]** ${escapeMarkdownLine(item.title)}`);
    lines.push(`  ${escapeMarkdownBlock(item.description)}`);
    if (item.requiredConditions.length > 0) {
      lines.push(`  Conditions: ${item.requiredConditions.map((condition) => escapeMarkdownLine(condition)).join('; ')}`);
    }
    if (item.evidenceRefs.length > 0) {
      lines.push(`  Evidence refs: ${item.evidenceRefs.map((ref) => escapeMarkdownLine(ref)).join(', ')}`);
    }
  }
  return lines.join('\n');
}

function renderSuppressedClaims(claims: SuppressedClaimRecord[]): string {
  if (claims.length === 0) {
    return '### Suppressed Or Overstated Claims\n\nNo suppressed claims.';
  }

  const lines = ['### Suppressed Or Overstated Claims', ''];
  for (const claim of claims) {
    lines.push(`- ${escapeMarkdownBlock(claim.claim)}`);
    lines.push(`  Reason: ${escapeMarkdownBlock(claim.reason)}`);
    if (claim.evidenceRefs.length > 0) {
      lines.push(`  Evidence refs: ${claim.evidenceRefs.map((ref) => escapeMarkdownLine(ref)).join(', ')}`);
    }
  }
  return lines.join('\n');
}

function formatVerdictLabel(verdict: string): string {
  switch (verdict) {
    case 'confirmed_vulnerabilities_present':
      return 'confirmed vulnerabilities present';
    case 'validated_architectural_risks_only':
      return 'validated architectural or configuration risks only';
    case 'high_priority_unconfirmed_leads':
      return 'high-priority unconfirmed leads';
    case 'no_material_findings':
      return 'no material findings';
    default:
      return verdict;
  }
}
