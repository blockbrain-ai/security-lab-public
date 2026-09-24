/**
 * Fix planner — generates governed remediation proposals from confirmed
 * findings. Proposals are informational only — human approval is required
 * before any code changes are made.
 */

import type { ChainFinding } from './contracts.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RemediationProposal {
  findingId: string;
  severity: string;
  title: string;
  description: string;
  suggestedFix: string;
  affectedFiles: string[];
  testStrategy: string;
  riskAssessment: string;
  status: 'proposed' | 'approved' | 'rejected' | 'implemented';
}

// ---------------------------------------------------------------------------
// Proposal generation
// ---------------------------------------------------------------------------

export function generateProposal(
  finding: ChainFinding,
  findingId: string,
): RemediationProposal {
  return {
    findingId,
    severity: finding.severity,
    title: `Fix: ${finding.description.split('\n')[0]?.slice(0, 80)}`,
    description: finding.description,
    suggestedFix: finding.remediationSuggestion,
    affectedFiles: extractAffectedFiles(finding),
    testStrategy: buildTestStrategy(finding),
    riskAssessment: assessFixRisk(finding),
    status: 'proposed',
  };
}

export function formatProposals(proposals: RemediationProposal[]): string {
  if (proposals.length === 0) return 'No remediation proposals.';

  const lines = ['# Remediation Proposals', ''];

  for (const p of proposals) {
    lines.push(`## [${p.severity.toUpperCase()}] ${p.title}`);
    lines.push('');
    lines.push(`**Status:** ${p.status}`);
    lines.push(`**Finding:** ${p.findingId}`);
    lines.push('');
    lines.push('### Description');
    lines.push(p.description);
    lines.push('');
    lines.push('### Suggested Fix');
    lines.push(p.suggestedFix);
    lines.push('');
    lines.push('### Affected Files');
    for (const f of p.affectedFiles) {
      lines.push(`- ${f}`);
    }
    lines.push('');
    lines.push('### Test Strategy');
    lines.push(p.testStrategy);
    lines.push('');
    lines.push('### Risk Assessment');
    lines.push(p.riskAssessment);
    lines.push('');
    lines.push('---');
    lines.push('');
  }

  lines.push('*All proposals require human approval before implementation.*');

  return lines.join('\n');
}

function extractAffectedFiles(finding: ChainFinding): string[] {
  // Extract file paths mentioned in reproduction steps
  const filePattern = /(?:src|packages|lib|frontend)\/[\w./-]+\.(?:ts|tsx|js|json|yaml|sh)/g;
  const files = new Set<string>();

  for (const step of finding.reproductionSteps) {
    const matches = step.match(filePattern) ?? [];
    for (const m of matches) files.add(m);
  }

  const descMatches = finding.description.match(filePattern) ?? [];
  for (const m of descMatches) files.add(m);

  return [...files];
}

function buildTestStrategy(finding: ChainFinding): string {
  const steps = [
    'Create a regression test that reproduces the vulnerability:',
    ...finding.reproductionSteps.map((s, i) => `${i + 1}. ${s}`),
    '',
    'After fix:',
    '- Run the regression test to verify the vulnerability is blocked',
    '- Run the full test suite to verify no regressions',
    '- Re-run the Security Lab investigation against the patched code',
  ];

  if (finding.involvedDormantReactivation) {
    steps.push('- Verify the dormant signal path is also addressed');
  }

  return steps.join('\n');
}

function assessFixRisk(finding: ChainFinding): string {
  const isChainFix = finding.reproductionSteps.length > 2;
  const isDormant = finding.involvedDormantReactivation;

  if (finding.severity === 'critical') {
    return 'HIGH RISK — Critical severity finding. Fix should be reviewed by at least two engineers. ' +
      'Consider deploying behind a feature flag initially.';
  }

  if (isChainFix) {
    return 'MEDIUM RISK — Fix addresses a multi-step chain. Verify that fixing one link ' +
      'does not create a new attack path through a different link.';
  }

  if (isDormant) {
    return 'MEDIUM RISK — Finding involved reactivated dormant signals. The root cause ' +
      'may be deeper than the immediate fix suggests.';
  }

  return 'LOW RISK — Standard fix. Verify with regression test and full suite.';
}
