/**
 * Supply-chain promotion gate — manages approval workflow
 * and determines whether build should be blocked.
 */

import type { SentinelResult, QuarantineResult } from './contracts.js';

/**
 * Determine whether a build should proceed given sentinel results.
 * Returns true if there are unresolved critical/high-severity issues.
 */
export function shouldBlockBuild(result: SentinelResult): boolean {
  if (result.blockedPackages.length > 0) return true;

  const unresolvedSevere = result.drifts.filter((d) =>
    (d.severity === 'critical' || d.severity === 'high')
    && !result.approvedPackages.includes(`${d.packageName}@${d.currentVersion}`)
  );

  const pendingHighRiskPackages = result.quarantineResults.some((entry) =>
    (entry.verdict === 'rejected' || entry.verdict === 'needs_review')
    && entry.checks.some((check) => !check.passed && (check.severity === 'critical' || check.severity === 'high')),
  );

  return unresolvedSevere.length > 0 || pendingHighRiskPackages;
}

/**
 * Summarise what's pending review.
 */
export function summarizePendingDrift(result: SentinelResult): string {
  const pending = [
    ...result.blockedPackages.map((p) => `  BLOCKED: ${p}`),
    ...result.needsReviewPackages.map((p) => `  NEEDS REVIEW: ${p}`),
  ];

  if (pending.length === 0) return 'No pending dependency drift.';

  return `Pending dependency drift:\n${pending.join('\n')}`;
}

/**
 * Filter quarantine results to only those that were approved.
 */
export function getApprovedResults(results: QuarantineResult[]): QuarantineResult[] {
  return results.filter((r) => r.verdict === 'approved');
}

/**
 * Filter quarantine results to those requiring human attention.
 */
export function getPendingResults(results: QuarantineResult[]): QuarantineResult[] {
  return results.filter((r) => r.verdict === 'needs_review' || r.verdict === 'rejected');
}
