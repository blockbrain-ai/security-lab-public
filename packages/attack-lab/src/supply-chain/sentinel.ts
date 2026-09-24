/**
 * Supply-chain sentinel — the main sentinel loop.
 *
 * 1. Load or create baseline
 * 2. Detect drift
 * 3. For each drift: quarantine, inspect, verdict
 * 4. Emit structured result with approved/blocked/needs-review
 * 5. Update baseline ONLY for approved packages
 */

import { resolve, join } from 'node:path';
import type { SentinelResult, QuarantineResult } from './contracts.js';
import { createBaseline, loadBaseline, saveBaseline, detectDrift } from './baseline.js';
import { inspectInstalledPackage } from './quarantine.js';
import { DEFAULT_SUPPLY_CHAIN_POLICY, getPolicyMetadata, type SupplyChainPolicy } from './policy.js';
import { shouldBlockBuild } from './gate.js';

// ---------------------------------------------------------------------------
// Main sentinel loop
// ---------------------------------------------------------------------------

export async function runSentinel(
  repoRoot: string,
  baselinePath?: string,
  policy: SupplyChainPolicy = DEFAULT_SUPPLY_CHAIN_POLICY,
): Promise<SentinelResult> {
  const effectiveBaselinePath = baselinePath ?? resolve(repoRoot, '.security-lab-baseline.json');
  const policyMetadata = getPolicyMetadata(policy);

  // Step 1: Load or create baseline
  let baseline = await loadBaseline(effectiveBaselinePath);
  let baselineStatus: SentinelResult['baselineStatus'];

  if (baseline) {
    baselineStatus = 'loaded';
  } else {
    baseline = await createBaseline(repoRoot);
    await saveBaseline(baseline, effectiveBaselinePath);
    baselineStatus = 'created';

    // First run: no drift to detect — the current state IS the baseline
    return {
      baselineStatus,
      baselinePath: effectiveBaselinePath,
      policyVersion: policyMetadata.version,
      policyHash: policyMetadata.hash,
      policyReviewedAt: policyMetadata.reviewedAt,
      drifts: [],
      quarantineResults: [],
      approvedPackages: [],
      blockedPackages: [],
      needsReviewPackages: [],
      shouldBlockBuild: false,
    };
  }

  // Step 2: Detect drift
  const drifts = await detectDrift(baseline, repoRoot);

  if (drifts.length === 0) {
    return {
      baselineStatus,
      baselinePath: effectiveBaselinePath,
      policyVersion: policyMetadata.version,
      policyHash: policyMetadata.hash,
      policyReviewedAt: policyMetadata.reviewedAt,
      drifts: [],
      quarantineResults: [],
      approvedPackages: [],
      blockedPackages: [],
      needsReviewPackages: [],
      shouldBlockBuild: false,
    };
  }

  // Step 3: Quarantine changed packages
  const quarantineResults: QuarantineResult[] = [];
  const packageDrifts = drifts.filter((d) =>
    d.kind === 'package_added' ||
    d.kind === 'version_changed' ||
    d.kind === 'integrity_changed' ||
    d.kind === 'install_script_added' ||
    d.kind === 'install_script_changed',
  );

  for (const drift of packageDrifts) {
    const packageDir = join(repoRoot, 'node_modules', drift.packageName);
    try {
      const result = await inspectInstalledPackage(
        packageDir,
        drift.packageName,
        drift.currentVersion ?? 'unknown',
      );
      quarantineResults.push(result);
    } catch {
      quarantineResults.push({
        packageName: drift.packageName,
        version: drift.currentVersion ?? 'unknown',
        verdict: 'needs_review',
        checks: [{ name: 'inspection_failed', passed: false, severity: 'high', details: 'Could not inspect package' }],
        reason: 'Inspection failed — package may not be installed locally',
        inspectedAt: new Date().toISOString(),
      });
    }
  }

  // Step 4: Categorise results
  const approvedPackages = quarantineResults.filter((r) => r.verdict === 'approved').map((r) => `${r.packageName}@${r.version}`);
  const blockedPackages = quarantineResults.filter((r) => r.verdict === 'rejected').map((r) => `${r.packageName}@${r.version}`);
  const needsReviewPackages = quarantineResults.filter((r) => r.verdict === 'needs_review').map((r) => `${r.packageName}@${r.version}`);

  // Step 5: Determine if build should be blocked
  const result: SentinelResult = {
    baselineStatus,
    baselinePath: effectiveBaselinePath,
    policyVersion: policyMetadata.version,
    policyHash: policyMetadata.hash,
    policyReviewedAt: policyMetadata.reviewedAt,
    drifts,
    quarantineResults,
    approvedPackages,
    blockedPackages,
    needsReviewPackages,
    shouldBlockBuild: false,
  };
  result.shouldBlockBuild = shouldBlockBuild(result);

  return result;
}

// ---------------------------------------------------------------------------
// Baseline promotion (only approved packages)
// ---------------------------------------------------------------------------

export async function approveAndUpdateBaseline(
  repoRoot: string,
  baselinePath: string,
  approvedPackageNames: string[],
): Promise<void> {
  const baseline = await loadBaseline(baselinePath);
  if (!baseline) return;

  const freshBaseline = await createBaseline(repoRoot);

  // Only update packages that were explicitly approved
  const approvedSet = new Set(approvedPackageNames.map(normalizeApprovedIdentifier));
  const freshByName = new Map(freshBaseline.packages.map((pkg) => [pkg.name, pkg]));
  const updatedPackages = baseline.packages.map((pkg) => {
    const fresh = freshByName.get(pkg.name);
    if (fresh && isApprovedPackage(fresh.name, fresh.version, approvedSet)) {
      return fresh;
    }
    return pkg;
  });

  // Add newly approved packages that weren't in the baseline before
  for (const fresh of freshBaseline.packages) {
    if (isApprovedPackage(fresh.name, fresh.version, approvedSet) && !baseline.packages.some((p) => p.name === fresh.name)) {
      updatedPackages.push(fresh);
    }
  }

  const updated = {
    ...baseline,
    approvedAt: new Date().toISOString(),
    packages: updatedPackages,
    // Update lockfile hash only if all drifts are resolved
    lockfileHash: freshBaseline.lockfileHash,
    packageJsonHash: freshBaseline.packageJsonHash,
  };

  await saveBaseline(updated, baselinePath);
}

// ---------------------------------------------------------------------------
// Human-readable summary
// ---------------------------------------------------------------------------

export function summarizeSentinelResult(result: SentinelResult): string {
  const lines = [
    '# Supply-Chain Sentinel Report',
    '',
    `Baseline: ${result.baselineStatus} (${result.baselinePath})`,
    `Policy: v${result.policyVersion} (${result.policyHash.slice(0, 12)}) reviewed ${result.policyReviewedAt}`,
    `Drifts detected: ${result.drifts.length}`,
    `Build blocked: ${result.shouldBlockBuild ? 'YES' : 'no'}`,
    '',
  ];

  if (result.drifts.length > 0) {
    lines.push('## Drift Details');
    for (const d of result.drifts) {
      lines.push(`- [${d.severity.toUpperCase()}] ${d.kind}: ${d.reason}`);
    }
    lines.push('');
  }

  if (result.quarantineResults.length > 0) {
    lines.push('## Quarantine Results');
    for (const q of result.quarantineResults) {
      const failedChecks = q.checks.filter((c) => !c.passed);
      lines.push(`- ${q.packageName}@${q.version}: **${q.verdict}** — ${q.reason}`);
      if (failedChecks.length > 0) {
        for (const c of failedChecks) {
          lines.push(`    [${c.severity}] ${c.name}: ${c.details}`);
        }
      }
    }
    lines.push('');
  }

  if (result.approvedPackages.length > 0) {
    lines.push(`## Approved: ${result.approvedPackages.join(', ')}`);
  }
  if (result.blockedPackages.length > 0) {
    lines.push(`## BLOCKED: ${result.blockedPackages.join(', ')}`);
  }
  if (result.needsReviewPackages.length > 0) {
    lines.push(`## Needs Review: ${result.needsReviewPackages.join(', ')}`);
  }

  return lines.join('\n');
}

function normalizeApprovedIdentifier(value: string): string {
  return value.trim().replace(/^@+/, '@');
}

function isApprovedPackage(name: string, version: string, approvedSet: Set<string>): boolean {
  return approvedSet.has(normalizeApprovedIdentifier(name))
    || approvedSet.has(normalizeApprovedIdentifier(`${name}@${version}`));
}
