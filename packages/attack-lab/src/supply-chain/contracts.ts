/**
 * Supply-chain sentinel contracts — baseline, drift detection,
 * quarantine workflow, and promotion gate types.
 */

// ---------------------------------------------------------------------------
// Baseline
// ---------------------------------------------------------------------------

export interface DependencyBaseline {
  /** Schema version for forward compatibility. */
  version: 1;
  /** When this baseline was last approved. */
  approvedAt: string;
  /** Preferred package manager for this baseline. */
  packageManager?: 'npm' | 'pnpm' | 'yarn' | 'unknown';
  /** Lockfile name that produced this baseline. */
  lockfileName?: string | null;
  /** SHA-256 of package.json content. */
  packageJsonHash: string;
  /** SHA-256 of lockfile content. */
  lockfileHash: string;
  /** Per-package approved state. */
  packages: ApprovedPackage[];
}

export interface ApprovedPackage {
  name: string;
  version: string;
  /** SHA-512 integrity hash from lockfile. */
  integrityHash: string;
  /** Whether this package has install scripts. */
  hasInstallScript: boolean;
  /** SHA-256 of install script content (if any). */
  installScriptHash?: string;
  /** Registry URL this was resolved from. */
  resolvedFrom?: string;
  approvedAt: string;
}

// ---------------------------------------------------------------------------
// Drift
// ---------------------------------------------------------------------------

export interface DependencyDrift {
  detectedAt: string;
  kind: DriftKind;
  packageName: string;
  previousVersion?: string;
  currentVersion?: string;
  previousHash?: string;
  currentHash?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  reason: string;
}

export type DriftKind =
  | 'package_json_changed'
  | 'package_added'
  | 'package_removed'
  | 'version_changed'
  | 'integrity_changed'
  | 'install_script_changed'
  | 'install_script_added'
  | 'lockfile_changed'
  | 'registry_changed'
  | 'transitive_added';

// ---------------------------------------------------------------------------
// Quarantine
// ---------------------------------------------------------------------------

export interface QuarantineResult {
  packageName: string;
  version: string;
  verdict: 'approved' | 'rejected' | 'needs_review';
  checks: QuarantineCheck[];
  reason: string;
  inspectedAt: string;
}

export interface QuarantineCheck {
  name: string;
  passed: boolean;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  details: string;
}

// ---------------------------------------------------------------------------
// Sentinel result
// ---------------------------------------------------------------------------

export interface SentinelResult {
  baselineStatus: 'created' | 'loaded' | 'not_found';
  baselinePath: string;
  policyVersion: string;
  policyHash: string;
  policyReviewedAt: string;
  drifts: DependencyDrift[];
  quarantineResults: QuarantineResult[];
  approvedPackages: string[];
  blockedPackages: string[];
  needsReviewPackages: string[];
  shouldBlockBuild: boolean;
}
