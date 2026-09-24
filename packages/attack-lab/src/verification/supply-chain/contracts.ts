/**
 * Supply-chain verification contracts — extends the existing sentinel
 * drift detection with confirmation experiments. Sentinel says "this
 * looks risky"; this lane runs the experiment that confirms or refutes
 * the risk.
 */

import type { DependencyDrift } from '../../supply-chain/contracts.js';

// ---------------------------------------------------------------------------
// Change set
// ---------------------------------------------------------------------------

export interface DependencyChangeSet {
  changeSetId: string;
  detectedAt: string;
  packageManager: 'npm' | 'pnpm' | 'yarn' | 'unknown';
  baselinePath: string;
  drifts: DependencyDrift[];
  changedPackages: ChangedPackage[];
}

export interface ChangedPackage {
  name: string;
  previousVersion?: string;
  currentVersion?: string;
  previousIntegrity?: string;
  currentIntegrity?: string;
  resolvedFrom?: string;
  hasInstallScript: boolean;
  isTransitive: boolean;
}

// ---------------------------------------------------------------------------
// Artifact inspection
// ---------------------------------------------------------------------------

export interface ArtifactFetchResult {
  packageName: string;
  version: string;
  tarballPath: string;
  unpackedPath: string;
  tarballSha256: string;
  fetchedFrom: string;
  fetchedAt: string;
}

export interface ArtifactInspection {
  packageName: string;
  version: string;
  tarballSha256: string;
  hasInstallScript: boolean;
  installScriptContent?: string;
  installScriptSha256?: string;
  hasPostInstallScript: boolean;
  hasNativeBinaries: boolean;
  nativeBinaryPaths: string[];
  hasObfuscatedSource: boolean;
  obfuscatedFiles: string[];
  containsNetworkCalls: boolean;
  networkCallSummary: string[];
  registryMatchesBaseline: boolean;
  signatureVerified: boolean;
  publishMetadata?: Record<string, unknown>;
  notes: string[];
}

// ---------------------------------------------------------------------------
// Install sandbox
// ---------------------------------------------------------------------------

export interface InstallSandboxResult {
  packageName: string;
  version: string;
  /**
   * False when the install was not executed because no isolation backend was
   * configured. A skipped step is recorded rather than silently omitted.
   */
  executed: boolean;
  /** How the install was isolated (or `none` when it did not run). */
  isolation: 'docker' | 'none';
  /** Why the install did not run. */
  skippedReason?: string;
  exitCode: number;
  durationMs: number;
  stdoutTail: string;
  stderrTail: string;
  filesWrittenOutsideSandbox: string[];
  networkAttempts: string[];
  exceededTimeout: boolean;
}

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

export type SupplyChainVerdict =
  | 'confirmed_risk'
  | 'approved_drift'
  | 'needs_review'
  | 'refuted'
  | 'not_applicable';

export interface SupplyChainExperiment {
  experimentId: string;
  changeSetId: string;
  packageName: string;
  version: string;
  startedAt: string;
  completedAt: string;
  inspection: ArtifactInspection;
  installSandbox?: InstallSandboxResult;
  baselineComparison: {
    diffSummary: string;
    materiallyDifferent: boolean;
  };
  policyHash: string;
  verdict: SupplyChainVerdict;
  reasoning: string;
  evidenceRefs: string[];
}
