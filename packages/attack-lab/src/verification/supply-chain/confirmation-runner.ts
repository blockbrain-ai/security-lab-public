/**
 * Confirmation runner — orchestrates fetch → inspect → install sandbox
 * → policy review for a dependency change set. Produces one
 * SupplyChainExperiment per changed package.
 */

import { randomBytes } from 'node:crypto';
import type {
  DependencyChangeSet,
  SupplyChainExperiment,
  ChangedPackage,
} from './contracts.js';
import type { ApprovedPackage, DependencyBaseline } from '../../supply-chain/contracts.js';
import { ArtifactFetcher } from './artifact-fetcher.js';
import { ProvenanceVerifier } from './provenance-verifier.js';
import { InstallSandbox, type InstallSandboxIsolation } from './install-sandbox.js';
import { DiffAnalyzer } from './diff-analyzer.js';
import { PolicyReview } from './policy-review.js';

// ---------------------------------------------------------------------------
// Confirmation runner options
// ---------------------------------------------------------------------------

export interface ConfirmationRunnerOptions {
  quarantineDir: string;
  baseline?: DependencyBaseline;
  policyReview?: PolicyReview;
  /**
   * Run the install sandbox in addition to static inspection. Off by default:
   * this step executes the package's install scripts, so enabling it is an
   * explicit decision.
   */
  enableInstallSandbox?: boolean;
  /**
   * Isolation backend for the install sandbox. Required for the step to run —
   * without it the sandbox records the step as skipped instead of executing a
   * target's install scripts on this host.
   */
  installSandboxIsolation?: InstallSandboxIsolation;
}

// ---------------------------------------------------------------------------
// Confirmation runner
// ---------------------------------------------------------------------------

export class SupplyChainConfirmationRunner {
  private readonly fetcher: ArtifactFetcher;
  private readonly verifier: ProvenanceVerifier;
  private readonly sandbox: InstallSandbox;
  private readonly diff: DiffAnalyzer;
  private readonly policy: PolicyReview;

  constructor(private readonly options: ConfirmationRunnerOptions) {
    this.fetcher = new ArtifactFetcher({ quarantineDir: options.quarantineDir });
    this.verifier = new ProvenanceVerifier();
    this.sandbox = new InstallSandbox();
    this.diff = new DiffAnalyzer();
    this.policy = options.policyReview ?? new PolicyReview();
  }

  async run(changeSet: DependencyChangeSet): Promise<SupplyChainExperiment[]> {
    const experiments: SupplyChainExperiment[] = [];
    for (const pkg of changeSet.changedPackages) {
      try {
        const experiment = await this.confirmOne(changeSet, pkg);
        experiments.push(experiment);
      } catch (error) {
        experiments.push(this.errorExperiment(changeSet, pkg, error));
      }
    }
    return experiments;
  }

  private async confirmOne(
    changeSet: DependencyChangeSet,
    pkg: ChangedPackage,
  ): Promise<SupplyChainExperiment> {
    const startedAt = new Date().toISOString();
    const experimentId = `exp-supply-chain-${pkg.name}-${Date.now()}-${randomBytes(4).toString('hex')}`;

    if (!pkg.currentVersion) {
      // Removed package — no artifact to fetch
      const completedAt = new Date().toISOString();
      return {
        experimentId,
        changeSetId: changeSet.changeSetId,
        packageName: pkg.name,
        version: pkg.previousVersion ?? 'removed',
        startedAt,
        completedAt,
        inspection: emptyInspection(pkg),
        baselineComparison: { diffSummary: 'package removed', materiallyDifferent: true },
        policyHash: this.policy.hash(),
        verdict: 'needs_review',
        reasoning: 'Package was removed from baseline; manual confirmation that the removal is intended',
        evidenceRefs: [],
      };
    }

    const fetched = await this.fetcher.fetch(pkg.name, pkg.currentVersion);
    const inspection = await this.verifier.inspect(fetched, pkg.resolvedFrom);

    const approved = this.findApproved(pkg.name);
    let installSandbox;
    if (this.shouldRunSandbox(inspection)) {
      installSandbox = await this.sandbox.run(fetched, {
        packageManager: changeSet.packageManager === 'unknown' ? 'npm' : changeSet.packageManager,
        isolation: this.options.installSandboxIsolation,
      });
    }

    const diffResult = this.diff.analyze(pkg, inspection, approved, installSandbox);
    const decision = this.policy.decide(inspection, diffResult, installSandbox);

    return {
      experimentId,
      changeSetId: changeSet.changeSetId,
      packageName: pkg.name,
      version: pkg.currentVersion,
      startedAt,
      completedAt: new Date().toISOString(),
      inspection,
      installSandbox,
      baselineComparison: {
        diffSummary: diffResult.diffSummary,
        materiallyDifferent: diffResult.materiallyDifferent,
      },
      policyHash: this.policy.hash(),
      verdict: decision.verdict,
      reasoning: decision.reasoning,
      evidenceRefs: [`tarball:${fetched.tarballSha256}`, `unpacked:${fetched.unpackedPath}`],
    };
  }

  private findApproved(packageName: string): ApprovedPackage | undefined {
    return this.options.baseline?.packages.find((p) => p.name === packageName);
  }

  private shouldRunSandbox(inspection: { hasInstallScript: boolean; hasNativeBinaries: boolean }): boolean {
    // Fail closed: executing a package's install scripts is opt-in, never the
    // default, however suspicious the package looks.
    if (this.options.enableInstallSandbox !== true) {
      return false;
    }
    if (!this.options.installSandboxIsolation) {
      return false;
    }
    // Enabled and isolated: the operator has opted in to observing install-time
    // behaviour, so the step runs regardless of what static inspection found.
    return true;
  }

  private errorExperiment(
    changeSet: DependencyChangeSet,
    pkg: ChangedPackage,
    error: unknown,
  ): SupplyChainExperiment {
    const now = new Date().toISOString();
    return {
      experimentId: `exp-supply-chain-${pkg.name}-error-${Date.now()}`,
      changeSetId: changeSet.changeSetId,
      packageName: pkg.name,
      version: pkg.currentVersion ?? 'unknown',
      startedAt: now,
      completedAt: now,
      inspection: emptyInspection(pkg),
      baselineComparison: { diffSummary: 'error', materiallyDifferent: true },
      policyHash: this.policy.hash(),
      verdict: 'needs_review',
      reasoning: `Confirmation experiment errored: ${error instanceof Error ? error.message : String(error)}`,
      evidenceRefs: [],
    };
  }
}

function emptyInspection(pkg: ChangedPackage) {
  return {
    packageName: pkg.name,
    version: pkg.currentVersion ?? 'unknown',
    tarballSha256: '',
    hasInstallScript: false,
    hasPostInstallScript: false,
    hasNativeBinaries: false,
    nativeBinaryPaths: [],
    hasObfuscatedSource: false,
    obfuscatedFiles: [],
    containsNetworkCalls: false,
    networkCallSummary: [],
    registryMatchesBaseline: true,
    signatureVerified: false,
    notes: [],
  };
}
