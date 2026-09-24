/**
 * Diff analyzer — compares the current artifact contents and install
 * behavior against the previously approved baseline. Surfaces changes
 * that the policy review and confirmation runner consume.
 */

import type { ArtifactInspection, ChangedPackage, InstallSandboxResult } from './contracts.js';
import type { ApprovedPackage } from '../../supply-chain/contracts.js';

// ---------------------------------------------------------------------------
// Diff result
// ---------------------------------------------------------------------------

export interface DiffResult {
  diffSummary: string;
  materiallyDifferent: boolean;
  changes: string[];
}

// ---------------------------------------------------------------------------
// Diff analyzer
// ---------------------------------------------------------------------------

export class DiffAnalyzer {
  analyze(
    changed: ChangedPackage,
    inspection: ArtifactInspection,
    approved: ApprovedPackage | undefined,
    sandbox?: InstallSandboxResult,
  ): DiffResult {
    const changes: string[] = [];

    if (approved) {
      if (approved.version !== changed.currentVersion) {
        changes.push(`version: ${approved.version} → ${changed.currentVersion}`);
      }
      if (approved.integrityHash !== changed.currentIntegrity) {
        changes.push(`integrity hash changed`);
      }
      if (approved.installScriptHash !== inspection.installScriptSha256) {
        if (approved.hasInstallScript && !inspection.hasInstallScript) {
          changes.push('install script removed');
        } else if (!approved.hasInstallScript && inspection.hasInstallScript) {
          changes.push('install script ADDED (previously absent)');
        } else {
          changes.push('install script CONTENT changed');
        }
      }
      if (approved.resolvedFrom && inspection.registryMatchesBaseline === false) {
        changes.push('registry source changed from baseline');
      }
    } else {
      changes.push('package is new (no prior approved baseline)');
    }

    if (inspection.hasNativeBinaries) {
      changes.push(`native binaries present: ${inspection.nativeBinaryPaths.slice(0, 3).join(', ')}`);
    }
    if (inspection.hasObfuscatedSource) {
      changes.push(`obfuscated source detected: ${inspection.obfuscatedFiles.slice(0, 3).join(', ')}`);
    }
    if (inspection.containsNetworkCalls) {
      changes.push(`network calls detected (${inspection.networkCallSummary.length} matches)`);
    }
    if (sandbox) {
      if (sandbox.exitCode !== 0) {
        changes.push(`sandbox install failed with exit ${sandbox.exitCode}`);
      }
      if (sandbox.filesWrittenOutsideSandbox.length > 0) {
        changes.push(
          `sandbox wrote outside its workspace: ${sandbox.filesWrittenOutsideSandbox.slice(0, 3).join(', ')}`,
        );
      }
      if (sandbox.networkAttempts.length > 0) {
        changes.push(`sandbox attempted network: ${sandbox.networkAttempts.join('; ')}`);
      }
      if (sandbox.exceededTimeout) {
        changes.push('sandbox install exceeded timeout (killed)');
      }
    }

    const materiallyDifferent =
      changes.some(
        (c) =>
          c.includes('install script') ||
          c.includes('native') ||
          c.includes('obfuscated') ||
          c.includes('network') ||
          c.includes('outside its workspace') ||
          c.includes('registry source changed') ||
          c.includes('integrity hash changed'),
      );

    return {
      diffSummary: changes.length > 0 ? changes.join('; ') : 'no changes detected',
      materiallyDifferent,
      changes,
    };
  }
}
