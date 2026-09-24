/**
 * Policy review — maps a confirmed change set against the versioned
 * supply-chain policy. The policy hash is recorded with every verdict
 * so the operator can prove which rules were in force.
 */

import { createHash } from 'node:crypto';
import type { ArtifactInspection, InstallSandboxResult, SupplyChainVerdict } from './contracts.js';
import type { DiffResult } from './diff-analyzer.js';

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

export interface SupplyChainPolicy {
  version: string;
  forbidNewInstallScripts: boolean;
  forbidNewNativeBinaries: boolean;
  forbidObfuscatedSource: boolean;
  forbidUnregisteredOrigins: boolean;
  requireSignatureVerification: boolean;
  allowedRegistries: string[];
}

export const DEFAULT_POLICY: SupplyChainPolicy = {
  version: '1.0.0',
  forbidNewInstallScripts: true,
  forbidNewNativeBinaries: true,
  forbidObfuscatedSource: true,
  forbidUnregisteredOrigins: true,
  requireSignatureVerification: false,
  allowedRegistries: ['https://registry.npmjs.org', 'https://registry.yarnpkg.com'],
};

// ---------------------------------------------------------------------------
// Policy review
// ---------------------------------------------------------------------------

export class PolicyReview {
  constructor(private readonly policy: SupplyChainPolicy = DEFAULT_POLICY) {}

  hash(): string {
    return createHash('sha256').update(JSON.stringify(this.policy)).digest('hex');
  }

  decide(
    inspection: ArtifactInspection,
    diff: DiffResult,
    sandbox?: InstallSandboxResult,
  ): { verdict: SupplyChainVerdict; reasoning: string } {
    const reasons: string[] = [];

    if (this.policy.forbidNewInstallScripts && diff.changes.some((c) => c.includes('install script ADDED'))) {
      reasons.push('policy forbids newly added install scripts');
    }
    if (
      this.policy.forbidNewNativeBinaries &&
      inspection.hasNativeBinaries &&
      diff.changes.some((c) => c.includes('native'))
    ) {
      reasons.push('policy forbids newly added native binaries');
    }
    if (this.policy.forbidObfuscatedSource && inspection.hasObfuscatedSource) {
      reasons.push('policy forbids obfuscated source');
    }
    if (this.policy.forbidUnregisteredOrigins && !inspection.registryMatchesBaseline) {
      reasons.push('policy forbids unregistered origins');
    }
    if (this.policy.requireSignatureVerification && !inspection.signatureVerified) {
      reasons.push('policy requires signature verification');
    }
    if (sandbox && sandbox.filesWrittenOutsideSandbox.length > 0) {
      reasons.push('install sandbox wrote outside its workspace');
    }

    if (reasons.length > 0) {
      return {
        verdict: 'confirmed_risk',
        reasoning: reasons.join('; '),
      };
    }

    if (diff.materiallyDifferent) {
      return {
        verdict: 'needs_review',
        reasoning: `Material drift detected but no policy rule fired: ${diff.diffSummary}`,
      };
    }

    return {
      verdict: 'approved_drift',
      reasoning: `Drift inspected and judged safe under policy ${this.policy.version}`,
    };
  }
}
