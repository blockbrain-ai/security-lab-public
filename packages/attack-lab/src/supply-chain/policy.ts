/**
 * Versioned supply-chain policy — defines what is allowed, what triggers
 * quarantine, and what is blocked outright. Policy version and hash are
 * captured in campaign evidence.
 */

import { createHash } from 'node:crypto';

// ---------------------------------------------------------------------------
// Policy definition
// ---------------------------------------------------------------------------

export interface SupplyChainPolicy {
  version: string;
  reviewedAt: string;
  /** Allowed registries. Packages from other registries trigger quarantine. */
  allowedRegistries: string[];
  /** Whether a lockfile is required. */
  lockfileRequired: boolean;
  /** Whether integrity hashes are required for all packages. */
  integrityRequired: boolean;
  /** How to handle git:// or file:// dependencies. */
  gitUrlDependencyHandling: 'block' | 'quarantine' | 'allow';
  /** Severity assigned to packages with install scripts. */
  installScriptSeverity: 'medium' | 'high' | 'critical';
  /** Severity assigned to packages with native binaries. */
  nativeBinarySeverity: 'medium' | 'high' | 'critical';
  /** Conditions that require quarantine. */
  quarantineConditions: string[];
  /** Package name patterns to always block. */
  blockedPatterns: string[];
}

// ---------------------------------------------------------------------------
// Default policy
// ---------------------------------------------------------------------------

export const DEFAULT_SUPPLY_CHAIN_POLICY: SupplyChainPolicy = {
  version: '1.0.0',
  reviewedAt: '2026-04-10',
  allowedRegistries: [
    'https://registry.npmjs.org/',
    'https://registry.npmmirror.com/',
  ],
  lockfileRequired: true,
  integrityRequired: true,
  gitUrlDependencyHandling: 'quarantine',
  installScriptSeverity: 'high',
  nativeBinarySeverity: 'high',
  quarantineConditions: [
    'new_package_with_install_scripts',
    'version_change_with_install_script_change',
    'integrity_hash_changed',
    'registry_changed',
    'git_or_file_dependency',
    'native_binary_present',
  ],
  blockedPatterns: [],
};

// ---------------------------------------------------------------------------
// Policy hash (for evidence)
// ---------------------------------------------------------------------------

export function computePolicyHash(policy: SupplyChainPolicy): string {
  return createHash('sha256')
    .update(JSON.stringify(policy))
    .digest('hex');
}

export function getPolicyMetadata(policy: SupplyChainPolicy): {
  version: string;
  hash: string;
  reviewedAt: string;
} {
  return {
    version: policy.version,
    hash: computePolicyHash(policy),
    reviewedAt: policy.reviewedAt,
  };
}
