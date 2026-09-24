/**
 * Hosted identity matrix — maps hosted principals to expected
 * boundaries and trust levels. Used to make every hosted finding
 * about a *specific identity transition*, not a vague "auth bypass".
 */

import type { HostedIdentitySpec } from './contracts.js';

// ---------------------------------------------------------------------------
// Auto-migration helper
// ---------------------------------------------------------------------------

/**
 * Resolve the effective `isCanary` value for a hosted identity.
 * If the field is explicitly set, use it. Otherwise, auto-migrate
 * legacy profiles: identities with 'canary' in their id or description,
 * or the 'guest' identity, are treated as canaries.
 */
export function resolveIsCanary(identity: HostedIdentitySpec): boolean {
  if (typeof identity.isCanary === 'boolean') {
    return identity.isCanary;
  }
  // Auto-migration for legacy profiles
  if (identity.id === 'guest') return true;
  if (identity.id.includes('canary')) return true;
  if (identity.description.toLowerCase().includes('canary')) return true;
  return false;
}

// ---------------------------------------------------------------------------
// Identity matrix
// ---------------------------------------------------------------------------

export class HostedIdentityMatrix {
  private readonly identities: Map<string, HostedIdentitySpec>;

  constructor(identities: HostedIdentitySpec[]) {
    this.identities = new Map(identities.map((i) => [i.id, i]));
  }

  get(id: string): HostedIdentitySpec | undefined {
    return this.identities.get(id);
  }

  list(): HostedIdentitySpec[] {
    return [...this.identities.values()];
  }

  /**
   * Generate the boundary matrix for hosted probing.
   * Returns an array of "low_identity -> forbidden_boundary" pairs
   * that the campaign should explicitly verify cannot be crossed.
   */
  generateBoundaryMatrix(): Array<{ identityId: string; boundary: string }> {
    const pairs: Array<{ identityId: string; boundary: string }> = [];
    for (const identity of this.identities.values()) {
      for (const boundary of identity.forbiddenBoundaries ?? []) {
        pairs.push({ identityId: identity.id, boundary });
      }
    }
    return pairs;
  }

  /**
   * Validate that all identities are explicitly marked as canaries.
   * Uses the explicit `isCanary` and `allowInHosted` metadata fields
   * rather than substring-matching on role strings.
   *
   * Legacy profiles that do not declare these fields are auto-migrated:
   * identities with 'canary' in their id/description or the 'guest'
   * identity are treated as canaries.
   */
  validateAllAreCanaries(): void {
    for (const identity of this.identities.values()) {
      const effectiveIsCanary = resolveIsCanary(identity);
      const effectiveAllowInHosted = identity.allowInHosted ?? effectiveIsCanary;

      if (!effectiveIsCanary) {
        throw new Error(
          `Hosted identity "${identity.id}" is not marked as a canary. ` +
            'Set isCanary: true explicitly in the identity spec, or use a dedicated canary identity.',
        );
      }
      if (!effectiveAllowInHosted) {
        throw new Error(
          `Hosted identity "${identity.id}" is marked as a canary but not allowed in hosted lanes. ` +
            'Set allowInHosted: true explicitly in the identity spec.',
        );
      }
    }
  }
}
