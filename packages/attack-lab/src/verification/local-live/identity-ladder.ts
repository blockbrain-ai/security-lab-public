/**
 * Identity ladder — manages multiple identity contexts (anonymous,
 * user_a, user_b, admin, service) for cross-tenant and privilege
 * escalation testing.
 */

import type { IdentitySpec } from './contracts.js';

// ---------------------------------------------------------------------------
// Identity ladder
// ---------------------------------------------------------------------------

export class IdentityLadder {
  private readonly identities: Map<string, IdentitySpec>;
  private readonly environment: Record<string, string | undefined>;
  private readonly tenantHeader: string;

  constructor(
    identities: IdentitySpec[],
    environment?: Record<string, string | undefined>,
    tenantHeader?: string,
  ) {
    this.identities = new Map(identities.map((i) => [i.id, i]));
    this.environment = environment ?? process.env;
    // Default tenant header for backwards compatibility (target profile is source of truth)
    this.tenantHeader = tenantHeader ?? 'x-organization-id';
  }

  get(id: string): IdentitySpec | undefined {
    return this.identities.get(this.resolveIdentityId(id));
  }

  list(): IdentitySpec[] {
    return [...this.identities.values()];
  }

  /**
   * Build the headers for a probe using a given identity.
   * Returns null if the identity references env vars that aren't set.
   */
  buildHeaders(id: string): Record<string, string> | null {
    const identity = this.identities.get(this.resolveIdentityId(id));
    if (!identity) return null;

    const headers: Record<string, string> = {};

    switch (identity.kind) {
      case 'anonymous':
        return headers;

      case 'session_cookie': {
        if (!identity.cookieEnv) return null;
        const cookieValue = this.environment[identity.cookieEnv];
        if (!cookieValue) return null;
        headers['Cookie'] = cookieValue;
        if (identity.organizationId) {
          headers[this.tenantHeader] = identity.organizationId;
        }
        return headers;
      }

      case 'bearer_token': {
        if (!identity.tokenEnv) return null;
        const token = this.environment[identity.tokenEnv];
        if (!token) return null;
        headers['Authorization'] = `Bearer ${token}`;
        if (identity.organizationId) {
          headers[this.tenantHeader] = identity.organizationId;
        }
        return headers;
      }

      case 'api_key': {
        if (!identity.apiKeyEnv) return null;
        const key = this.environment[identity.apiKeyEnv];
        if (!key) return null;
        headers['x-api-key'] = key;
        if (identity.organizationId) {
          headers[this.tenantHeader] = identity.organizationId;
        }
        return headers;
      }

      case 'iap_header': {
        // For local testing of IAP-protected apps that read x-goog headers
        headers['x-goog-authenticated-user-email'] = `accounts.google.com:${id}@test.local`;
        headers['x-goog-authenticated-user-id'] = `accounts.google.com:test-${id}`;
        return headers;
      }
    }
  }

  private resolveIdentityId(id: string): string {
    if (this.identities.has(id)) {
      return id;
    }

    if (id === 'anonymous' || id === 'anon') {
      if (this.identities.has('guest')) {
        return 'guest';
      }
      const anonymousIdentity = [...this.identities.values()].find((identity) => identity.kind === 'anonymous');
      if (anonymousIdentity) {
        return anonymousIdentity.id;
      }
    }

    return id;
  }

  /**
   * Identify cross-tenant test pairs (e.g., user_a vs user_b).
   */
  getCrossTenantPairs(): Array<[IdentitySpec, IdentitySpec]> {
    const pairs: Array<[IdentitySpec, IdentitySpec]> = [];
    const all = this.list();
    for (let i = 0; i < all.length; i++) {
      for (let j = i + 1; j < all.length; j++) {
        const a = all[i]!;
        const b = all[j]!;
        if (a.organizationId && b.organizationId && a.organizationId !== b.organizationId) {
          pairs.push([a, b]);
        }
      }
    }
    return pairs;
  }

  /**
   * Identify privilege escalation pairs (low → high).
   */
  getPrivilegeEscalationPairs(): Array<[IdentitySpec, IdentitySpec]> {
    const pairs: Array<[IdentitySpec, IdentitySpec]> = [];
    const all = this.list();
    const roleOrder = ['anonymous', 'user', 'service', 'admin'];

    for (const low of all) {
      for (const high of all) {
        if (low.id === high.id) continue;
        const lowIdx = roleOrder.indexOf(low.expectedRole ?? 'user');
        const highIdx = roleOrder.indexOf(high.expectedRole ?? 'user');
        if (lowIdx >= 0 && highIdx > lowIdx) {
          pairs.push([low, high]);
        }
      }
    }
    return pairs;
  }
}
