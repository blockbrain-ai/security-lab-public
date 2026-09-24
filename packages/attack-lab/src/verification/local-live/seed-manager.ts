/**
 * Seed manager — creates and tracks seeded test data for live
 * verification (canary tenants, canary records, canary users).
 */

import type { SeedDataSpec, SeedTenant, SeedRecord } from './contracts.js';

export interface SeededFixture {
  tenants: Array<SeedTenant & { seededAt: string }>;
  records: Array<SeedRecord & { seededAt: string }>;
}

export class SeedManager {
  private readonly seeded: SeededFixture = { tenants: [], records: [] };

  recordSeed(spec: SeedDataSpec): SeededFixture {
    const at = new Date().toISOString();
    this.seeded.tenants.push(...spec.tenants.map((t) => ({ ...t, seededAt: at })));
    this.seeded.records.push(...spec.records.map((r) => ({ ...r, seededAt: at })));
    return this.seeded;
  }

  getSeededTenants(): Array<SeedTenant & { seededAt: string }> {
    return [...this.seeded.tenants];
  }

  getSeededRecords(): Array<SeedRecord & { seededAt: string }> {
    return [...this.seeded.records];
  }

  getRecordsForTenant(tenantId: string): Array<SeedRecord & { seededAt: string }> {
    return this.seeded.records.filter((r) => r.tenantId === tenantId);
  }

  /**
   * Get a record from a different tenant for IDOR testing.
   */
  getCrossTenantRecord(currentTenantId: string): (SeedRecord & { seededAt: string }) | undefined {
    return this.seeded.records.find((r) => r.tenantId !== currentTenantId);
  }
}
