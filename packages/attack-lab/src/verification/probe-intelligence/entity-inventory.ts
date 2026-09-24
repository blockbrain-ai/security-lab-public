/**
 * Entity inventory — generic per-target catalog of discovered, seeded,
 * and minted entities that local-live probes need for parameter resolution.
 *
 * Section 11.1: every entry carries provenance so reports can distinguish
 * seeded values from runtime-discovered ones, and serious runs can refuse
 * to count unresolved-parameter probes as meaningful attempts.
 */

// ---------------------------------------------------------------------------
// Provenance — how an entity entered the inventory
// ---------------------------------------------------------------------------

export type EntityProvenance =
  | 'seeded'
  | 'minted'
  | 'discovered_static'
  | 'discovered_runtime';

// ---------------------------------------------------------------------------
// Entity kind — closed enum of generic categories
// ---------------------------------------------------------------------------

export type EntityKind =
  | 'company_id'
  | 'tenant_id'
  | 'user_id'
  | 'invite_token'
  | 'claim_token'
  | 'onboarding_token'
  | 'api_key'
  | 'websocket_company_id'
  | 'route_param'
  | 'enum_value'
  | 'session_id'
  | 'resource_id'
  | 'custom';

export const ENTITY_KINDS: readonly EntityKind[] = [
  'company_id',
  'tenant_id',
  'user_id',
  'invite_token',
  'claim_token',
  'onboarding_token',
  'api_key',
  'websocket_company_id',
  'route_param',
  'enum_value',
  'session_id',
  'resource_id',
  'custom',
] as const;

// ---------------------------------------------------------------------------
// Entity entry — a single resolved value with metadata
// ---------------------------------------------------------------------------

export interface EntityEntry {
  /** Unique entry identifier. */
  id: string;
  /** Category of entity. */
  kind: EntityKind;
  /** The concrete resolved value. */
  value: string;
  /** How the value was obtained. */
  provenance: EntityProvenance;
  /** Optional parameter name this value maps to (e.g. `:companyId`). */
  parameterName?: string;
  /** Identity context (e.g. which user/role produced this value). */
  identityId?: string;
  /** When the entry was added. */
  addedAt: string;
  /** Which stage/round discovered it. */
  discoveredDuring?: string;
  /** Free-form metadata for target-specific context. */
  metadata?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Entity inventory — the full catalog
// ---------------------------------------------------------------------------

export interface EntityInventory {
  /** All entries, keyed by entry id. */
  entries: EntityEntry[];
  /** Timestamp of last modification. */
  lastModifiedAt: string;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createEmptyInventory(): EntityInventory {
  return {
    entries: [],
    lastModifiedAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Mutation helpers
// ---------------------------------------------------------------------------

function generateEntryId(kind: EntityKind, inventory: EntityInventory): string {
  const seq = inventory.entries.length + 1;
  return `entity-${kind}-${Date.now()}-${seq}-${Math.random().toString(36).slice(2, 6)}`;
}

/**
 * Add an entity to the inventory. Returns the entry id.
 * Deduplicates on (kind, value, parameterName) — if a matching entry
 * already exists, the existing id is returned and no duplicate is added.
 */
export function addEntity(
  inventory: EntityInventory,
  entry: Omit<EntityEntry, 'id' | 'addedAt'>,
): string {
  const existing = inventory.entries.find(
    (e) =>
      e.kind === entry.kind &&
      e.value === entry.value &&
      e.parameterName === entry.parameterName,
  );
  if (existing) {
    return existing.id;
  }

  const id = generateEntryId(entry.kind, inventory);
  inventory.entries.push({
    ...entry,
    id,
    addedAt: new Date().toISOString(),
  });
  inventory.lastModifiedAt = new Date().toISOString();
  return id;
}

/**
 * Seed multiple entities at once (e.g. from target profile bootstrap).
 */
export function seedEntities(
  inventory: EntityInventory,
  entries: Array<Omit<EntityEntry, 'id' | 'addedAt'>>,
): string[] {
  return entries.map((e) => addEntity(inventory, e));
}

/**
 * Look up all entries matching a given kind.
 */
export function getEntitiesByKind(
  inventory: EntityInventory,
  kind: EntityKind,
): EntityEntry[] {
  return inventory.entries.filter((e) => e.kind === kind);
}

/**
 * Look up entries matching a parameter name (e.g. `:companyId`).
 */
export function getEntitiesByParameter(
  inventory: EntityInventory,
  parameterName: string,
): EntityEntry[] {
  return inventory.entries.filter((e) => e.parameterName === parameterName);
}

/**
 * Look up entries matching a kind and optionally an identity.
 */
export function getEntitiesByKindAndIdentity(
  inventory: EntityInventory,
  kind: EntityKind,
  identityId?: string,
): EntityEntry[] {
  return inventory.entries.filter(
    (e) => e.kind === kind && (!identityId || e.identityId === identityId),
  );
}

// ---------------------------------------------------------------------------
// Serialization — inventory is stored alongside campaign memory
// ---------------------------------------------------------------------------

export interface SerializedEntityInventory {
  entries: EntityEntry[];
  lastModifiedAt: string;
}

export function serializeInventory(inventory: EntityInventory): SerializedEntityInventory {
  return {
    entries: inventory.entries,
    lastModifiedAt: inventory.lastModifiedAt,
  };
}

export function deserializeInventory(raw: SerializedEntityInventory): EntityInventory {
  return {
    entries: raw.entries ?? [],
    lastModifiedAt: raw.lastModifiedAt ?? new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Placeholder detection
// ---------------------------------------------------------------------------

/** Pattern for route-style placeholders like `:companyId`, `:userId`. */
const PLACEHOLDER_PATTERN_GLOBAL = /:[a-zA-Z][a-zA-Z0-9_]*/g;

/** Non-global variant for stateless .test() calls. */
const PLACEHOLDER_PATTERN = /:[a-zA-Z][a-zA-Z0-9_]*/;

/**
 * Extract all placeholder names from a URL path.
 * E.g. `/api/companies/:companyId/users/:userId` → [':companyId', ':userId']
 */
export function extractPlaceholders(path: string): string[] {
  const matches = path.match(PLACEHOLDER_PATTERN_GLOBAL);
  return matches ? [...new Set(matches)] : [];
}

/**
 * Returns true if the path contains unresolved placeholders.
 * Uses a non-global regex so repeated calls are safe (no lastIndex drift).
 */
export function hasUnresolvedPlaceholders(path: string): boolean {
  return PLACEHOLDER_PATTERN.test(path);
}

// ---------------------------------------------------------------------------
// Inventory summary for reports
// ---------------------------------------------------------------------------

export interface InventorySummary {
  totalEntries: number;
  byKind: Record<string, number>;
  byProvenance: Record<string, number>;
  unresolvedParameters: string[];
}

export function summarizeInventory(
  inventory: EntityInventory,
  unresolvedParameters: string[] = [],
): InventorySummary {
  const byKind: Record<string, number> = {};
  const byProvenance: Record<string, number> = {};
  for (const entry of inventory.entries) {
    byKind[entry.kind] = (byKind[entry.kind] ?? 0) + 1;
    byProvenance[entry.provenance] = (byProvenance[entry.provenance] ?? 0) + 1;
  }
  return {
    totalEntries: inventory.entries.length,
    byKind,
    byProvenance,
    unresolvedParameters,
  };
}
