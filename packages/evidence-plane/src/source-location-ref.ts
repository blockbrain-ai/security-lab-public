/**
 * Section 7.1 — SourceLocationRef: file:line provenance for evidence refs.
 *
 * A `SourceLocationRef` ties a finding or hypothesis back to the exact lines
 * of code that support it. Paths are always workspace-relative (never
 * absolute) so that campaign data is portable across machines.
 */

// ---------------------------------------------------------------------------
// Core type
// ---------------------------------------------------------------------------

export interface SourceLocationRef {
  /** Workspace-relative file path (never absolute). */
  path: string;
  /** First line number (1-based). */
  startLine: number;
  /** Last line number (1-based); defaults to startLine for single-line refs. */
  endLine?: number;
  /** Optional language hint for the renderer. */
  language?: string;
}

// ---------------------------------------------------------------------------
// Discriminated evidence ref union
// ---------------------------------------------------------------------------

export type EvidenceRef =
  | { kind: 'source'; location: SourceLocationRef }
  | { kind: 'signal'; id: string }
  | { kind: 'hypothesis'; id: string }
  | { kind: 'finding'; id: string }
  | { kind: 'probe'; id: string };

// ---------------------------------------------------------------------------
// Parse / format
// ---------------------------------------------------------------------------

/**
 * Parse a source ref string in `path:startLine-endLine` or `path:line`
 * format into a `SourceLocationRef`. Returns `undefined` if the string
 * does not match the expected format.
 */
export function parseSourceRef(str: string): SourceLocationRef | undefined {
  // Match `path:startLine-endLine` or `path:startLine`
  const match = str.match(/^(.+):(\d+)(?:-(\d+))?$/);
  if (!match) return undefined;
  const path = match[1]!;
  const startLine = Number(match[2]);
  const endLine = match[3] != null ? Number(match[3]) : undefined;
  if (!Number.isFinite(startLine) || startLine < 1) return undefined;
  if (endLine != null && (!Number.isFinite(endLine) || endLine < startLine)) return undefined;
  return { path, startLine, endLine };
}

/**
 * Format a `SourceLocationRef` into a string like
 * `src/api/routes/approvals.ts:42-58` or `src/foo.ts:10`.
 */
export function formatSourceRef(ref: SourceLocationRef): string {
  if (ref.endLine != null && ref.endLine !== ref.startLine) {
    return `${ref.path}:${ref.startLine}-${ref.endLine}`;
  }
  return `${ref.path}:${ref.startLine}`;
}

// ---------------------------------------------------------------------------
// Path portability
// ---------------------------------------------------------------------------

/**
 * Convert an absolute path to a workspace-relative path. If the path is
 * already relative (does not start with `/`), it is returned unchanged.
 */
export function toWorkspaceRelative(filePath: string, workspaceRoot: string): string {
  if (!filePath.startsWith('/')) return filePath;
  const root = workspaceRoot.endsWith('/') ? workspaceRoot : `${workspaceRoot}/`;
  if (filePath.startsWith(root)) {
    return filePath.slice(root.length);
  }
  // Path is absolute but outside the workspace — return as-is without the
  // leading slash to avoid leaking absolute paths into evidence.
  return filePath.startsWith('/') ? filePath.slice(1) : filePath;
}

// ---------------------------------------------------------------------------
// Legacy string ref migration
// ---------------------------------------------------------------------------

/**
 * Auto-wrap a legacy opaque string ref (e.g. `ws-3-28`, `ph-5-12`,
 * `finding-1`) into the discriminated `EvidenceRef` union. Used when
 * loading pre-7.1 campaign data.
 */
export function migrateStringRef(raw: string): EvidenceRef {
  if (raw.startsWith('ws-')) return { kind: 'signal', id: raw };
  if (raw.startsWith('ph-')) return { kind: 'hypothesis', id: raw };
  if (raw.startsWith('finding-')) return { kind: 'finding', id: raw };
  if (raw.startsWith('exp-') || raw.startsWith('probe-')) return { kind: 'probe', id: raw };
  // Default to signal for unrecognized formats — safe because the ref is
  // already an opaque ID and this is only used for display.
  return { kind: 'signal', id: raw };
}

/**
 * Normalize a mixed array of raw strings and `EvidenceRef` objects into
 * a clean `EvidenceRef[]`. Handles pre-7.1 campaign data where refs were
 * plain strings.
 */
export function normalizeEvidenceRefs(refs: Array<string | EvidenceRef>): EvidenceRef[] {
  return refs.map((ref) => {
    if (typeof ref === 'string') {
      // Check if it looks like a source ref (path:line)
      const parsed = parseSourceRef(ref);
      if (parsed) {
        return { kind: 'source' as const, location: parsed };
      }
      return migrateStringRef(ref);
    }
    return ref;
  });
}
