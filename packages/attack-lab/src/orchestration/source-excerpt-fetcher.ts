/**
 * Section 7.1 — SourceExcerptFetcher.
 *
 * Reads source files from the workspace and returns redacted excerpts
 * bounded by the excerpt budget (max 20 lines per ref, max 5 refs per
 * hypothesis). Credential-shaped strings are redacted before the excerpt
 * is handed to a model.
 */

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { SourceLocationRef } from '../../../evidence-plane/src/source-location-ref.js';
import { formatSourceRef } from '../../../evidence-plane/src/source-location-ref.js';

// ---------------------------------------------------------------------------
// Budget constants
// ---------------------------------------------------------------------------

/** Maximum number of source lines per single excerpt. */
export const MAX_LINES_PER_EXCERPT = 20;

/** Maximum number of source refs to include per hypothesis. */
export const MAX_REFS_PER_HYPOTHESIS = 5;

// ---------------------------------------------------------------------------
// Excerpt shape
// ---------------------------------------------------------------------------

export interface SourceExcerpt {
  ref: SourceLocationRef;
  /** Formatted ref string like `src/api/routes/approvals.ts:42-58`. */
  label: string;
  /** The extracted and redacted source lines. */
  content: string;
  /** Number of lines in the excerpt. */
  lineCount: number;
}

// ---------------------------------------------------------------------------
// Credential redaction
// ---------------------------------------------------------------------------

/**
 * Patterns that look like credentials or secrets. Each match is replaced
 * with `[REDACTED]`.
 */
const CREDENTIAL_PATTERNS = [
  // Long alphanumeric tokens (32+ chars) — API keys, secrets
  /[A-Za-z0-9_\-/+]{32,}/g,
  // Bearer tokens
  /Bearer\s+\S+/gi,
  // Explicit key/secret assignments in source
  /(?:password|secret|token|api_key|apikey|api-key|private_key)\s*[:=]\s*['"][^'"]+['"]/gi,
];

/**
 * Redact credential-shaped strings from a source excerpt.
 */
export function redactCredentials(text: string): string {
  let result = text;
  for (const pattern of CREDENTIAL_PATTERNS) {
    result = result.replace(pattern, '[REDACTED]');
  }
  return result;
}

// ---------------------------------------------------------------------------
// Fetcher
// ---------------------------------------------------------------------------

/**
 * Fetch a source excerpt for a single `SourceLocationRef`.
 *
 * Reads the file, extracts the relevant lines (capped at
 * `MAX_LINES_PER_EXCERPT`), redacts credential-shaped strings, and returns
 * the excerpt. Returns `undefined` if the file cannot be read.
 */
export async function fetchExcerpt(
  ref: SourceLocationRef,
  workspaceRoot: string,
): Promise<SourceExcerpt | undefined> {
  const filePath = resolve(workspaceRoot, ref.path);
  let content: string;
  try {
    content = await readFile(filePath, 'utf8');
  } catch {
    return undefined;
  }

  const lines = content.split('\n');
  const start = Math.max(0, ref.startLine - 1); // 1-based → 0-based
  const end = ref.endLine != null ? ref.endLine : ref.startLine;
  const requestedEnd = Math.min(lines.length, end);

  // Cap at MAX_LINES_PER_EXCERPT
  const cappedEnd = Math.min(requestedEnd, start + MAX_LINES_PER_EXCERPT);
  const extracted = lines.slice(start, cappedEnd).join('\n');
  const redacted = redactCredentials(extracted);

  return {
    ref,
    label: formatSourceRef(ref),
    content: redacted,
    lineCount: cappedEnd - start,
  };
}

/**
 * Fetch excerpts for multiple source refs, bounded by
 * `MAX_REFS_PER_HYPOTHESIS`.
 */
export async function fetchExcerpts(
  refs: SourceLocationRef[],
  workspaceRoot: string,
): Promise<SourceExcerpt[]> {
  const bounded = refs.slice(0, MAX_REFS_PER_HYPOTHESIS);
  const results = await Promise.all(
    bounded.map((ref) => fetchExcerpt(ref, workspaceRoot)),
  );
  return results.filter((r): r is SourceExcerpt => r != null);
}
