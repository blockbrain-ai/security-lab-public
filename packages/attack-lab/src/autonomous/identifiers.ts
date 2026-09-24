/**
 * Identifier validation for values that become filesystem paths or are
 * interpolated into prompts (campaign ids, run ids, rule ids).
 *
 * Campaign and run identifiers are attacker-influenced: they arrive from the
 * CLI, from a runfile, or from a resumed campaign's state file, and are then
 * used to `resolve()` state, lock and evidence paths. Anything that is not a
 * plain identifier is rejected at the boundary rather than sanitised later.
 */

/** Letters, digits, dot, dash and underscore; must start with a letter or digit. */
export const SAFE_IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

/** Upper bound so an identifier cannot become an oversized path component. */
export const MAX_IDENTIFIER_LENGTH = 128;

const RESERVED_IDENTIFIERS = new Set(['.', '..']);

export function isSafeIdentifier(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= MAX_IDENTIFIER_LENGTH &&
    !RESERVED_IDENTIFIERS.has(value) &&
    SAFE_IDENTIFIER_PATTERN.test(value)
  );
}

/**
 * Validate an identifier, returning it unchanged when safe.
 * Throws with the supplied label so the CLI can point at the offending flag.
 */
export function assertSafeIdentifier(value: string, label: string): string {
  if (!isSafeIdentifier(value)) {
    throw new Error(
      `Invalid ${label} "${value}": identifiers must match ${SAFE_IDENTIFIER_PATTERN.source} ` +
      `and be at most ${MAX_IDENTIFIER_LENGTH} characters (no path separators).`,
    );
  }
  return value;
}

/** Validate an optional identifier; `undefined`/`null` pass through. */
export function assertOptionalSafeIdentifier(
  value: string | null | undefined,
  label: string,
): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  return assertSafeIdentifier(value, label);
}

/**
 * Assert that a resolved path stays inside `rootDir`. Used as a second line of
 * defence where a path is built from an identifier plus other segments.
 */
export function assertWithinRoot(resolvedPath: string, rootDir: string, label: string): string {
  const root = rootDir.endsWith('/') ? rootDir : `${rootDir}/`;
  if (resolvedPath !== rootDir && !resolvedPath.startsWith(root)) {
    throw new Error(`${label} resolves outside ${rootDir}: ${resolvedPath}`);
  }
  return resolvedPath;
}
