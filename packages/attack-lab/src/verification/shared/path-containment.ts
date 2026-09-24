/**
 * Path containment for filesystem sandboxes.
 *
 * `resolve()` is lexical: it collapses `..` but does not follow symlinks, so a
 * scanned repository containing `docs/keys -> ~/.ssh` defeats a containment
 * check that only compares resolved strings. These helpers resolve through the
 * filesystem where the path exists, and fall back to the lexical answer for
 * paths that do not (a write target may legitimately not exist yet).
 */

import { realpathSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';

/**
 * Real path when the filesystem can tell us. For a path that does not exist
 * yet, resolve the deepest existing ancestor and re-append the remainder —
 * otherwise a symlinked root (for example `/var` → `/private/var` on macOS)
 * would make a legitimate not-yet-created path look like an escape.
 */
export function realpathOrResolved(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    // Fall through to ancestor resolution.
  }

  const absolute = resolve(path);
  const trailing: string[] = [];
  let current = absolute;

  for (;;) {
    const parent = dirname(current);
    if (parent === current) {
      return absolute;
    }
    trailing.unshift(basename(current));
    current = parent;
    try {
      return join(realpathSync(current), ...trailing);
    } catch {
      // Keep walking up.
    }
  }
}

/** True when `candidate` is `root` or sits underneath it, after symlink resolution. */
export function isWithinRootReal(candidate: string, root: string): boolean {
  const realRoot = realpathOrResolved(root);
  const realCandidate = realpathOrResolved(candidate);
  const rel = relative(realRoot, realCandidate);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

/**
 * Assert containment and return the real path, so callers read the file they
 * actually checked rather than the path they were handed.
 */
export function assertWithinRootReal(candidate: string, root: string, label = 'path'): string {
  if (!isWithinRootReal(candidate, root)) {
    throw new Error(`${label} escapes its sandbox: ${candidate}`);
  }
  return realpathOrResolved(candidate);
}
