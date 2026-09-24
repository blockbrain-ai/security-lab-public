/**
 * GitHub `owner/repo` slug derivation.
 *
 * The slug is derived from the *scanned target's* git remote and is then
 * interpolated into shell snippets inside the verification agent's prompt
 * (which runs unsandboxed). A hostile repository can therefore put arbitrary
 * text in its `origin` URL, so anything that is not a plain slug is discarded
 * rather than sanitised.
 */

import { execSync } from 'node:child_process';

/** Letters, digits, dot, dash, underscore on both sides of a single slash. */
export const REPO_SLUG_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

/** Placeholder used when no safe slug can be derived. */
export const UNKNOWN_REPO_SLUG = 'UNKNOWN_OWNER/UNKNOWN_REPO';

export function isSafeRepoSlug(value: unknown): value is string {
  return typeof value === 'string' && REPO_SLUG_PATTERN.test(value);
}

/** Read the target repository's origin URL, or null when unavailable. */
export type RemoteReader = (repoRoot: string) => string | null;

/**
 * Derive the GitHub slug for a target repository.
 *
 * @param repoRoot  Repository root used to read the origin remote.
 * @param explicit  Operator-supplied `--repo-slug`; validated and returned as-is.
 * @param readRemote Injection point for tests.
 */
export function deriveRepoSlug(
  repoRoot: string,
  explicit?: string,
  readRemote: RemoteReader = readOriginRemote,
): string {
  if (explicit !== undefined) {
    if (!isSafeRepoSlug(explicit)) {
      throw new Error(
        `Invalid --repo-slug "${explicit}": expected owner/repo using letters, digits, dot, dash or underscore.`,
      );
    }
    return explicit;
  }

  const remoteUrl = readRemote(repoRoot);
  if (remoteUrl) {
    // Handles both https://github.com/owner/repo.git and git@github.com:owner/repo.git
    const match = remoteUrl.match(/github\.com[/:]([^/]+\/[^/.]+)/);
    const candidate = match?.[1];
    if (candidate !== undefined) {
      if (isSafeRepoSlug(candidate)) {
        return candidate;
      }
      console.warn(
        `Ignoring unsafe GitHub slug derived from the target's origin remote: ${JSON.stringify(candidate)}`,
      );
    }
  }

  return UNKNOWN_REPO_SLUG;
}

function readOriginRemote(repoRoot: string): string | null {
  try {
    return execSync('git remote get-url origin', {
      cwd: repoRoot,
      encoding: 'utf8',
      timeout: 5000,
    }).trim();
  } catch {
    return null;
  }
}
