/**
 * argv size limits for CLI providers.
 *
 * Linux caps a single argv entry at ~128 KB (MAX_ARG_STRLEN), so a prompt that
 * large cannot be passed as a command-line argument: the spawn fails with
 * E2BIG. macOS allows far more, which is why this only surfaces in CI/Linux.
 *
 * Providers that can pipe the prompt on stdin should do so. Providers that
 * cannot must refuse the call with an actionable message rather than letting
 * the operating system fail it with an opaque E2BIG.
 */

/** Conservative ceiling: Linux allows ~128 KB per argument. */
export const MAX_ARGV_PROMPT_BYTES = 100_000;

export function promptExceedsArgvLimit(prompt: string): boolean {
  return Buffer.byteLength(prompt, 'utf8') > MAX_ARGV_PROMPT_BYTES;
}

export function argvLimitError(provider: string, prompt: string, remedy: string): Error {
  const bytes = Buffer.byteLength(prompt, 'utf8');
  return new Error(
    `${provider} cannot pass a ${bytes.toLocaleString()}-byte prompt as a command-line argument ` +
      `(limit ${MAX_ARGV_PROMPT_BYTES.toLocaleString()} bytes; Linux rejects larger argv entries with E2BIG). ` +
      remedy,
  );
}
