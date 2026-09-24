/**
 * Shared retry logic with exponential backoff.
 *
 * Mirrors the reference architecture's RETRY_DELAYS pattern:
 *   60s → 120s → 1800s → 1800s → 1800s
 * to survive 1-hour usage-cap windows (~93 min total backoff).
 */

export interface RetryOptions {
  /** Delay sequence in milliseconds. Defaults to [60000, 120000, 1800000, 1800000, 1800000]. */
  delays?: number[];
  /** Status codes that trigger retry (rate limit / overloaded). */
  retryableStatusCodes?: number[];
  /** Called before each retry with attempt number and delay. */
  onRetry?: (attempt: number, delayMs: number, error: unknown) => void;
}

const DEFAULT_DELAYS = [60_000, 120_000, 1_800_000, 1_800_000, 1_800_000];
const DEFAULT_RETRYABLE = [429, 529, 503, 502];

export async function withRetry<T>(
  fn: () => Promise<T>,
  options: RetryOptions = {},
): Promise<T> {
  const delays = options.delays ?? DEFAULT_DELAYS;
  const retryable = new Set(options.retryableStatusCodes ?? DEFAULT_RETRYABLE);

  let lastError: unknown;

  for (let attempt = 0; attempt <= delays.length; attempt++) {
    try {
      return await fn();
    } catch (error: unknown) {
      lastError = error;

      if (!isRetryable(error, retryable)) {
        throw error;
      }

      if (attempt >= delays.length) {
        break;
      }

      const delay = delays[attempt]!;
      options.onRetry?.(attempt + 1, delay, error);
      await sleep(delay);
    }
  }

  throw lastError;
}

function isRetryable(error: unknown, retryableCodes: Set<number>): boolean {
  if (error && typeof error === 'object') {
    const status =
      'status' in error ? (error as { status: number }).status : undefined;
    if (status && retryableCodes.has(status)) return true;

    const code =
      'code' in error ? (error as { code: string }).code : undefined;
    if (code === 'ECONNRESET' || code === 'ETIMEDOUT' || code === 'ECONNREFUSED') {
      return true;
    }

    const message =
      'message' in error ? (error as { message: string }).message : '';
    if (/rate.limit|overloaded|capacity|too.many.requests/i.test(message)) {
      return true;
    }
  }
  return false;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
