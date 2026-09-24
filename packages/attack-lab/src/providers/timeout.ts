/**
 * Provider timeout helper — bounds each SDK attempt so a single hung
 * network call cannot stall the campaign indefinitely.
 *
 * Section 1.1 adds ProviderTimeoutError (typed, catchable) and an
 * optional onTimeout callback for emitting provider_timeout events.
 */

// ---------------------------------------------------------------------------
// Typed timeout error
// ---------------------------------------------------------------------------

export class ProviderTimeoutError extends Error {
  readonly code = 'ETIMEDOUT';
  constructor(
    public readonly label: string,
    public readonly timeoutMs: number,
    public readonly elapsedMs: number,
  ) {
    super(`${label} timed out after ${timeoutMs}ms`);
    this.name = 'ProviderTimeoutError';
  }
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface TimeoutOptions {
  timeoutMs: number;
  label: string;
  /** Called when a timeout occurs, before the error is thrown. */
  onTimeout?: (info: { label: string; timeoutMs: number; elapsedMs: number }) => void | Promise<void>;
}

// ---------------------------------------------------------------------------
// Global timeout event listener (set by the runner to emit provider_timeout)
// ---------------------------------------------------------------------------

type TimeoutListener = (info: { provider: string; model: string; label: string; elapsedMs: number; timeoutMs: number }) => void | Promise<void>;

let globalTimeoutListener: TimeoutListener | null = null;

/** Register a global listener for provider timeout events. */
export function setProviderTimeoutListener(listener: TimeoutListener | null): void {
  globalTimeoutListener = listener;
}

/** Get the current global listener (used internally by adapters). */
export function getProviderTimeoutListener(): TimeoutListener | null {
  return globalTimeoutListener;
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

export async function withRequestTimeout<T>(
  fn: () => Promise<T>,
  options: TimeoutOptions,
): Promise<T> {
  if (!Number.isFinite(options.timeoutMs) || options.timeoutMs <= 0) {
    return fn();
  }

  const start = Date.now();
  let timer: ReturnType<typeof setTimeout> | undefined;

  try {
    return await Promise.race([
      fn(),
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => {
          const elapsedMs = Date.now() - start;
          const error = new ProviderTimeoutError(options.label, options.timeoutMs, elapsedMs);
          if (options.onTimeout) {
            // Fire-and-forget — do not block the rejection
            Promise.resolve(options.onTimeout({ label: options.label, timeoutMs: options.timeoutMs, elapsedMs })).catch(() => {});
          }
          reject(error);
        }, options.timeoutMs);
      }),
    ]);
  } finally {
    if (timer) {
      clearTimeout(timer);
    }
  }
}
