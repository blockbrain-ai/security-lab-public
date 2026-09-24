/**
 * Heartbeat helper — wraps a long-running async operation and emits
 * periodic heartbeat events so "is the process stuck?" is observable
 * from the evidence stream alone.
 *
 * The interval timer uses .unref() so heartbeats do not keep the
 * Node.js event loop alive after the wrapped operation settles.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface HeartbeatOptions {
  /** Stage name for the heartbeat event (e.g. 'static', 'local_live'). */
  stage: string;
  /** Optional role context (e.g. 'planner', 'judge'). */
  role?: string;
  /** Interval between heartbeats in ms (default 30 000). */
  intervalMs?: number;
  /** Expected timeout for the operation, if known. */
  expectedTimeoutMs?: number;
  /** Callback to emit the heartbeat event. */
  emit: (stage: string, payload: Record<string, unknown>) => Promise<void>;
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/**
 * Wrap an async operation with periodic heartbeat events.
 *
 * Returns the resolved value of the wrapped promise. If the promise
 * rejects, the heartbeat stops and the error propagates.
 */
export async function withHeartbeat<T>(
  operation: Promise<T>,
  options: HeartbeatOptions,
): Promise<T> {
  const intervalMs = options.intervalMs ?? 30_000;
  const start = Date.now();
  let stopped = false;

  const timer = setInterval(() => {
    if (stopped) {
      return;
    }
    const now = Date.now();
    const payload: Record<string, unknown> = {
      stage: options.stage,
      elapsedMs: now - start,
      lastActivityAt: new Date(now).toISOString(),
    };
    if (options.role) {
      payload.role = options.role;
    }
    if (options.expectedTimeoutMs != null) {
      payload.expectedTimeoutMs = options.expectedTimeoutMs;
    }
    // Fire-and-forget — heartbeat emission must not block the operation
    options.emit(`${options.stage}_heartbeat`, payload).catch(() => {});
  }, intervalMs);

  // .unref() ensures the timer does not keep the event loop alive
  timer.unref();

  try {
    return await operation;
  } finally {
    stopped = true;
    clearInterval(timer);
  }
}
