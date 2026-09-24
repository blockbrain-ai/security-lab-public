/**
 * Rate limiter — bounded request rate per host with both
 * requests-per-second and per-campaign caps.
 */

export interface RateLimiterConfig {
  /** Maximum requests per second. */
  requestsPerSecond: number;
  /** Maximum total requests per campaign. */
  maxRequestsPerCampaign: number;
  /** Auto-stop after this many consecutive 5xx responses. */
  autoStopOn5xxStreak: number;
  /** Auto-stop if average response time doubles compared to baseline. */
  autoStopOnLatencyDoubling: boolean;
}

export const DEFAULT_LOCAL_LIVE_LIMITER: RateLimiterConfig = {
  requestsPerSecond: 10,
  maxRequestsPerCampaign: 1000,
  autoStopOn5xxStreak: 5,
  autoStopOnLatencyDoubling: true,
};

export const DEFAULT_HOSTED_LIMITER: RateLimiterConfig = {
  requestsPerSecond: 1,
  maxRequestsPerCampaign: 100,
  autoStopOn5xxStreak: 1,
  autoStopOnLatencyDoubling: true,
};

// ---------------------------------------------------------------------------
// Rate limiter implementation
// ---------------------------------------------------------------------------

export class RateLimiter {
  private readonly config: RateLimiterConfig;
  private requestCount = 0;
  private fiveXxStreak = 0;
  private latencyHistory: number[] = [];
  private lastRequestAt = 0;
  private stopped = false;
  private stopReason: string | null = null;

  constructor(config: RateLimiterConfig) {
    this.config = config;
  }

  /**
   * Wait until the next request slot is available, or throw if stopped.
   */
  async acquire(): Promise<void> {
    if (this.stopped) {
      throw new Error(`Rate limiter stopped: ${this.stopReason}`);
    }

    if (this.requestCount >= this.config.maxRequestsPerCampaign) {
      this.stop('campaign request budget exhausted');
      throw new Error(`Rate limiter stopped: ${this.stopReason}`);
    }

    const minInterval = 1000 / this.config.requestsPerSecond;
    const now = Date.now();
    const elapsed = now - this.lastRequestAt;
    if (elapsed < minInterval) {
      await new Promise((resolve) => setTimeout(resolve, minInterval - elapsed));
    }
    this.lastRequestAt = Date.now();
    this.requestCount++;
  }

  /**
   * Record the result of a request to update auto-stop counters.
   */
  recordResult(status: number, durationMs: number): void {
    if (status >= 500) {
      this.fiveXxStreak++;
      if (this.fiveXxStreak >= this.config.autoStopOn5xxStreak) {
        this.stop(`${this.fiveXxStreak} consecutive 5xx responses`);
      }
    } else {
      this.fiveXxStreak = 0;
    }

    this.latencyHistory.push(durationMs);
    if (this.latencyHistory.length > 20) {
      this.latencyHistory.shift();
    }

    if (this.config.autoStopOnLatencyDoubling && this.latencyHistory.length >= 10) {
      const baseline = this.latencyHistory.slice(0, 5).reduce((a, b) => a + b, 0) / 5;
      const recent = this.latencyHistory.slice(-5).reduce((a, b) => a + b, 0) / 5;
      if (recent > baseline * 2 && recent > 1000) {
        this.stop(`average latency doubled: ${baseline.toFixed(0)}ms → ${recent.toFixed(0)}ms`);
      }
    }
  }

  /**
   * Manually stop the rate limiter.
   */
  stop(reason: string): void {
    this.stopped = true;
    this.stopReason = reason;
  }

  isStopped(): boolean {
    return this.stopped;
  }

  getStopReason(): string | null {
    return this.stopReason;
  }

  getRequestCount(): number {
    return this.requestCount;
  }

  getRemainingBudget(): number {
    return Math.max(0, this.config.maxRequestsPerCampaign - this.requestCount);
  }
}
