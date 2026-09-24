/**
 * Auto-stop — incident detection for hosted probing. Tracks 5xx,
 * latency spikes, IAP redirects, WAF blocks, daily budgets, and
 * the kill switch. Once tripped, the campaign halts.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import type { AutoStopIncident } from './contracts.js';

// ---------------------------------------------------------------------------
// Auto-stop options
// ---------------------------------------------------------------------------

export interface AutoStopOptions {
  /** Path to the kill-switch file. */
  killSwitchPath?: string;
  /** Path where the daily budget counter is persisted. */
  budgetStatePath?: string;
  /** Hard daily request budget per host. */
  dailyBudget: number;
  /** Latency in ms above baseline that triggers a spike incident. */
  latencySpikeMs: number;
}

const DEFAULT_OPTIONS: AutoStopOptions = {
  killSwitchPath: '.security-lab-stop',
  dailyBudget: 500,
  latencySpikeMs: 5_000,
};

// ---------------------------------------------------------------------------
// Auto-stop monitor
// ---------------------------------------------------------------------------

interface BudgetState {
  date: string;
  count: number;
}

export class AutoStopMonitor {
  private incident: AutoStopIncident | null = null;
  private baselineLatency: number | null = null;
  private requestCount = 0;
  private readonly opts: AutoStopOptions;

  constructor(
    private readonly host: string,
    options: Partial<AutoStopOptions> = {},
  ) {
    this.opts = { ...DEFAULT_OPTIONS, ...options };
  }

  /**
   * Pre-flight check before sending any probe.
   * Returns the current incident if the campaign should halt.
   */
  preflight(): AutoStopIncident | null {
    if (this.incident) return this.incident;

    if (this.opts.killSwitchPath && existsSync(this.opts.killSwitchPath)) {
      this.incident = {
        reason: 'kill_switch',
        detail: `Kill switch file present: ${this.opts.killSwitchPath}`,
        at: new Date().toISOString(),
      };
      return this.incident;
    }

    const budget = this.loadBudget();
    if (budget.count >= this.opts.dailyBudget) {
      this.incident = {
        reason: 'daily_budget_exceeded',
        detail: `Daily budget ${this.opts.dailyBudget} exceeded for host ${this.host} (count=${budget.count})`,
        at: new Date().toISOString(),
      };
      return this.incident;
    }

    return null;
  }

  /**
   * Record the result of a probe and update incident state.
   */
  recordResult(status: number, durationMs: number, headers: Record<string, string>): AutoStopIncident | null {
    if (this.incident) return this.incident;

    this.requestCount += 1;
    this.persistBudget(this.loadBudget().count + 1);

    if (status >= 500) {
      this.incident = {
        reason: 'first_5xx',
        detail: `HTTP ${status} from ${this.host}`,
        at: new Date().toISOString(),
      };
      return this.incident;
    }

    // WAF block heuristic — 403 with WAF-typical headers/body
    if (status === 403) {
      const wafHeaders = ['cf-ray', 'x-amz-cf-id', 'x-sucuri-id', 'server'];
      for (const header of wafHeaders) {
        const value = headers[header]?.toLowerCase() ?? '';
        if (value.includes('waf') || value.includes('cloudflare') || value.includes('sucuri')) {
          this.incident = {
            reason: 'waf_block',
            detail: `WAF block detected (header ${header}=${value})`,
            at: new Date().toISOString(),
          };
          return this.incident;
        }
      }
    }

    // IAP redirect heuristic — 302 to accounts.google.com
    if (status === 302 || status === 307) {
      const location = headers['location']?.toLowerCase() ?? '';
      if (location.includes('accounts.google.com') || location.includes('iap.googleapis.com')) {
        this.incident = {
          reason: 'iap_redirect',
          detail: `IAP redirect to ${location}`,
          at: new Date().toISOString(),
        };
        return this.incident;
      }
    }

    // Latency spike
    if (this.baselineLatency === null) {
      this.baselineLatency = durationMs;
    } else {
      if (durationMs > this.baselineLatency * 3 || durationMs > this.opts.latencySpikeMs) {
        this.incident = {
          reason: 'latency_spike',
          detail: `Latency ${durationMs}ms exceeds baseline ${this.baselineLatency}ms`,
          at: new Date().toISOString(),
        };
        return this.incident;
      }
      this.baselineLatency = (this.baselineLatency + durationMs) / 2;
    }

    return null;
  }

  get current(): AutoStopIncident | null {
    return this.incident;
  }

  // ---------------------------------------------------------------------------
  // Budget persistence
  // ---------------------------------------------------------------------------

  private loadBudget(): BudgetState {
    const today = new Date().toISOString().slice(0, 10);
    const path = this.budgetPath();
    if (!path) return { date: today, count: 0 };
    try {
      const content = readFileSync(path, 'utf8');
      const parsed = JSON.parse(content) as BudgetState;
      if (parsed.date === today) return parsed;
      return { date: today, count: 0 };
    } catch {
      return { date: today, count: 0 };
    }
  }

  private persistBudget(count: number): void {
    const path = this.budgetPath();
    if (!path) return;
    try {
      mkdirSync(dirname(path), { recursive: true });
      const today = new Date().toISOString().slice(0, 10);
      writeFileSync(path, JSON.stringify({ date: today, count }), 'utf8');
    } catch {
      // ignore — budget enforcement is best-effort across crashes
    }
  }

  private budgetPath(): string | null {
    if (this.opts.budgetStatePath) return this.opts.budgetStatePath;
    return resolve('data', 'hosted-budget', `${sanitizeHost(this.host)}.json`);
  }
}

function sanitizeHost(host: string): string {
  return host.replace(/[^a-zA-Z0-9._-]/g, '_');
}
