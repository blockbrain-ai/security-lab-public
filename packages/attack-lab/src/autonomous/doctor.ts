/**
 * Preflight doctor — runs before the first pipeline stage to verify
 * prerequisites are present. Fails fast in serious mode before any
 * provider budget is spent; records coverage gaps in smoke mode.
 *
 * Section 1.1: spec 2.5
 */

import { execFile } from 'node:child_process';
import { stat } from 'node:fs/promises';
import { promisify } from 'node:util';
import type { InvestigationTarget } from './target-profile.js';
import type { PreflightCheckResult } from '../../../evidence-plane/src/events/integrity-events.js';

const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PreflightReport {
  checks: PreflightCheckResult[];
  allPassed: boolean;
}

export interface PreflightContext {
  target: InvestigationTarget;
  campaignId: string;
  mode: string;
  preset?: string;
  /** Whether the portfolio expects a claude_code worker. */
  needsClaudeCode?: boolean;
  /** Whether the portfolio expects a codex_cli worker. */
  needsCodexCli?: boolean;
  /** Whether the portfolio expects a pi_cli worker. */
  needsPiCli?: boolean;
  /** Skip the preflight (--skip-preflight). */
  skipPreflight?: boolean;
  /** Allow degraded serious runs. */
  allowDegraded?: boolean;
}

export class PreflightFailedError extends Error {
  constructor(
    public readonly report: PreflightReport,
  ) {
    const failures = report.checks
      .filter((c) => c.status === 'fail')
      .map((c) => `${c.id}: ${c.message}`)
      .join('; ');
    super(`Preflight failed: ${failures}`);
    this.name = 'PreflightFailedError';
  }
}

// ---------------------------------------------------------------------------
// Main entry
// ---------------------------------------------------------------------------

export async function runPreflight(context: PreflightContext): Promise<PreflightReport> {
  const checks: PreflightCheckResult[] = [];

  // 1. Required workers present
  if (context.needsClaudeCode) {
    await checkBinaryAvailable('claude', ['--version'], checks, 'worker_claude_code', 'Claude Code CLI available on PATH');
  }
  if (context.needsCodexCli) {
    await checkBinaryAvailable('codex', ['--version'], checks, 'worker_codex_cli', 'Codex CLI available on PATH');
  }
  if (context.needsPiCli) {
    await checkBinaryAvailable('pi', ['--version'], checks, 'worker_pi_cli', 'Pi CLI available on PATH');
  }

  // 2. Docker / Linux runtime
  if (context.target.linuxSidecar && (context.target.linuxSidecar as Record<string, unknown>).enabled) {
    await checkBinaryAvailable('docker', ['--version'], checks, 'docker_runtime', 'Docker available for Linux sidecar');
  }

  // 3. Auth bootstrap
  if (context.target.authBootstrap) {
    checks.push({
      id: 'auth_bootstrap',
      status: 'pass',
      message: 'Auth bootstrap configuration present in target profile',
    });
  }

  // 4. Rollback declared for mutation canaries
  if (context.target.canaries && context.target.canaries.length > 0) {
    if (context.target.rollback) {
      checks.push({
        id: 'rollback_declared',
        status: 'pass',
        message: 'Rollback declared for target with mutation canaries',
      });
    } else {
      checks.push({
        id: 'rollback_declared',
        status: 'fail',
        message: 'Target has mutation canaries but no rollback declared',
      });
    }
  }

  // 5. Required identities resolvable
  if (context.target.requiredIdentities && context.target.requiredIdentities.length > 0) {
    const missing: string[] = [];
    for (const identity of context.target.requiredIdentities) {
      if (!process.env[identity]) {
        missing.push(identity);
      }
    }
    if (missing.length > 0) {
      checks.push({
        id: 'required_identities',
        status: 'fail',
        message: `Missing required identity env vars: ${missing.join(', ')}`,
      });
    } else {
      checks.push({
        id: 'required_identities',
        status: 'pass',
        message: 'All required identities resolvable',
      });
    }
  }

  // 6. Live target reachable
  if (context.target.baseUrl) {
    await checkLiveTargetReachable(context.target.baseUrl, checks);
  }

  // 7. Repo markers present
  const verificationPolicy = context.target.verificationPolicy as Record<string, unknown> | undefined;
  const expectedMarkers = (verificationPolicy?.expectedRepoMarkers as string[]) ?? ['package.json'];
  if (context.target.repoRoot) {
    await checkRepoMarkers(context.target.repoRoot, expectedMarkers, checks);
  }

  const allPassed = checks.every((c) => c.status !== 'fail');
  return { checks, allPassed };
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

async function checkBinaryAvailable(
  binary: string,
  args: string[],
  checks: PreflightCheckResult[],
  id: string,
  message: string,
): Promise<void> {
  try {
    await execFileAsync(binary, args, { timeout: 10_000 });
    checks.push({ id, status: 'pass', message });
  } catch {
    checks.push({ id, status: 'fail', message: `${message} — not found or not executable` });
  }
}

async function checkLiveTargetReachable(
  baseUrl: string,
  checks: PreflightCheckResult[],
): Promise<void> {
  try {
    const url = new URL(baseUrl);
    // Use a cheap fetch with a short timeout
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);
    try {
      const response = await fetch(url.toString(), {
        method: 'GET',
        signal: controller.signal,
        redirect: 'follow',
      });
      checks.push({
        id: 'live_target_reachable',
        status: 'pass',
        message: `Live target reachable at ${baseUrl} (HTTP ${response.status})`,
      });
    } finally {
      clearTimeout(timeout);
    }
  } catch (error) {
    checks.push({
      id: 'live_target_reachable',
      status: 'fail',
      message: `Live target unreachable at ${baseUrl}`,
      details: error instanceof Error ? error.message : String(error),
    });
  }
}

async function checkRepoMarkers(
  repoRoot: string,
  markers: string[],
  checks: PreflightCheckResult[],
): Promise<void> {
  const missing: string[] = [];
  for (const marker of markers) {
    try {
      await stat(`${repoRoot}/${marker}`);
    } catch {
      missing.push(marker);
    }
  }
  if (missing.length > 0) {
    checks.push({
      id: 'repo_markers',
      status: 'fail',
      message: `Missing repo markers: ${missing.join(', ')}`,
      details: `Expected in ${repoRoot}`,
    });
  } else {
    checks.push({
      id: 'repo_markers',
      status: 'pass',
      message: `Repo markers present: ${markers.join(', ')}`,
    });
  }
}
