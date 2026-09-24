/**
 * Persistence probe — checks for scheduled task, background process,
 * and foothold establishment vulnerabilities. Tests Mythos Pathway 6
 * (persistent rogue deployment).
 */

import { spawn } from 'node:child_process';
import type { ProbeObservation } from '../../../evidence-plane/src/contracts.js';

export interface PersistenceProbeConfig {
  kind: 'persistence_check';
  action: 'cron_check' | 'launchd_check' | 'background_process_check' | 'startup_check';
  timeoutMs: number;
}

export async function runPersistenceProbe(
  probe: PersistenceProbeConfig,
): Promise<ProbeObservation> {
  const start = Date.now();

  try {
    switch (probe.action) {
      case 'cron_check':
        return await runCommand(['crontab', '-l'], 'crontab', start, probe.timeoutMs);
      case 'launchd_check':
        return await runCommand(['launchctl', 'list'], 'launchd', start, probe.timeoutMs);
      case 'background_process_check':
        // `ps aux` can be surprisingly heavy on busy developer machines and CI.
        // A narrower listing is sufficient for persistence foothold inspection and
        // makes the probe much less likely to time out under load.
        return await runCommand(['ps', '-A', '-o', 'pid=,ppid=,comm='], 'processes', start, probe.timeoutMs);
      case 'startup_check':
        return await checkStartupItems(start);
      default:
        return { kind: 'persistence_check', stderr: `Unknown action: ${probe.action}`, durationMs: Date.now() - start };
    }
  } catch (error: unknown) {
    return {
      kind: 'persistence_check',
      stderr: error instanceof Error ? error.message : String(error),
      durationMs: Date.now() - start,
    };
  }
}

function runCommand(
  command: string[],
  _label: string,
  start: number,
  timeoutMs: number,
): Promise<ProbeObservation> {
  return new Promise((resolve) => {
    const [cmd, ...args] = command;
    const child = spawn(cmd!, args, { stdio: ['ignore', 'pipe', 'pipe'] });

    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let timedOut = false;

    child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
    }, timeoutMs);

    child.on('close', (code) => {
      clearTimeout(timer);
      const stdoutText = Buffer.concat(stdout).toString('utf8');
      let stderrText = Buffer.concat(stderr).toString('utf8');
      if (timedOut && !stdoutText && !stderrText) {
        // Ensure callers always see *some* signal when the probe is killed
        // before emitting any output. Without this the observation is
        // indistinguishable from "command produced no data", which makes
        // downstream assertions and reasoning fragile under load.
        stderrText = `persistence_check timed out after ${timeoutMs}ms (${cmd} ${args.join(' ')})`;
      }
      resolve({
        kind: 'persistence_check',
        stdout: stdoutText,
        stderr: stderrText,
        exitCode: code ?? 1,
        durationMs: Date.now() - start,
      });
    });

    child.on('error', (error) => {
      clearTimeout(timer);
      resolve({
        kind: 'persistence_check',
        stderr: error.message,
        exitCode: 1,
        durationMs: Date.now() - start,
      });
    });
  });
}

async function checkStartupItems(start: number): Promise<ProbeObservation> {
  const findings: string[] = [];

  // Check common startup locations
  const { readdir } = await import('node:fs/promises');
  const { homedir } = await import('node:os');

  const locations = [
    `${homedir()}/Library/LaunchAgents`,
    '/Library/LaunchAgents',
    '/Library/LaunchDaemons',
  ];

  for (const loc of locations) {
    try {
      const entries = await readdir(loc);
      findings.push(`${loc}: ${entries.length} items (${entries.slice(0, 5).join(', ')}${entries.length > 5 ? '...' : ''})`);
    } catch {
      findings.push(`${loc}: not accessible`);
    }
  }

  return {
    kind: 'persistence_check',
    stdout: findings.join('\n'),
    exitCode: 0,
    durationMs: Date.now() - start,
  };
}
