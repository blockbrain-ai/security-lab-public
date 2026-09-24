/**
 * Runtime surface runner — bounded confirmation for findings about
 * the local process/persistence surface (env exposure, /proc visibility,
 * file descriptor leaks, startup hooks, cron, launchd, background
 * processes).
 *
 * Every check uses canary decoys and is read-only by default. The
 * runner never pivots into unrelated host resources — it confirms or
 * refutes the specific finding it was given, then stops.
 */

import { readFile, readdir, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { LiveProbeRequest, LiveExecutionResult } from './contracts.js';

// ---------------------------------------------------------------------------
// Runtime surface options
// ---------------------------------------------------------------------------

export interface RuntimeSurfaceOptions {
  /** Decoy markers we expect to find if the surface is leaking. */
  decoyMarkers?: string[];
  /** Limit on files we will inspect during a single check. */
  maxFilesPerCheck?: number;
  /** Limit on bytes we will read from any single file. */
  maxBytesPerFile?: number;
  /** Optional explicit working directory for persistence checks. */
  workingDir?: string;
}

const DEFAULT_OPTIONS: Required<Omit<RuntimeSurfaceOptions, 'workingDir'>> = {
  decoyMarkers: ['SECURITY_LAB_DECOY', 'SECURITY_LAB_CANARY'],
  maxFilesPerCheck: 50,
  maxBytesPerFile: 8_192,
};

// ---------------------------------------------------------------------------
// Public entrypoint
// ---------------------------------------------------------------------------

export async function executeRuntimeSurfaceProbe(
  probe: LiveProbeRequest,
  options: RuntimeSurfaceOptions = {},
): Promise<LiveExecutionResult> {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const probeId = `runtime-${probe.findingId}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const start = Date.now();

  if (probe.probeKind === 'process' && probe.process) {
    return runProcessCheck(probe, probeId, opts, start);
  }
  if (probe.probeKind === 'persistence' && probe.persistence) {
    return runPersistenceCheck(probe, probeId, opts, start);
  }

  return {
    probeId,
    findingId: probe.findingId,
    identityId: probe.identityId,
    request: { method: 'NONE', url: '', headers: {} },
    response: { status: 0, headers: {}, body: '', durationMs: Date.now() - start },
    rollbackExecuted: false,
    verdict: 'not_applicable',
    reasoning: `Runtime surface runner does not handle probeKind="${probe.probeKind}"`,
  };
}

// ---------------------------------------------------------------------------
// Process checks — env, fd, /proc, credential search
// ---------------------------------------------------------------------------

async function runProcessCheck(
  probe: LiveProbeRequest,
  probeId: string,
  opts: Required<Omit<RuntimeSurfaceOptions, 'workingDir'>> & RuntimeSurfaceOptions,
  start: number,
): Promise<LiveExecutionResult> {
  const action = probe.process!.action;
  const patterns = probe.process!.searchPatterns ?? opts.decoyMarkers;

  const observations: string[] = [];
  let leaked = false;

  try {
    switch (action) {
      case 'env_scan': {
        for (const [key, value] of Object.entries(process.env)) {
          if (!value) continue;
          for (const marker of patterns) {
            if (key.includes(marker) || value.includes(marker)) {
              leaked = true;
              observations.push(`env:${key} leaked marker "${marker}"`);
            }
          }
        }
        if (!leaked) observations.push('env_scan: no decoy markers visible in process.env');
        break;
      }

      case 'fd_scan': {
        // /proc/self/fd is Linux-only; on macOS we report not_applicable.
        const fdDir = '/proc/self/fd';
        try {
          const entries = await readdir(fdDir);
          const inspected = entries.slice(0, opts.maxFilesPerCheck);
          observations.push(`fd_scan: inspected ${inspected.length} of ${entries.length} fds`);
          for (const fd of inspected) {
            try {
              const linkPath = resolve(fdDir, fd);
              const info = await stat(linkPath);
              for (const marker of patterns) {
                if (linkPath.includes(marker)) {
                  leaked = true;
                  observations.push(`fd ${fd} → ${linkPath} contains marker "${marker}"`);
                }
              }
              if (info.size > 0 && info.size < opts.maxBytesPerFile) {
                // Don't actually read fd contents — link target inspection only
              }
            } catch {
              // ignore unreadable fds
            }
          }
        } catch {
          return {
            probeId,
            findingId: probe.findingId,
            identityId: probe.identityId,
            request: { method: 'fd_scan', url: fdDir, headers: {} },
            response: { status: 0, headers: {}, body: '', durationMs: Date.now() - start },
            rollbackExecuted: false,
            verdict: 'not_applicable',
            reasoning: 'fd_scan requires /proc/self/fd (Linux only)',
          };
        }
        break;
      }

      case 'proc_self_read': {
        const procPath = '/proc/self/environ';
        try {
          const content = await readFile(procPath, 'utf8');
          const normalized = content.replace(/\0/g, '\n');
          const truncated = normalized.slice(0, opts.maxBytesPerFile);
          for (const marker of patterns) {
            if (truncated.includes(marker)) {
              leaked = true;
              observations.push(`/proc/self/environ leaked marker "${marker}"`);
            }
          }
          if (!leaked) {
            observations.push('proc_self_read: no markers in /proc/self/environ');
          }
        } catch {
          return {
            probeId,
            findingId: probe.findingId,
            identityId: probe.identityId,
            request: { method: 'proc_self_read', url: procPath, headers: {} },
            response: { status: 0, headers: {}, body: '', durationMs: Date.now() - start },
            rollbackExecuted: false,
            verdict: 'not_applicable',
            reasoning: 'proc_self_read requires Linux /proc/self/environ access',
          };
        }
        break;
      }

      case 'credential_search': {
        // Read-only scan of well-known credential locations for decoy markers.
        const candidates = [
          '.env',
          '.env.local',
          '.env.development',
          'config/credentials.json',
        ];
        const baseDir = opts.workingDir ?? process.cwd();
        let inspected = 0;
        for (const candidate of candidates) {
          if (inspected >= opts.maxFilesPerCheck) break;
          try {
            const path = resolve(baseDir, candidate);
            const content = await readFile(path, 'utf8');
            inspected += 1;
            const truncated = content.slice(0, opts.maxBytesPerFile);
            for (const marker of patterns) {
              if (truncated.includes(marker)) {
                leaked = true;
                observations.push(`${candidate} leaked marker "${marker}"`);
              }
            }
          } catch {
            // file doesn't exist — skip
          }
        }
        observations.push(`credential_search: inspected ${inspected} files`);
        break;
      }
    }
  } catch (error) {
    return {
      probeId,
      findingId: probe.findingId,
      identityId: probe.identityId,
      request: { method: action, url: '', headers: {} },
      response: { status: 0, headers: {}, body: '', durationMs: Date.now() - start },
      rollbackExecuted: false,
      verdict: 'runtime_error',
      reasoning: error instanceof Error ? error.message : String(error),
    };
  }

  return {
    probeId,
    findingId: probe.findingId,
    identityId: probe.identityId,
    request: { method: action, url: '', headers: {} },
    response: {
      status: leaked ? 200 : 404,
      headers: {},
      body: observations.join('\n'),
      durationMs: Date.now() - start,
    },
    canaryMatched: leaked ? 'exploitable' : 'safe',
    rollbackExecuted: false,
    verdict: leaked ? 'confirmed' : 'refuted',
    reasoning: leaked
      ? `Runtime surface leak confirmed: ${observations.filter((o) => o.includes('leaked')).join('; ')}`
      : `No leak observed during ${action}`,
  };
}

// ---------------------------------------------------------------------------
// Persistence checks — startup hooks, cron, launchd, background processes
// ---------------------------------------------------------------------------

async function runPersistenceCheck(
  probe: LiveProbeRequest,
  probeId: string,
  opts: Required<Omit<RuntimeSurfaceOptions, 'workingDir'>> & RuntimeSurfaceOptions,
  start: number,
): Promise<LiveExecutionResult> {
  const action = probe.persistence!.action;
  const observations: string[] = [];
  let footholdFound = false;

  try {
    switch (action) {
      case 'startup_check': {
        // Inspect package.json scripts and well-known startup files for
        // decoy-marker injection.
        const baseDir = opts.workingDir ?? process.cwd();
        const candidates = ['package.json', 'pnpm-workspace.yaml', '.npmrc'];
        for (const candidate of candidates) {
          try {
            const path = resolve(baseDir, candidate);
            const content = (await readFile(path, 'utf8')).slice(0, opts.maxBytesPerFile);
            for (const marker of opts.decoyMarkers) {
              if (content.includes(marker)) {
                footholdFound = true;
                observations.push(`${candidate} contains decoy marker "${marker}"`);
              }
            }
          } catch {
            // missing file — skip
          }
        }
        observations.push('startup_check: scanned package.json + workspace configs');
        break;
      }

      case 'cron_check': {
        // crontab inspection — read-only, requires the user crontab to be
        // available via the standard path. We do not exec `crontab -l`.
        const candidates = ['/etc/crontab', '/var/spool/cron'];
        for (const candidate of candidates) {
          try {
            const info = await stat(candidate);
            observations.push(`cron_check: ${candidate} present (size=${info.size})`);
          } catch {
            observations.push(`cron_check: ${candidate} not present`);
          }
        }
        break;
      }

      case 'launchd_check': {
        // macOS launchd plists — read-only directory listing.
        const candidates = [
          `${process.env.HOME ?? ''}/Library/LaunchAgents`,
          '/Library/LaunchAgents',
          '/Library/LaunchDaemons',
        ];
        for (const candidate of candidates) {
          if (!candidate) continue;
          try {
            const entries = (await readdir(candidate)).slice(0, opts.maxFilesPerCheck);
            observations.push(`launchd_check: ${candidate} → ${entries.length} entries`);
            for (const entry of entries) {
              for (const marker of opts.decoyMarkers) {
                if (entry.includes(marker)) {
                  footholdFound = true;
                  observations.push(`launchd plist "${entry}" matches decoy marker`);
                }
              }
            }
          } catch {
            observations.push(`launchd_check: ${candidate} unavailable`);
          }
        }
        break;
      }

      case 'background_process_check': {
        // We never spawn `ps`. Instead, we inspect /proc on Linux for our
        // decoy markers; on macOS this returns not_applicable.
        try {
          const entries = (await readdir('/proc')).filter((e) => /^\d+$/.test(e));
          const inspected = entries.slice(0, opts.maxFilesPerCheck);
          observations.push(
            `background_process_check: inspected ${inspected.length} of ${entries.length} pids`,
          );
          for (const pid of inspected) {
            try {
              const cmdline = (await readFile(`/proc/${pid}/cmdline`, 'utf8')).slice(
                0,
                opts.maxBytesPerFile,
              );
              for (const marker of opts.decoyMarkers) {
                if (cmdline.includes(marker)) {
                  footholdFound = true;
                  observations.push(`pid ${pid} cmdline contains decoy marker "${marker}"`);
                }
              }
            } catch {
              // skip unreadable processes
            }
          }
        } catch {
          return {
            probeId,
            findingId: probe.findingId,
            identityId: probe.identityId,
            request: { method: action, url: '/proc', headers: {} },
            response: { status: 0, headers: {}, body: '', durationMs: Date.now() - start },
            rollbackExecuted: false,
            verdict: 'not_applicable',
            reasoning: 'background_process_check requires Linux /proc filesystem',
          };
        }
        break;
      }
    }
  } catch (error) {
    return {
      probeId,
      findingId: probe.findingId,
      identityId: probe.identityId,
      request: { method: action, url: '', headers: {} },
      response: { status: 0, headers: {}, body: '', durationMs: Date.now() - start },
      rollbackExecuted: false,
      verdict: 'runtime_error',
      reasoning: error instanceof Error ? error.message : String(error),
    };
  }

  return {
    probeId,
    findingId: probe.findingId,
    identityId: probe.identityId,
    request: { method: action, url: '', headers: {} },
    response: {
      status: footholdFound ? 200 : 404,
      headers: {},
      body: observations.join('\n'),
      durationMs: Date.now() - start,
    },
    canaryMatched: footholdFound ? 'exploitable' : 'safe',
    rollbackExecuted: false,
    verdict: footholdFound ? 'confirmed' : 'refuted',
    reasoning: footholdFound
      ? `Persistence foothold confirmed: ${observations.filter((o) => o.includes('marker') || o.includes('decoy')).join('; ')}`
      : `No persistence foothold observed during ${action}`,
  };
}
