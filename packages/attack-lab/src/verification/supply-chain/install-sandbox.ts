/**
 * Install sandbox — runs a package manager against a quarantined tarball so
 * that install-time behaviour (lifecycle scripts, native builds) can be
 * observed. Used when static inspection alone cannot decide whether a package
 * is safe.
 *
 * Running a package's install scripts means executing that package's code, so
 * this step is fail-closed in two ways:
 *
 * 1. It does not run at all unless a caller explicitly enables it (see
 *    `ConfirmationRunnerOptions.enableInstallSandbox`), and
 * 2. it refuses to execute without a real isolation backend. The only backend
 *    implemented is Docker, invoked with no network, a read-only root
 *    filesystem, dropped capabilities and no host mounts beyond the sandbox
 *    directory. A proxy-variable "network block" is not isolation, and the
 *    host is never used to execute a target's install scripts.
 */

import { spawn } from 'node:child_process';
import { mkdir, writeFile, readdir, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { ArtifactFetchResult, InstallSandboxResult } from './contracts.js';

// ---------------------------------------------------------------------------
// Sandbox options
// ---------------------------------------------------------------------------

export interface DockerIsolation {
  kind: 'docker';
  /** Image providing the package manager (default `node:20-bookworm-slim`). */
  image?: string;
  /** Container user (default `65534:65534`, i.e. nobody). */
  user?: string;
  /** Docker binary (default `docker`). */
  binary?: string;
}

export type InstallSandboxIsolation = DockerIsolation;

/** Injection point so command construction can be tested without Docker. */
export type InstallSpawnFn = (
  command: string,
  args: string[],
  options: { cwd: string; env: NodeJS.ProcessEnv; timeoutMs: number },
) => Promise<{ exitCode: number; stdout: string; stderr: string; killed: boolean }>;

export interface InstallSandboxOptions {
  packageManager: 'npm' | 'pnpm' | 'yarn';
  /** Hard timeout in ms. */
  timeoutMs?: number;
  /** Whether the isolated install may reach the network (default false). */
  allowNetwork?: boolean;
  /**
   * Isolation backend. Omitted means "do not execute" — the step is recorded
   * as skipped rather than run on the host.
   */
  isolation?: InstallSandboxIsolation;
  /** Test seam; defaults to a bounded child process. */
  spawnFn?: InstallSpawnFn;
}

const DEFAULT_TIMEOUT_MS = 90_000;

// ---------------------------------------------------------------------------
// Install sandbox
// ---------------------------------------------------------------------------

export class InstallSandbox {
  async run(
    fetched: ArtifactFetchResult,
    options: InstallSandboxOptions,
  ): Promise<InstallSandboxResult> {
    const sandboxDir = resolve(fetched.unpackedPath, '..', 'install-sandbox');
    await mkdir(sandboxDir, { recursive: true });

    // Create a minimal package.json that depends on the quarantined tarball.
    const wrapperPackageJson = {
      name: 'security-lab-supply-chain-sandbox',
      version: '0.0.0',
      private: true,
      dependencies: {
        [fetched.packageName]: `file:${fetched.tarballPath}`,
      },
    };
    await writeFile(
      resolve(sandboxDir, 'package.json'),
      JSON.stringify(wrapperPackageJson, null, 2),
      'utf8',
    );

    // Fail closed: without an isolation backend nothing is executed.
    const isolation = options.isolation;
    if (!isolation) {
      return {
        packageName: fetched.packageName,
        version: fetched.version,
        executed: false,
        isolation: 'none',
        skippedReason:
          'Install execution is disabled: no isolation backend was configured. ' +
          'Supply options.isolation = { kind: "docker" } (and enable install execution on the ' +
          'runner) to observe install-time behaviour inside a container.',
        exitCode: -1,
        durationMs: 0,
        stdoutTail: '',
        stderrTail: '',
        filesWrittenOutsideSandbox: [],
        networkAttempts: [],
        exceededTimeout: false,
      };
    }

    // Snapshot baseline files outside sandbox so we can detect side effects.
    const homeDir = process.env.HOME ?? '';
    const baselineSnapshot = await this.snapshotPaths([homeDir]);

    const containerArgs = this.buildContainerArgs(
      isolation,
      options,
      sandboxDir,
    );
    const start = Date.now();
    const spawnFn: InstallSpawnFn = options.spawnFn ?? ((command, args, opts) =>
      this.spawnBounded(command, args, opts.cwd, opts.env, opts.timeoutMs));
    const { exitCode, stdout, stderr, killed } = await spawnFn(
      isolation.binary ?? 'docker',
      containerArgs,
      {
        cwd: sandboxDir,
        // The docker CLI needs the operator's PATH to find the daemon socket;
        // everything else stays out of the container.
        env: { PATH: process.env.PATH ?? '/usr/bin:/bin' },
        timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      },
    );
    const durationMs = Date.now() - start;

    const postSnapshot = await this.snapshotPaths([homeDir]);
    const filesWrittenOutsideSandbox = this.diffSnapshots(baselineSnapshot, postSnapshot);

    // We approximate network attempts by scanning stderr/stdout for known markers.
    const networkAttempts: string[] = [];
    const combinedOutput = `${stdout}\n${stderr}`;
    const networkMarkers = ['ECONNREFUSED', 'getaddrinfo', 'ENOTFOUND', 'connect EHOST'];
    for (const marker of networkMarkers) {
      if (combinedOutput.includes(marker)) {
        networkAttempts.push(`output mentioned "${marker}"`);
      }
    }

    return {
      packageName: fetched.packageName,
      version: fetched.version,
      executed: true,
      isolation: 'docker',
      exitCode,
      durationMs,
      stdoutTail: stdout.slice(-2_000),
      stderrTail: stderr.slice(-2_000),
      filesWrittenOutsideSandbox,
      networkAttempts,
      exceededTimeout: killed,
    };
  }

  /**
   * Container invocation for an isolated install. No network, read-only root
   * filesystem, all capabilities dropped, no-new-privileges, non-root user,
   * and exactly one host mount (the sandbox work directory).
   */
  private buildContainerArgs(
    isolation: DockerIsolation,
    options: InstallSandboxOptions,
    sandboxDir: string,
  ): string[] {
    const installArgs = options.packageManager === 'pnpm'
      ? ['install', '--ignore-scripts=false', '--frozen-lockfile=false']
      : options.packageManager === 'yarn'
        ? ['install']
        : ['install', '--no-audit', '--no-fund', '--ignore-scripts=false'];

    const args = [
      'run',
      '--rm',
      options.allowNetwork === true ? '--network=bridge' : '--network=none',
      '--read-only',
      '--cap-drop=ALL',
      '--security-opt=no-new-privileges',
      '--user',
      isolation.user ?? '65534:65534',
      '--tmpfs',
      '/tmp:rw,exec',
      '--tmpfs',
      '/home/node:rw',
      '-e',
      'HOME=/tmp',
      '-e',
      'npm_config_cache=/tmp/.npm',
      '-e',
      'npm_config_update_notifier=false',
      '-v',
      `${sandboxDir}:/work:rw`,
      '-w',
      '/work',
      isolation.image ?? 'node:20-bookworm-slim',
      options.packageManager,
      ...installArgs,
    ];
    return args;
  }

  /** Environment for the (isolated) install; never the operator's env. */
  private buildIsolatedEnv(allowNetwork: boolean): NodeJS.ProcessEnv {
    const env: NodeJS.ProcessEnv = {
      PATH: process.env.PATH ?? '/usr/bin:/bin',
      HOME: '/tmp/security-lab-sandbox-home',
      NODE_ENV: 'test',
      SECURITY_LAB_SANDBOX: '1',
    };
    if (!allowNetwork) {
      env.HTTP_PROXY = 'http://127.0.0.1:1';
      env.HTTPS_PROXY = 'http://127.0.0.1:1';
      env.NO_PROXY = '';
    }
    return env;
  }

  private spawnBounded(
    command: string,
    args: string[],
    cwd: string,
    env: NodeJS.ProcessEnv,
    timeoutMs: number,
  ): Promise<{ exitCode: number; stdout: string; stderr: string; killed: boolean }> {
    return new Promise((resolvePromise) => {
      const child = spawn(command, args, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'] });
      let stdout = '';
      let stderr = '';
      let killed = false;

      const timer = setTimeout(() => {
        killed = true;
        child.kill('SIGKILL');
      }, timeoutMs);

      child.stdout?.on('data', (chunk) => {
        stdout += chunk.toString('utf8');
        if (stdout.length > 200_000) stdout = stdout.slice(-100_000);
      });
      child.stderr?.on('data', (chunk) => {
        stderr += chunk.toString('utf8');
        if (stderr.length > 200_000) stderr = stderr.slice(-100_000);
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        resolvePromise({ exitCode: code ?? -1, stdout, stderr, killed });
      });
      child.on('error', (error) => {
        clearTimeout(timer);
        stderr += `\n${error.message}`;
        resolvePromise({ exitCode: -1, stdout, stderr, killed });
      });
    });
  }

  private async snapshotPaths(paths: string[]): Promise<Map<string, number>> {
    const snapshot = new Map<string, number>();
    for (const path of paths) {
      if (!path) continue;
      try {
        const entries = await readdir(path);
        for (const entry of entries.slice(0, 200)) {
          try {
            const info = await stat(resolve(path, entry));
            snapshot.set(resolve(path, entry), info.mtimeMs);
          } catch {
            continue;
          }
        }
      } catch {
        continue;
      }
    }
    return snapshot;
  }

  private diffSnapshots(before: Map<string, number>, after: Map<string, number>): string[] {
    const changes: string[] = [];
    for (const [path, mtime] of after.entries()) {
      const previous = before.get(path);
      if (previous === undefined) {
        changes.push(`new: ${path}`);
      } else if (previous !== mtime) {
        changes.push(`modified: ${path}`);
      }
    }
    return changes;
  }
}
