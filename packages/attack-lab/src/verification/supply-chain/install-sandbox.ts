/**
 * Install sandbox — runs `npm install` (or pnpm/yarn equivalent) on
 * a quarantined package with no secrets, no network publish, and
 * strict filesystem boundaries. Used when static inspection alone
 * cannot determine whether the package is safe.
 */

import { spawn } from 'node:child_process';
import { mkdir, writeFile, readdir, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { ArtifactFetchResult, InstallSandboxResult } from './contracts.js';

// ---------------------------------------------------------------------------
// Sandbox options
// ---------------------------------------------------------------------------

export interface InstallSandboxOptions {
  packageManager: 'npm' | 'pnpm' | 'yarn';
  /** Hard timeout in ms. */
  timeoutMs?: number;
  /** Whether the sandbox is allowed to make any network calls. */
  allowNetwork?: boolean;
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

    // Snapshot baseline files outside sandbox so we can detect side effects.
    const homeDir = process.env.HOME ?? '';
    const baselineSnapshot = await this.snapshotPaths([homeDir]);

    const env = this.buildIsolatedEnv(options.allowNetwork ?? false);
    const args = options.packageManager === 'pnpm'
      ? ['install', '--ignore-scripts=false', '--frozen-lockfile=false']
      : options.packageManager === 'yarn'
        ? ['install']
        : ['install', '--no-audit', '--no-fund'];

    const start = Date.now();
    const { exitCode, stdout, stderr, killed } = await this.spawnBounded(
      options.packageManager,
      args,
      sandboxDir,
      env,
      options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
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
      exitCode,
      durationMs,
      stdoutTail: stdout.slice(-2_000),
      stderrTail: stderr.slice(-2_000),
      filesWrittenOutsideSandbox,
      networkAttempts,
      exceededTimeout: killed,
    };
  }

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
