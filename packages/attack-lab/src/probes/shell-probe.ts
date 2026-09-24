import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import type { ProbeObservation } from '../../../evidence-plane/src/contracts.js';
import type { SecurityLabProbe, SecurityLabTarget } from '../types/runfile.js';

export async function runShellProbe(
  probe: Extract<SecurityLabProbe, { kind: 'shell_command' }>,
  target: Extract<SecurityLabTarget, { kind: 'shell' }>,
): Promise<ProbeObservation> {
  const startedAt = Date.now();

  return new Promise<ProbeObservation>((resolvePromise, reject) => {
    const child = spawn(probe.command[0]!, probe.command.slice(1), {
      cwd: resolveShellCwd(probe.cwd ?? target.cwd),
      // Deliberately NOT `...process.env`: a probe runs a command derived from
      // model output, so inheriting the operator's environment would hand it
      // API keys, cloud credentials and an SSH agent. Only PATH is carried
      // over; everything else must be declared by the target or the probe.
      env: {
        PATH: process.env.PATH ?? '/usr/bin:/bin',
        ...(target.env ?? {}),
        ...(probe.env ?? {}),
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];

    const timeout = setTimeout(() => {
      child.kill('SIGTERM');
      reject(new Error(`Shell probe timed out after ${probe.timeoutMs}ms`));
    }, probe.timeoutMs);

    child.stdout.on('data', (chunk: Buffer) => {
      stdoutChunks.push(chunk);
    });

    child.stderr.on('data', (chunk: Buffer) => {
      stderrChunks.push(chunk);
    });

    child.on('error', (error) => {
      clearTimeout(timeout);
      reject(error);
    });

    child.on('close', (exitCode) => {
      clearTimeout(timeout);
      resolvePromise({
        kind: probe.kind,
        exitCode,
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
        durationMs: Date.now() - startedAt,
      });
    });
  });
}

function resolveShellCwd(cwd: string | undefined): string | undefined {
  if (!cwd) {
    return undefined;
  }
  return resolve(cwd);
}

