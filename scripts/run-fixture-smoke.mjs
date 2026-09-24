import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const cwd = new URL('..', import.meta.url);
const tsxCli = fileURLToPath(new URL('../node_modules/tsx/dist/cli.mjs', import.meta.url));
const nonce = randomBytes(8).toString('hex');

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * The fixture runfiles target a fixed port, so this must match. A stale server
 * left on that port is detected two ways: the spawned server exits immediately
 * with EADDRINUSE (handled below), and the health check must echo this run's
 * nonce, so an older process cannot be mistaken for the one we just started.
 */
const port = Number(process.env.SECURITY_LAB_FIXTURE_PORT ?? 4317);
const baseUrl = `http://127.0.0.1:${port}/health`;

let serverExit = null;
let serverError = null;
const server = spawn(process.execPath, [tsxCli, 'packages/attack-lab/src/testing/fixture-server.ts'], {
  cwd,
  stdio: 'inherit',
  shell: false,
  env: {
    ...process.env,
    SECURITY_LAB_FIXTURE_PORT: String(port),
    SECURITY_LAB_FIXTURE_NONCE: nonce,
  },
});
server.on('exit', (code, signal) => {
  serverExit = { code, signal };
});
server.on('error', (error) => {
  serverError = error;
});

async function waitForFixtureServer() {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    if (serverError) {
      throw new Error(`Fixture server failed to start: ${serverError.message}`);
    }
    if (serverExit) {
      throw new Error(
        `Fixture server exited before becoming healthy (code ${serverExit.code ?? 'null'}, signal ${serverExit.signal ?? 'none'}).`,
      );
    }
    try {
      const response = await fetch(baseUrl);
      if (response.ok) {
        const body = await response.json();
        if (body.nonce !== nonce) {
          throw new Error(
            `Health check on port ${port} answered by a different process (nonce mismatch) — refusing to test against a stale server.`,
          );
        }
        return;
      }
    } catch (error) {
      if (error instanceof Error && error.message.includes('nonce mismatch')) {
        throw error;
      }
      // Server still starting.
    }
    await wait(250);
  }
  throw new Error('Fixture server did not become healthy in time.');
}

async function runCommand(args) {
  await new Promise((resolve, reject) => {
    const child = spawn('npm', args, {
      cwd,
      stdio: 'inherit',
      shell: false,
    });

    child.on('exit', (code) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(`Command failed: npm ${args.join(' ')} (exit ${code ?? 'unknown'})`));
    });
    child.on('error', reject);
  });
}

try {
  await waitForFixtureServer();
  await runCommand(['run', 'lab:run', '--', 'runfiles/fixture-http-smoke.yaml']);
  await runCommand(['run', 'lab:run', '--', 'runfiles/fixture-shell-smoke.yaml']);
  await runCommand(['run', 'lab:run', '--', 'runfiles/fixture-chain-canary.yaml']);
} finally {
  if (serverExit === null) {
    server.kill('SIGTERM');
    await wait(250);
    if (serverExit === null) {
      server.kill('SIGKILL');
    }
  }
}
