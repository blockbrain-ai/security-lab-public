import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { chmod, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import type { InvestigationTarget } from '../../autonomous/target-profile.js';
import { prepareLocalAuthBootstrap, containsProductionMarker } from './auth-bootstrap.js';
import { prepareLocalTargetSession } from './target-lifecycle.js';

test('prepareLocalAuthBootstrap mints Fixture canary JWTs and writes an env file', { concurrency: false }, async () => {
  const campaignDir = await mkdtemp(resolve(tmpdir(), 'security-lab-bootstrap-'));
  const target: InvestigationTarget = {
    id: 'fixture-local',
    name: 'Fixture Local',
    kind: 'http',
    environment: 'local_live',
    baseUrl: 'http://localhost:4000',
    hints: {},
    supportedProbeKinds: [],
    identities: [
      { id: 'guest', kind: 'anonymous' },
      { id: 'user_a_low', kind: 'bearer_token', tokenEnv: 'TARGET_USER_A_TOKEN', organizationId: 'org-a', expectedRole: 'user' },
      { id: 'admin_canary', kind: 'bearer_token', tokenEnv: 'BOS_ADMIN_CANARY_TOKEN', expectedRole: 'admin' },
    ],
    authBootstrap: { type: 'fixture_local_jwt', secret: 'test-secret' },
  };

  const result = await prepareLocalAuthBootstrap(target, campaignDir);
  assert.ok(result);
  assert.ok(result.identityEnv['TARGET_USER_A_TOKEN']);
  assert.ok(result.identityEnv['BOS_ADMIN_CANARY_TOKEN']);
  assert.equal(result.environment['FIXTURE_JWT_SECRET'], 'test-secret');
  assert.match(result.environment['CHANNEL_ENCRYPTION_KEY'] ?? '', /^[0-9a-f]{64}$/i);
  assert.equal(result.issuedIdentities.length, 2);

  const envFile = await readFile(result.envFilePath!, 'utf8');
  assert.match(envFile, /TARGET_USER_A_TOKEN=/);
  assert.match(envFile, /BOS_ADMIN_CANARY_TOKEN=/);
  assert.match(envFile, /CHANNEL_ENCRYPTION_KEY=/);
});

test('containsProductionMarker detects production-looking secrets (Section 3.1)', () => {
  assert.equal(containsProductionMarker('prod_abc123'), true);
  assert.equal(containsProductionMarker('live_key_xyz'), true);
  assert.equal(containsProductionMarker('real_user_secret'), true);
  assert.equal(containsProductionMarker('test-secret'), false);
  assert.equal(containsProductionMarker('canary-secret'), false);
});

test('prepareLocalAuthBootstrap refuses production secrets and emits coverage_gap (Section 3.1)', { concurrency: false }, async () => {
  const campaignDir = await mkdtemp(resolve(tmpdir(), 'security-lab-bootstrap-prod-'));
  const events: Array<{ stage: string; payload: Record<string, unknown> }> = [];
  const target: InvestigationTarget = {
    id: 'fixture-local',
    name: 'Fixture Local',
    kind: 'http',
    environment: 'local_live',
    baseUrl: 'http://localhost:4000',
    hints: {},
    supportedProbeKinds: [],
    identities: [
      { id: 'user_a_low', kind: 'bearer_token', tokenEnv: 'TARGET_USER_A_TOKEN', expectedRole: 'user' },
    ],
    authBootstrap: { type: 'fixture_local_jwt', secret: 'prod_very_real_secret' },
  };

  const result = await prepareLocalAuthBootstrap(target, campaignDir, {
    onEvent: (stage, payload) => events.push({ stage, payload }),
  });
  assert.equal(result, null, 'must refuse to mint canary credentials from a production secret');
  const gap = events.find((e) => e.stage === 'coverage_gap');
  assert.ok(gap, 'coverage_gap event emitted');
  assert.equal(gap?.payload.code, 'auth_bootstrap_refused_production_secret');
});

test('prepareLocalTargetSession creates a compose override and executes startup/shutdown commands', { concurrency: false }, async () => {
  const campaignDir = await mkdtemp(resolve(tmpdir(), 'security-lab-local-target-'));
  const repoRoot = await mkdtemp(resolve(tmpdir(), 'security-lab-compose-root-'));
  const binaryPath = resolve(campaignDir, 'docker');
  const logPath = resolve(campaignDir, 'docker.log');

  await writeFile(binaryPath, `#!/bin/sh
echo "$@" >> ${JSON.stringify(logPath)}
exit 0
`, 'utf8');
  await chmod(binaryPath, 0o755);

  const target: InvestigationTarget = {
    id: 'fixture-local-live-linux',
    name: 'Fixture Local Live Linux',
    kind: 'http',
    environment: 'local_live',
    baseUrl: undefined,
    repoRoot,
    cwd: repoRoot,
    hints: {},
    supportedProbeKinds: [],
    identities: [
      { id: 'user_a_low', kind: 'bearer_token', tokenEnv: 'TARGET_USER_A_TOKEN', organizationId: 'org-a', expectedRole: 'user' },
    ],
    authBootstrap: { type: 'fixture_local_jwt', secret: 'bootstrap-secret' },
    linuxSidecar: { composeService: 'backend', buildOnStartup: true },
    localStartup: {
      command: binaryPath,
      cwd: repoRoot,
      args: ['compose', 'up', '-d', 'backend'],
      env: {
        COMPOSE_PROJECT_NAME: 'bos-security-lab',
      },
      timeoutMs: 5000,
    },
    localShutdown: {
      command: binaryPath,
      cwd: repoRoot,
      args: ['compose', 'down'],
      env: {
        COMPOSE_PROJECT_NAME: 'bos-security-lab',
      },
      timeoutMs: 5000,
    },
    processDecoys: {
      envMarkers: ['SECURITY_LAB_DECOY'],
    },
    verificationPolicy: {
      cleanStartup: true,
      removeVolumesOnShutdown: true,
    },
  };

  const session = await prepareLocalTargetSession(target, campaignDir);
  assert.ok(session.composeOverridePath);
  const override = await readFile(session.composeOverridePath!, 'utf8');
  assert.match(override, /backend:/);
  assert.match(override, /FIXTURE_JWT_SECRET/);
  assert.match(override, /SECURITY_LAB_MARKER_1/);
  assert.doesNotMatch(override, /ports: !override/);

  await session.stop();

  const log = await readFile(logPath, 'utf8');
  assert.match(log, /compose -f docker-compose\.yml -f .*compose\.override\.yaml down --remove-orphans -v/);
  assert.match(log, /compose -f docker-compose\.yml -f .*compose\.override\.yaml up --build -d backend/);
  assert.match(log, /compose -f docker-compose\.yml -f .*compose\.override\.yaml down --remove-orphans -v/);
});

test('prepareLocalTargetSession writes compose port overrides for isolated local-live targets', { concurrency: false }, async () => {
  const campaignDir = await mkdtemp(resolve(tmpdir(), 'security-lab-local-target-ports-'));
  const repoRoot = await mkdtemp(resolve(tmpdir(), 'security-lab-compose-root-'));
  const binaryPath = resolve(campaignDir, 'docker');
  const logPath = resolve(campaignDir, 'docker.log');

  await writeFile(binaryPath, `#!/bin/sh
echo "$@" >> ${JSON.stringify(logPath)}
exit 0
`, 'utf8');
  await chmod(binaryPath, 0o755);

  const target: InvestigationTarget = {
    id: 'fixture-local-live-linux',
    name: 'Fixture Local Live Linux',
    kind: 'http',
    environment: 'local_live',
    baseUrl: undefined,
    repoRoot,
    cwd: repoRoot,
    hints: {},
    supportedProbeKinds: [],
    identities: [],
    authBootstrap: { type: 'fixture_local_jwt', secret: 'bootstrap-secret' },
    linuxSidecar: {
      composeService: 'backend',
      buildOnStartup: true,
      serviceOverrides: {
        backend: {
          build: {
            context: repoRoot,
            dockerfile: './Dockerfile.security-lab',
          },
          ports: ['4019:4000'],
          healthcheck: {
            test: ['CMD', 'wget', '--no-verbose', '--tries=1', '--spider', 'http://127.0.0.1:4000/health'],
            interval: '30s',
            timeout: '3s',
            retries: 6,
            startPeriod: '15s',
          },
        },
        postgres: { ports: ['5435:5432'] },
      },
    },
    localStartup: {
      command: binaryPath,
      cwd: repoRoot,
      args: ['compose', 'up', '-d', 'backend', 'postgres'],
      env: {
        COMPOSE_PROJECT_NAME: 'bos-security-lab',
      },
      timeoutMs: 5000,
    },
  };

  const session = await prepareLocalTargetSession(target, campaignDir);
  const override = await readFile(session.composeOverridePath!, 'utf8');
  assert.match(override, /backend:/);
  assert.match(override, /postgres:/);
  assert.match(override, /ports: !override/);
  assert.match(override, /"4019:4000"/);
  assert.match(override, /"5435:5432"/);
  assert.match(override, /build:/);
  assert.match(override, /context:/);
  assert.match(override, /dockerfile:/);
  assert.match(override, /healthcheck:/);
  assert.match(override, /http:\/\/127\.0\.0\.1:4000\/health/);
  assert.match(override, /start_period: "15s"/);
  await session.stop();

  const startupLog = await readFile(logPath, 'utf8');
  assert.match(startupLog, /compose -f docker-compose\.yml -f .*compose\.override\.yaml up --build -d backend postgres/);
});

test('prepareLocalTargetSession appends override files after existing compose file flags', { concurrency: false }, async () => {
  const campaignDir = await mkdtemp(resolve(tmpdir(), 'security-lab-local-target-files-'));
  const repoRoot = await mkdtemp(resolve(tmpdir(), 'security-lab-compose-root-'));
  const binaryPath = resolve(campaignDir, 'docker');
  const logPath = resolve(campaignDir, 'docker.log');

  await writeFile(binaryPath, `#!/bin/sh
echo "$@" >> ${JSON.stringify(logPath)}
exit 0
`, 'utf8');
  await chmod(binaryPath, 0o755);

  const target: InvestigationTarget = {
    id: 'fixture-local-live-linux',
    name: 'Fixture Local Live Linux',
    kind: 'http',
    environment: 'local_live',
    baseUrl: undefined,
    repoRoot,
    cwd: repoRoot,
    hints: {},
    supportedProbeKinds: [],
    identities: [],
    authBootstrap: { type: 'fixture_local_jwt', secret: 'bootstrap-secret' },
    linuxSidecar: {
      composeService: 'backend',
      buildOnStartup: true,
    },
    localStartup: {
      command: binaryPath,
      cwd: repoRoot,
      args: ['compose', '-f', 'docker-compose.yml', 'up', '-d', 'backend'],
      timeoutMs: 5000,
    },
  };

  const session = await prepareLocalTargetSession(target, campaignDir);
  await session.stop();

  const log = await readFile(logPath, 'utf8');
  assert.match(log, /compose -f docker-compose\.yml -f .*compose\.override\.yaml up --build -d backend/);
});

test('prepareLocalTargetSession honors readiness checks and targetContainer fallback for compose service', { concurrency: false }, async () => {
  const campaignDir = await mkdtemp(resolve(tmpdir(), 'security-lab-local-target-ready-'));
  const repoRoot = await mkdtemp(resolve(tmpdir(), 'security-lab-compose-root-'));
  const binaryPath = resolve(campaignDir, 'docker');
  const logPath = resolve(campaignDir, 'docker.log');

  await writeFile(binaryPath, `#!/bin/sh
echo "$@" >> ${JSON.stringify(logPath)}
exit 0
`, 'utf8');
  await chmod(binaryPath, 0o755);

  const server = createServer((req, res) => {
    if (req.url === '/ready') {
      res.statusCode = 204;
      res.end('ok');
      return;
    }
    res.statusCode = 404;
    res.end('nope');
  });
  await new Promise<void>((resolveStart) => server.listen(0, '127.0.0.1', () => resolveStart()));
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Expected TCP server address');
  }

  const target: InvestigationTarget = {
    id: 'fixture-local-live-linux',
    name: 'Fixture Local Live Linux',
    kind: 'http',
    environment: 'local_live',
    baseUrl: `http://127.0.0.1:${address.port}`,
    repoRoot,
    cwd: repoRoot,
    hints: {},
    supportedProbeKinds: [],
    identities: [],
    authBootstrap: { type: 'fixture_local_jwt', secret: 'bootstrap-secret' },
    linuxSidecar: {
      targetContainer: 'backend',
    },
    localStartup: {
      command: binaryPath,
      cwd: repoRoot,
      args: ['compose', 'up', '-d', 'backend'],
      timeoutMs: 5000,
      readinessCheck: {
        path: '/ready',
        expectStatus: 204,
        timeoutMs: 1000,
        intervalMs: 25,
      },
    },
    localShutdown: {
      command: binaryPath,
      cwd: repoRoot,
      args: ['compose', 'down'],
      timeoutMs: 5000,
    },
  };

  try {
    const session = await prepareLocalTargetSession(target, campaignDir);
    assert.ok(session.composeOverridePath);
    const override = await readFile(session.composeOverridePath!, 'utf8');
    assert.match(override, /backend:/);
    assert.match(override, /FIXTURE_JWT_SECRET/);
    await session.stop();
  } finally {
    server.close();
  }
});

test('prepareLocalTargetSession fails closed when docker compose auth bootstrap lacks a target container', { concurrency: false }, async () => {
  const campaignDir = await mkdtemp(resolve(tmpdir(), 'security-lab-local-target-fail-'));
  const repoRoot = await mkdtemp(resolve(tmpdir(), 'security-lab-compose-root-'));
  const binaryPath = resolve(campaignDir, 'docker');

  await writeFile(binaryPath, '#!/bin/sh\nexit 0\n', 'utf8');
  await chmod(binaryPath, 0o755);

  const target: InvestigationTarget = {
    id: 'fixture-local-live-linux',
    name: 'Fixture Local Live Linux',
    kind: 'http',
    environment: 'local_live',
    baseUrl: undefined,
    repoRoot,
    cwd: repoRoot,
    hints: {},
    supportedProbeKinds: [],
    identities: [],
    authBootstrap: { type: 'fixture_local_jwt', secret: 'bootstrap-secret' },
    linuxSidecar: {},
    localStartup: {
      command: binaryPath,
      cwd: repoRoot,
      args: ['compose', 'up', '-d', 'backend'],
      timeoutMs: 5000,
    },
  };

  await assert.rejects(
    () => prepareLocalTargetSession(target, campaignDir),
    /no linuxSidecar\.composeService is configured/,
  );
});
