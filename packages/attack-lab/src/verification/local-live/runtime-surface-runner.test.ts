import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { executeRuntimeSurfaceProbe } from './runtime-surface-runner.js';
import type { LiveProbeRequest } from './contracts.js';

function baseProbe(): LiveProbeRequest {
  return {
    findingId: 'finding-1',
    hypothesis: 'runtime foothold exists',
    probeKind: 'process',
    identityId: 'guest',
    process: {
      action: 'env_scan',
      searchPatterns: ['SECURITY_LAB_DECOY'],
    },
  };
}

test('executeRuntimeSurfaceProbe handles unsupported probe kinds', async () => {
  const result = await executeRuntimeSurfaceProbe({
    ...baseProbe(),
    probeKind: 'http',
    http: { method: 'GET', path: '/health' },
  });
  assert.equal(result.verdict, 'not_applicable');
});

test('runtime surface process checks detect env and credential markers', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-runtime-surface-'));

  try {
    process.env.SECURITY_LAB_DECOY_ENV = 'SECURITY_LAB_DECOY';
    const envResult = await executeRuntimeSurfaceProbe(baseProbe(), {
      workingDir: root,
      decoyMarkers: ['SECURITY_LAB_DECOY'],
    });
    assert.equal(envResult.verdict, 'confirmed');

    await writeFile(join(root, '.env'), 'SECRET=SECURITY_LAB_DECOY\n', 'utf8');
    const credentialResult = await executeRuntimeSurfaceProbe(
      {
        ...baseProbe(),
        process: { action: 'credential_search', searchPatterns: ['SECURITY_LAB_DECOY'] },
      },
      {
        workingDir: root,
        decoyMarkers: ['SECURITY_LAB_DECOY'],
      },
    );
    assert.equal(credentialResult.verdict, 'confirmed');
  } finally {
    delete process.env.SECURITY_LAB_DECOY_ENV;
    await rm(root, { recursive: true, force: true });
  }
});

test('runtime surface persistence checks cover startup, launchd, cron, and background branches', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-runtime-surface-'));
  const home = await mkdtemp(join(tmpdir(), 'security-lab-runtime-home-'));
  const previousHome = process.env.HOME;

  try {
    await writeFile(join(root, 'package.json'), '{"scripts":{"start":"SECURITY_LAB_CANARY"}}', 'utf8');
    await mkdir(join(home, 'Library', 'LaunchAgents'), { recursive: true });
    await writeFile(
      join(home, 'Library', 'LaunchAgents', 'SECURITY_LAB_CANARY.plist'),
      '<plist/>',
      'utf8',
    );
    process.env.HOME = home;

    const startup = await executeRuntimeSurfaceProbe(
      {
        ...baseProbe(),
        probeKind: 'persistence',
        persistence: { action: 'startup_check' },
      },
      {
        workingDir: root,
        decoyMarkers: ['SECURITY_LAB_CANARY'],
      },
    );
    assert.equal(startup.verdict, 'confirmed');

    const launchd = await executeRuntimeSurfaceProbe(
      {
        ...baseProbe(),
        probeKind: 'persistence',
        persistence: { action: 'launchd_check' },
      },
      {
        workingDir: root,
        decoyMarkers: ['SECURITY_LAB_CANARY'],
      },
    );
    assert.equal(launchd.verdict, 'confirmed');

    const cron = await executeRuntimeSurfaceProbe(
      {
        ...baseProbe(),
        probeKind: 'persistence',
        persistence: { action: 'cron_check' },
      },
      { workingDir: root },
    );
    assert.ok(['confirmed', 'refuted'].includes(cron.verdict));

    const background = await executeRuntimeSurfaceProbe(
      {
        ...baseProbe(),
        probeKind: 'persistence',
        persistence: { action: 'background_process_check' },
      },
      { workingDir: root, decoyMarkers: ['SECURITY_LAB_CANARY'] },
    );
    assert.ok(['confirmed', 'refuted', 'not_applicable'].includes(background.verdict));

    const fdScan = await executeRuntimeSurfaceProbe(
      {
        ...baseProbe(),
        process: { action: 'fd_scan', searchPatterns: ['SECURITY_LAB_CANARY'] },
      },
      { workingDir: root },
    );
    assert.ok(['confirmed', 'refuted', 'not_applicable'].includes(fdScan.verdict));

    const procSelf = await executeRuntimeSurfaceProbe(
      {
        ...baseProbe(),
        process: { action: 'proc_self_read', searchPatterns: ['SECURITY_LAB_CANARY'] },
      },
      { workingDir: root },
    );
    assert.ok(['confirmed', 'refuted', 'not_applicable'].includes(procSelf.verdict));
  } finally {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    await rm(root, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});
