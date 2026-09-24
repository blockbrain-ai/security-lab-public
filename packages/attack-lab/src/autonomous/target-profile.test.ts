import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { loadInvestigationTarget, resolveAdaptiveExplorationConfig, summarizeTargetProfile } from './target-profile.js';
import type { InvestigationTarget } from './target-profile.js';
import { loadTargetOverlay } from './target-overlay.js';
import { getAttackLabRoot } from '../loaders/runfile-loader.js';

// ---------------------------------------------------------------------------
// Self-contained profile fixtures
//
// These replace the original tests that pointed at operator-specific target
// profiles: the loader behaviour they covered (env interpolation, inheritance,
// overlays, scoping metadata) is exercised against profiles created here.
// ---------------------------------------------------------------------------

interface Fixture {
  root: string;
  profile: (name: string) => string;
}

async function makeFixtureDir(): Promise<Fixture> {
  const root = await mkdtemp(join(tmpdir(), 'target-profile-'));
  return { root, profile: (name: string) => join(root, name) };
}

async function writeBaseProfile(fixture: Fixture): Promise<void> {
  await mkdir(join(fixture.root, 'repo', 'src'), { recursive: true });
  await mkdir(join(fixture.root, 'repo', 'frontend', 'src'), { recursive: true });
  await writeFile(
    fixture.profile('base.yaml'),
    [
      'id: fixture-base',
      'name: Fixture Base',
      'kind: code',
      'environment: sandbox',
      'repoRootEnv: TARGET_REPO_ROOT',
      'includePaths:',
      '  - src',
      '  - frontend/src',
      'routeRoots:',
      '  - src/api/routes',
      'searchRoots:',
      '  - src',
      'maxRoutes: 150',
      'maxFiles: 5000',
      'authMechanism:',
      '  tenantHeader: x-organization-id',
      'overlay: ./overlay.yaml',
      '',
    ].join('\n'),
    'utf8',
  );
}

async function writeOverlay(fixture: Fixture): Promise<void> {
  await writeFile(
    fixture.profile('overlay.yaml'),
    [
      'vulnerabilityFamilies:',
      '  - family: tenant_isolation',
      '    description: Cross-tenant data access through a shared identifier.',
      '    priority: high',
      'trustBoundaries:',
      '  - from: external_untrusted',
      '    to: public_api',
      '    mechanism: session validation',
      'highValuePatterns:',
      '  - "$queryRaw"',
      '  - "eval("',
      '',
    ].join('\n'),
    'utf8',
  );
}

test('loadInvestigationTarget resolves YAML profiles, inheritance and environment variables', async () => {
  const fixture = await makeFixtureDir();
  try {
    await writeBaseProfile(fixture);
    await writeOverlay(fixture);
    process.env['TARGET_REPO_ROOT'] = join(fixture.root, 'repo');
    process.env['TARGET_STAGING_URL'] = 'https://staging.example.test';

    await writeFile(
      fixture.profile('staging.yaml'),
      [
        'id: fixture-staging',
        'name: Fixture Staging',
        'kind: http',
        'environment: staging',
        'baseUrl: ${TARGET_STAGING_URL}',
        '',
      ].join('\n'),
      'utf8',
    );

    await writeFile(
      fixture.profile('local-live.yaml'),
      [
        'extends: ./base.yaml',
        'id: fixture-local-live',
        'name: Fixture Local Live',
        'kind: http',
        'environment: local_live',
        'baseUrl: http://localhost:4019',
        'linuxSidecar:',
        '  composeService: backend',
        '  composeProjectName: fixture-security-lab',
        '  buildOnStartup: true',
        'localStartup:',
        '  command: docker',
        'localShutdown:',
        '  command: docker',
        'verificationPolicy:',
        '  localLiveRounds: 3',
        '  cleanStartup: true',
        '',
      ].join('\n'),
      'utf8',
    );

    const staging = await loadInvestigationTarget(fixture.profile('staging.yaml'));
    assert.equal(staging.baseUrl, 'https://staging.example.test');
    assert.equal(staging.environment, 'staging');
    assert.ok(staging.supportedProbeKinds.includes('http_request'));
    assert.ok(!staging.supportedProbeKinds.includes('shell_command'));

    const localLive = await loadInvestigationTarget(fixture.profile('local-live.yaml'));
    assert.equal(localLive.id, 'fixture-local-live');
    assert.equal(localLive.sourceProfileId, 'fixture-base');
    assert.equal(localLive.repoRoot, process.env['TARGET_REPO_ROOT']);
    assert.equal(localLive.baseUrl, 'http://localhost:4019');
    assert.equal(localLive.linuxSidecar?.['composeService'], 'backend');
    assert.equal(localLive.linuxSidecar?.['composeProjectName'], 'fixture-security-lab');
    assert.equal(localLive.linuxSidecar?.['buildOnStartup'], true);
    assert.equal(localLive.localStartup?.['command'], 'docker');
    assert.equal(localLive.localShutdown?.['command'], 'docker');
    assert.equal(localLive.verificationPolicy?.['localLiveRounds'], 3);
    assert.equal(localLive.verificationPolicy?.['cleanStartup'], true);
    assert.equal(localLive.authMechanism?.tenantHeader, 'x-organization-id');
    assert.deepEqual(localLive.includePaths, ['src', 'frontend/src']);
    assert.deepEqual(localLive.routeRoots, ['src/api/routes']);
    assert.deepEqual(localLive.searchRoots, ['src']);
    assert.equal(localLive.maxRoutes, 150);
    assert.equal(localLive.maxFiles, 5000);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('loadInvestigationTarget resolves repo-root relative target paths from the workspace cwd', { concurrency: false }, async () => {
  const originalCwd = process.cwd();
  process.chdir(getAttackLabRoot());

  try {
    const liveTarget = await loadInvestigationTarget('packages/attack-lab/targets/example-http.yaml');
    assert.equal(liveTarget.kind, 'http');
    assert.equal(liveTarget.id, 'my-app-local');
    assert.ok(liveTarget.baseUrl?.startsWith('http://localhost'));
  } finally {
    process.chdir(originalCwd);
  }
});

test('loadInvestigationTarget fails closed for missing YAML target profiles', async () => {
  await assert.rejects(
    () => loadInvestigationTarget('packages/attack-lab/targets/does-not-exist.yaml'),
    /Target profile not found/,
  );
});

test('profiles declare overlays through the pluggable overlay contract', async () => {
  const fixture = await makeFixtureDir();
  try {
    await writeBaseProfile(fixture);
    await writeOverlay(fixture);
    process.env['TARGET_REPO_ROOT'] = join(fixture.root, 'repo');

    const target = await loadInvestigationTarget(fixture.profile('base.yaml'));
    assert.equal(target.overlay, './overlay.yaml');

    const overlayContent = await loadTargetOverlay(target);
    assert.ok(overlayContent.length > 0);
    assert.ok(overlayContent.includes('Priority Vulnerability Families'));
    assert.ok(overlayContent.includes('Trust Boundaries to Probe'));
    assert.ok(overlayContent.includes('High-Value Code Patterns'));
    assert.ok(overlayContent.includes('tenant_isolation'));
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('derived profiles inherit the overlay from their base profile', async () => {
  const fixture = await makeFixtureDir();
  try {
    await writeBaseProfile(fixture);
    await writeOverlay(fixture);
    process.env['TARGET_REPO_ROOT'] = join(fixture.root, 'repo');

    await writeFile(
      fixture.profile('derived.yaml'),
      ['extends: ./base.yaml', 'id: fixture-derived', 'name: Fixture Derived', 'kind: http', 'environment: local_live', 'baseUrl: http://localhost:4020', ''].join('\n'),
      'utf8',
    );

    const derived = await loadInvestigationTarget(fixture.profile('derived.yaml'));
    assert.equal(derived.overlay, './overlay.yaml');
    const overlay = await loadTargetOverlay(derived);
    assert.ok(overlay.includes('tenant_isolation'));
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('target profiles without an overlay return an empty string from loadTargetOverlay', async () => {
  const fixture = await makeFixtureDir();
  try {
    await writeFile(
      fixture.profile('plain.yaml'),
      [
        'id: fixture-plain',
        'name: Fixture Plain',
        'kind: code',
        'environment: sandbox',
        `repoRoot: ${join(fixture.root, 'repo')}`,
        '',
      ].join('\n'),
      'utf8',
    );
    const target = await loadInvestigationTarget(fixture.profile('plain.yaml'));
    assert.equal(await loadTargetOverlay(target), '');
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('resolveAdaptiveExplorationConfig returns defaults when liveProbing omits the key', () => {
  const config = resolveAdaptiveExplorationConfig({ liveProbing: undefined });
  assert.equal(config.enabled, true);
  assert.equal(config.maxFollowupsPerSurprise, 3);
  assert.equal(config.maxMidRoundHypotheses, 5);
});

test('resolveAdaptiveExplorationConfig reads explicit adaptiveExploration overrides', () => {
  const config = resolveAdaptiveExplorationConfig({
    liveProbing: {
      adaptiveExploration: {
        enabled: false,
        maxFollowupsPerSurprise: 2,
        maxMidRoundHypotheses: 7,
      },
    },
  });
  assert.equal(config.enabled, false);
  assert.equal(config.maxFollowupsPerSurprise, 2);
  assert.equal(config.maxMidRoundHypotheses, 7);
});

test('resolveAdaptiveExplorationConfig clamps out-of-range values', () => {
  const config = resolveAdaptiveExplorationConfig({
    liveProbing: {
      adaptiveExploration: {
        maxFollowupsPerSurprise: 999,
        maxMidRoundHypotheses: -5,
      },
    },
  });
  assert.equal(config.maxFollowupsPerSurprise, 10);
  assert.equal(config.maxMidRoundHypotheses, 0);
});

// ---------------------------------------------------------------------------
// Browser capability and summary rendering
// ---------------------------------------------------------------------------

test('directory-based targets never get browser capability', async () => {
  const target = await loadInvestigationTarget('.');
  assert.equal(target.browser, undefined);
  assert.ok(!target.supportedProbeKinds.includes('browser_probe'));
});

test('summarizeTargetProfile renders browser info when enabled', () => {
  const target: InvestigationTarget = {
    id: 'test-app',
    name: 'Test App',
    kind: 'http',
    environment: 'local_live',
    baseUrl: 'http://localhost:3000',
    hints: {},
    supportedProbeKinds: ['http_request', 'browser_probe'],
    browser: {
      enabled: true,
      bootstrapUrl: 'http://localhost:3000/login',
    },
  };

  const summary = summarizeTargetProfile(target);
  assert.ok(summary.includes('Browser: enabled'));
  assert.ok(summary.includes('Browser Bootstrap URL: http://localhost:3000/login'));
});

test('summarizeTargetProfile omits browser info when disabled', () => {
  const target: InvestigationTarget = {
    id: 'test-app',
    name: 'Test App',
    kind: 'http',
    environment: 'local_live',
    baseUrl: 'http://localhost:3000',
    hints: {},
    supportedProbeKinds: ['http_request'],
    browser: {
      enabled: false,
    },
  };

  const summary = summarizeTargetProfile(target);
  assert.ok(!summary.includes('Browser: enabled'));
  assert.ok(!summary.includes('Browser Bootstrap URL'));
});

test('summarizeTargetProfile omits browser info when browser undefined', () => {
  const target: InvestigationTarget = {
    id: 'test-app',
    name: 'Test App',
    kind: 'code',
    environment: 'sandbox',
    hints: {},
    supportedProbeKinds: ['code_read'],
  };

  const summary = summarizeTargetProfile(target);
  assert.ok(!summary.includes('Browser'));
});

test('the shipped example profiles load with their documented defaults', async () => {
  const code = await loadInvestigationTarget('packages/attack-lab/targets/example-code.yaml');
  assert.equal(code.kind, 'code');
  assert.ok(code.supportedProbeKinds.includes('code_read'));

  const dependency = await loadInvestigationTarget('packages/attack-lab/targets/example-dependency.yaml');
  assert.ok(dependency.supportedProbeKinds.includes('dependency_read'));

  const httpProfile = await loadInvestigationTarget(resolve(getAttackLabRoot(), 'targets', 'example-http.yaml'));
  assert.equal(httpProfile.kind, 'http');
  assert.ok(httpProfile.supportedProbeKinds.includes('http_request'));
});
