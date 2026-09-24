import test from 'node:test';
import assert from 'node:assert/strict';
import { SupplyChainConfirmationRunner } from './confirmation-runner.js';
import type { DependencyChangeSet, ArtifactInspection, InstallSandboxResult } from './contracts.js';
import type { DependencyBaseline } from '../../supply-chain/contracts.js';

const baseChangeSet: DependencyChangeSet = {
  changeSetId: 'change-set-1',
  detectedAt: new Date().toISOString(),
  packageManager: 'npm',
  baselinePath: '/tmp/baseline.json',
  drifts: [],
  changedPackages: [],
};

const baseline: DependencyBaseline = {
  version: 1,
  approvedAt: new Date().toISOString(),
  packageManager: 'npm',
  lockfileName: 'package-lock.json',
  packageJsonHash: 'package-json-hash',
  lockfileHash: 'lockfile-hash',
  packages: [
    {
      name: 'fixture-package',
      version: '1.0.0',
      integrityHash: 'integrity',
      hasInstallScript: false,
      approvedAt: new Date().toISOString(),
    },
  ],
};

test('SupplyChainConfirmationRunner marks removed packages as needs_review', async () => {
  const runner = new SupplyChainConfirmationRunner({
    quarantineDir: '/tmp/security-lab-quarantine',
    baseline,
  });

  const [experiment] = await runner.run({
    ...baseChangeSet,
    changedPackages: [
      {
        name: 'removed-package',
        previousVersion: '1.0.0',
        currentVersion: undefined,
        hasInstallScript: false,
        isTransitive: false,
      },
    ],
  });

  assert.equal(experiment?.verdict, 'needs_review');
  assert.match(experiment?.reasoning ?? '', /removed from baseline/i);
});

test('SupplyChainConfirmationRunner orchestrates fetch, inspect, diff, sandbox, and policy review', async () => {
  // Install execution is opt-in and needs an isolation backend, so the test
  // opts in explicitly (the sandbox itself is stubbed below).
  const runner = new SupplyChainConfirmationRunner({
    quarantineDir: '/tmp/security-lab-quarantine',
    baseline,
    enableInstallSandbox: true,
    installSandboxIsolation: { kind: 'docker' },
  });

  const inspection: ArtifactInspection = {
    packageName: 'fixture-package',
    version: '2.0.0',
    tarballSha256: 'sha',
    hasInstallScript: true,
    installScriptContent: 'postinstall: node install.js',
    installScriptSha256: 'script-hash',
    hasPostInstallScript: true,
    hasNativeBinaries: false,
    nativeBinaryPaths: [],
    hasObfuscatedSource: false,
    obfuscatedFiles: [],
    containsNetworkCalls: false,
    networkCallSummary: [],
    registryMatchesBaseline: true,
    signatureVerified: false,
    notes: [],
  };
  const installSandbox: InstallSandboxResult = {
    executed: true,
    isolation: 'docker',
    packageName: 'fixture-package',
    version: '2.0.0',
    exitCode: 0,
    durationMs: 100,
    stdoutTail: '',
    stderrTail: '',
    filesWrittenOutsideSandbox: [],
    networkAttempts: [],
    exceededTimeout: false,
  };

  (runner as any).fetcher = {
    fetch: async () => ({
      packageName: 'fixture-package',
      version: '2.0.0',
      tarballPath: '/tmp/package.tgz',
      unpackedPath: '/tmp/unpacked',
      tarballSha256: 'sha',
      fetchedFrom: 'https://registry.npmjs.org/fixture-package/-/fixture-package-2.0.0.tgz',
      fetchedAt: new Date().toISOString(),
    }),
  };
  (runner as any).verifier = { inspect: async () => inspection };
  (runner as any).sandbox = { run: async () => installSandbox };
  (runner as any).diff = {
    analyze: () => ({
      diffSummary: 'install script added',
      materiallyDifferent: true,
    }),
  };
  (runner as any).policy = {
    decide: () => ({
      verdict: 'confirmed_risk',
      reasoning: 'Install script materially changed.',
    }),
    hash: () => 'policy-hash',
  };

  const [experiment] = await runner.run({
    ...baseChangeSet,
    changedPackages: [
      {
        name: 'fixture-package',
        previousVersion: '1.0.0',
        currentVersion: '2.0.0',
        hasInstallScript: true,
        isTransitive: false,
      },
    ],
  });

  assert.equal(experiment?.verdict, 'confirmed_risk');
  assert.equal(experiment?.installSandbox?.exitCode, 0);
  assert.ok(experiment?.evidenceRefs.some((entry) => entry.startsWith('tarball:')));
});

test('SupplyChainConfirmationRunner converts orchestration errors into needs_review experiments', async () => {
  const runner = new SupplyChainConfirmationRunner({
    quarantineDir: '/tmp/security-lab-quarantine',
  });
  (runner as any).fetcher = {
    fetch: async () => {
      throw new Error('registry offline');
    },
  };

  const [experiment] = await runner.run({
    ...baseChangeSet,
    changedPackages: [
      {
        name: 'broken-package',
        previousVersion: '1.0.0',
        currentVersion: '2.0.0',
        hasInstallScript: false,
        isTransitive: true,
      },
    ],
  });

  assert.equal(experiment?.verdict, 'needs_review');
  assert.match(experiment?.reasoning ?? '', /registry offline/i);
});

test('install execution is opt-in and requires an isolation backend', () => {
  const base = { quarantineDir: '/tmp/quarantine' };
  const inspection = { hasInstallScript: true, hasNativeBinaries: true };

  // Default: a package with install scripts is *not* executed.
  const byDefault = new SupplyChainConfirmationRunner(base as never);
  assert.equal((byDefault as never as { shouldRunSandbox: (i: typeof inspection) => boolean }).shouldRunSandbox(inspection), false);

  // Enabled but unisolated: still not executed.
  const enabledOnly = new SupplyChainConfirmationRunner({ ...base, enableInstallSandbox: true } as never);
  assert.equal((enabledOnly as never as { shouldRunSandbox: (i: typeof inspection) => boolean }).shouldRunSandbox(inspection), false);

  // Enabled with an isolation backend: runs.
  const isolated = new SupplyChainConfirmationRunner({
    ...base,
    enableInstallSandbox: true,
    installSandboxIsolation: { kind: 'docker' },
  } as never);
  assert.equal((isolated as never as { shouldRunSandbox: (i: typeof inspection) => boolean }).shouldRunSandbox(inspection), true);
});
