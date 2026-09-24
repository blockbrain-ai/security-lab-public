import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { DiffAnalyzer } from './diff-analyzer.js';
import type { ArtifactInspection, ChangedPackage } from './contracts.js';
import type { ApprovedPackage } from '../../supply-chain/contracts.js';

const baseInspection: ArtifactInspection = {
  packageName: 'pkg',
  version: '1.0.1',
  tarballSha256: 'aaa',
  hasInstallScript: false,
  hasPostInstallScript: false,
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

const baseChanged: ChangedPackage = {
  name: 'pkg',
  previousVersion: '1.0.0',
  currentVersion: '1.0.1',
  hasInstallScript: false,
  isTransitive: false,
};

const baseApproved: ApprovedPackage = {
  name: 'pkg',
  version: '1.0.0',
  integrityHash: 'sha512-old',
  hasInstallScript: false,
  approvedAt: '2024-01-01T00:00:00Z',
};

describe('DiffAnalyzer', () => {
  it('reports new install script as material drift', () => {
    const analyzer = new DiffAnalyzer();
    const result = analyzer.analyze(
      baseChanged,
      { ...baseInspection, hasInstallScript: true, installScriptSha256: 'new-script' },
      baseApproved,
    );
    assert.equal(result.materiallyDifferent, true);
    assert.ok(result.changes.some((c) => c.includes('install script')));
  });

  it('reports native binary as material drift', () => {
    const analyzer = new DiffAnalyzer();
    const result = analyzer.analyze(
      baseChanged,
      { ...baseInspection, hasNativeBinaries: true, nativeBinaryPaths: ['lib/native.node'] },
      baseApproved,
    );
    assert.equal(result.materiallyDifferent, true);
    assert.ok(result.changes.some((c) => c.includes('native')));
  });

  it('flags integrity hash change as material drift', () => {
    const analyzer = new DiffAnalyzer();
    const changed: ChangedPackage = {
      ...baseChanged,
      currentIntegrity: 'sha512-new',
    };
    const approved: ApprovedPackage = { ...baseApproved, integrityHash: 'sha512-old' };
    const result = analyzer.analyze(changed, baseInspection, approved);
    assert.equal(result.materiallyDifferent, true);
    assert.ok(result.changes.some((c) => c.includes('integrity hash')));
  });
});
