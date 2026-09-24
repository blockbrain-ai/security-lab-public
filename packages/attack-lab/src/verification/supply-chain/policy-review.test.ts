import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { PolicyReview } from './policy-review.js';
import type { ArtifactInspection } from './contracts.js';
import type { DiffResult } from './diff-analyzer.js';

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

describe('PolicyReview', () => {
  it('returns approved_drift when nothing material changed', () => {
    const review = new PolicyReview();
    const diff: DiffResult = { diffSummary: 'version bump only', materiallyDifferent: false, changes: [] };
    const decision = review.decide(baseInspection, diff);
    assert.equal(decision.verdict, 'approved_drift');
  });

  it('flags newly added install script as confirmed_risk', () => {
    const review = new PolicyReview();
    const diff: DiffResult = {
      diffSummary: 'install script ADDED (previously absent)',
      materiallyDifferent: true,
      changes: ['install script ADDED (previously absent)'],
    };
    const decision = review.decide({ ...baseInspection, hasInstallScript: true }, diff);
    assert.equal(decision.verdict, 'confirmed_risk');
  });

  it('flags obfuscated source as confirmed_risk', () => {
    const review = new PolicyReview();
    const diff: DiffResult = {
      diffSummary: 'obfuscated',
      materiallyDifferent: true,
      changes: ['obfuscated source detected'],
    };
    const decision = review.decide(
      { ...baseInspection, hasObfuscatedSource: true, obfuscatedFiles: ['x.js'] },
      diff,
    );
    assert.equal(decision.verdict, 'confirmed_risk');
  });

  it('returns needs_review when material drift but no rule fires', () => {
    const review = new PolicyReview();
    const diff: DiffResult = {
      diffSummary: 'integrity hash changed',
      materiallyDifferent: true,
      changes: ['integrity hash changed'],
    };
    const decision = review.decide(baseInspection, diff);
    assert.equal(decision.verdict, 'needs_review');
  });

  it('produces a stable hash', () => {
    const a = new PolicyReview().hash();
    const b = new PolicyReview().hash();
    assert.equal(a, b);
  });
});
