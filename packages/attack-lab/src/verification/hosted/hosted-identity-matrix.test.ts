import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { HostedIdentityMatrix } from './hosted-identity-matrix.js';

describe('HostedIdentityMatrix', () => {
  it('generates boundary matrix from forbiddenBoundaries', () => {
    const matrix = new HostedIdentityMatrix([
      {
        id: 'user_a_canary',
        description: 'Tenant A canary',
        authSourceRef: 'src',
        forbiddenBoundaries: ['tenant_b_resource', 'admin_action'],
      },
    ]);
    const pairs = matrix.generateBoundaryMatrix();
    assert.equal(pairs.length, 2);
    assert.deepEqual(pairs[0], { identityId: 'user_a_canary', boundary: 'tenant_b_resource' });
  });

  it('rejects identities not explicitly marked as canary', () => {
    const matrix = new HostedIdentityMatrix([
      { id: 'real_user', description: 'real prod user', authSourceRef: 's', expectedRole: 'production_admin' },
    ]);
    assert.throws(() => matrix.validateAllAreCanaries(), /not marked as a canary/);
  });

  it('rejects canary identities not allowed in hosted mode', () => {
    const matrix = new HostedIdentityMatrix([
      { id: 'user_a_canary', description: 'Tenant A canary', authSourceRef: 's', isCanary: true, allowInHosted: false },
    ]);
    assert.throws(() => matrix.validateAllAreCanaries(), /allowInHosted/);
  });

  it('accepts canary-marked identities via legacy id heuristic', () => {
    const matrix = new HostedIdentityMatrix([
      { id: 'guest', description: 'anon', authSourceRef: 's' },
      { id: 'user_a_canary', description: 'Tenant A canary', authSourceRef: 's' },
    ]);
    matrix.validateAllAreCanaries();
  });

  it('accepts identities with explicit isCanary + allowInHosted metadata', () => {
    const matrix = new HostedIdentityMatrix([
      { id: 'primary', description: 'tenant primary', authSourceRef: 's', isCanary: true, allowInHosted: true },
    ]);
    matrix.validateAllAreCanaries();
  });
});
