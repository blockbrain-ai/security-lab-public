import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { IdentityLadder } from './identity-ladder.js';

describe('IdentityLadder', () => {
  it('builds anonymous headers', () => {
    const ladder = new IdentityLadder([{ id: 'guest', kind: 'anonymous' }]);
    assert.deepEqual(ladder.buildHeaders('guest'), {});
  });

  it('maps anonymous aliases onto the configured guest identity', () => {
    const ladder = new IdentityLadder([{ id: 'guest', kind: 'anonymous' }]);
    assert.deepEqual(ladder.buildHeaders('anonymous'), {});
    assert.equal(ladder.get('anon')?.id, 'guest');
  });

  it('returns null for unknown identity', () => {
    const ladder = new IdentityLadder([]);
    assert.equal(ladder.buildHeaders('nope'), null);
  });

  it('returns null when env var is missing', () => {
    delete process.env.TEST_NO_TOKEN;
    const ladder = new IdentityLadder([
      { id: 'u', kind: 'bearer_token', tokenEnv: 'TEST_NO_TOKEN' },
    ]);
    assert.equal(ladder.buildHeaders('u'), null);
  });

  it('builds bearer headers when env var is present', () => {
    process.env.TEST_BEARER = 'abc';
    const ladder = new IdentityLadder([
      { id: 'u', kind: 'bearer_token', tokenEnv: 'TEST_BEARER', organizationId: 'org_a' },
    ]);
    const headers = ladder.buildHeaders('u');
    assert.equal(headers?.['Authorization'], 'Bearer abc');
    assert.equal(headers?.['x-organization-id'], 'org_a');
    delete process.env.TEST_BEARER;
  });

  it('finds cross-tenant pairs', () => {
    const ladder = new IdentityLadder([
      { id: 'a', kind: 'bearer_token', tokenEnv: 'X', organizationId: 'org_a' },
      { id: 'b', kind: 'bearer_token', tokenEnv: 'X', organizationId: 'org_b' },
    ]);
    const pairs = ladder.getCrossTenantPairs();
    assert.equal(pairs.length, 1);
    assert.equal(pairs[0]![0]!.id, 'a');
    assert.equal(pairs[0]![1]!.id, 'b');
  });

  it('finds privilege escalation pairs', () => {
    const ladder = new IdentityLadder([
      { id: 'low', kind: 'anonymous', expectedRole: 'user' },
      { id: 'high', kind: 'anonymous', expectedRole: 'admin' },
    ]);
    const pairs = ladder.getPrivilegeEscalationPairs();
    assert.ok(pairs.some(([l, h]) => l.id === 'low' && h.id === 'high'));
  });

  it('uses configurable tenant header from target profile', () => {
    process.env.TEST_BEARER_CUSTOM = 'token123';
    const ladder = new IdentityLadder(
      [{ id: 'u', kind: 'bearer_token', tokenEnv: 'TEST_BEARER_CUSTOM', organizationId: 'org_x' }],
      undefined,
      'x-custom-tenant-id',
    );
    const headers = ladder.buildHeaders('u');
    assert.equal(headers?.['x-custom-tenant-id'], 'org_x');
    assert.equal(headers?.['x-organization-id'], undefined);
    delete process.env.TEST_BEARER_CUSTOM;
  });

  it('defaults tenant header to x-organization-id when not configured', () => {
    process.env.TEST_BEARER_DEFAULT = 'tok';
    const ladder = new IdentityLadder(
      [{ id: 'u', kind: 'bearer_token', tokenEnv: 'TEST_BEARER_DEFAULT', organizationId: 'org_y' }],
    );
    const headers = ladder.buildHeaders('u');
    assert.equal(headers?.['x-organization-id'], 'org_y');
    delete process.env.TEST_BEARER_DEFAULT;
  });
});
