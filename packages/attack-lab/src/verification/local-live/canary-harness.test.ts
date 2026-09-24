import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  matchCanary,
  generateNonce,
  substituteNonce,
  buildIdorCanary,
  buildAuthBypassCanary,
  buildPromptInjectionCanary,
} from './canary-harness.js';

describe('canary-harness matchCanary', () => {
  const canary = buildAuthBypassCanary('/api/admin');

  it('returns "safe" when expectedWhenSafe matches', () => {
    assert.equal(matchCanary(canary, { status: 401, body: '' }), 'safe');
  });

  it('returns "exploitable" when expectedWhenExploitable matches', () => {
    assert.equal(matchCanary(canary, { status: 200, body: '' }), 'exploitable');
  });

  it('returns "neither" when no expectation matches', () => {
    assert.equal(matchCanary(canary, { status: 500, body: '' }), 'neither');
  });
});

describe('canary-harness IDOR canary', () => {
  it('marks status 200 with marker as exploitable', () => {
    const canary = buildIdorCanary('canary_b', 'wrong_org', 'canary_b', 'x-org-id');
    assert.equal(matchCanary(canary, { status: 200, body: '{"id":"canary_b"}' }), 'exploitable');
    assert.equal(matchCanary(canary, { status: 403, body: '' }), 'safe');
  });
});

describe('canary-harness prompt injection canary', () => {
  it('marks confirmed marker in body as exploitable', () => {
    const nonce = generateNonce();
    const canary = buildPromptInjectionCanary('/api/decisions', 'description', 'INJECT', nonce);
    assert.equal(
      matchCanary(canary, { status: 200, body: `INJECT_CONFIRMED_${nonce}` }),
      'exploitable',
    );
    assert.equal(matchCanary(canary, { status: 200, body: 'no marker here' }), 'safe');
  });
});

describe('canary-harness substituteNonce', () => {
  it('replaces ${nonce} placeholders', () => {
    assert.equal(substituteNonce('hello ${nonce} world', 'abc123'), 'hello abc123 world');
  });
});
