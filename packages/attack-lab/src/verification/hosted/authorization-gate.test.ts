import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { AuthorizationGate } from './authorization-gate.js';

describe('AuthorizationGate', () => {
  it('throws when authorize flag is not set', async () => {
    const gate = new AuthorizationGate();
    await assert.rejects(
      () =>
        gate.check(
          { campaignId: 'c', hostedTargetId: 't', baseUrl: 'https://example', authorizeFlagSet: false },
          { skipPrompt: true },
        ),
      /--authorize-hosted/,
    );
  });

  it('returns existing token when one is provided', async () => {
    const gate = new AuthorizationGate();
    const token = await gate.check(
      {
        campaignId: 'c',
        hostedTargetId: 't',
        baseUrl: 'https://example',
        authorizeFlagSet: true,
        authorizationToken: 'existing-token',
      },
      { skipPrompt: true },
    );
    assert.equal(token, 'existing-token');
  });

  it('returns automated token when skipPrompt is true and no prior token', async () => {
    const gate = new AuthorizationGate();
    const token = await gate.check(
      { campaignId: 'c', hostedTargetId: 't', baseUrl: 'https://example', authorizeFlagSet: true },
      { skipPrompt: true },
    );
    assert.match(token, /^automated-/);
  });
});
