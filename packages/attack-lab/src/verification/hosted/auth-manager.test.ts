import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, rm, writeFile } from 'node:fs/promises';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuthManager } from './auth-manager.js';
import type { AuthSource } from './contracts.js';

function makeManager(sources: Record<string, AuthSource>): AuthManager {
  return new AuthManager(new Map(Object.entries(sources)));
}

test('AuthManager resolves anonymous, bearer-token, and session-cookie credentials', async () => {
  process.env.HOSTED_BEARER = 'canary_bearer';
  process.env.HOSTED_COOKIE = 'canary_cookie';

  const manager = makeManager({
    anon: { source: 'anonymous' },
    bearer: { source: 'bearer_token', tokenEnv: 'HOSTED_BEARER' },
    cookie: { source: 'session_cookie', cookieName: 'session', cookieValueEnv: 'HOSTED_COOKIE' },
  });

  const anon = await manager.resolve('anon');
  assert.deepEqual(anon?.headers, {});

  const bearer = await manager.resolve('bearer');
  assert.equal(bearer?.headers['Authorization'], 'Bearer canary_bearer');

  const cookie = await manager.resolve('cookie');
  assert.equal(cookie?.headers['Cookie'], 'session=canary_cookie');

  delete process.env.HOSTED_BEARER;
  delete process.env.HOSTED_COOKIE;
});

test('AuthManager supports executable IAP user token sources and cache invalidation', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-auth-manager-'));

  try {
    const script = join(root, 'emit-token.sh');
    await writeFile(script, '#!/bin/sh\nprintf canary_iap_token\n', 'utf8');
    await chmod(script, 0o755);

    const manager = makeManager({
      iap: { source: 'iap_user_token', tokenCommand: script, refreshIntervalSeconds: 1 },
    });

    const first = await manager.resolve('iap');
    assert.equal(first?.headers['Proxy-Authorization'], 'Bearer canary_iap_token');

    manager.invalidate();
    const second = await manager.resolve('iap');
    assert.equal(second?.headers['Proxy-Authorization'], 'Bearer canary_iap_token');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('AuthManager rejects production-looking credentials and returns null for unknown sources', async () => {
  process.env.HOSTED_PROD_TOKEN = 'prod_secret_token';
  const manager = makeManager({
    prod: { source: 'bearer_token', tokenEnv: 'HOSTED_PROD_TOKEN' },
  });

  await assert.rejects(manager.resolve('prod'), /production marker/i);
  assert.equal(await manager.resolve('missing'), null);
  delete process.env.HOSTED_PROD_TOKEN;
});
