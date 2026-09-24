import { createServer } from 'node:http';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';
import type { InvestigationTarget } from '../../autonomous/target-profile.js';
import { prepareLocalTargetSession } from './target-lifecycle.js';

async function withServer(
  handler: (req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => void,
): Promise<{ baseUrl: string; close: () => Promise<void> }> {
  const server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('failed to bind test server');
  }
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  };
}

function buildTarget(overrides: Partial<InvestigationTarget> = {}): InvestigationTarget {
  return {
    id: 'local-live-test',
    name: 'Local Live Test',
    kind: 'http',
    environment: 'local_live',
    baseUrl: 'http://127.0.0.1:1',
    hints: {},
    supportedProbeKinds: ['http_request'],
    localStartup: {
      command: 'sh',
      args: ['-lc', 'exit 1'],
      readinessCheck: {
        method: 'GET',
        path: '/health',
        expectStatus: 200,
        timeoutMs: 2_000,
        intervalMs: 50,
      },
    },
    ...overrides,
  };
}

test('prepareLocalTargetSession recovers when startup command fails but readiness succeeds', async () => {
  const campaignDir = await mkdtemp(join(tmpdir(), 'security-lab-target-lifecycle-'));
  const server = await withServer((req, res) => {
    if (req.url === '/health') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"status":"ok"}');
      return;
    }
    res.writeHead(404);
    res.end();
  });

  try {
    const session = await prepareLocalTargetSession(
      buildTarget({ baseUrl: server.baseUrl }),
      campaignDir,
    );
    assert.equal(session.started, true);
    assert.ok(session.warnings?.some((warning) => warning.includes('readiness succeeded')));
  } finally {
    await server.close();
  }
});

test('prepareLocalTargetSession still fails when startup command fails and readiness never succeeds', async () => {
  const campaignDir = await mkdtemp(join(tmpdir(), 'security-lab-target-lifecycle-'));
  await assert.rejects(
    prepareLocalTargetSession(
      buildTarget(),
      campaignDir,
    ),
    /Local target startup failed/,
  );
});
