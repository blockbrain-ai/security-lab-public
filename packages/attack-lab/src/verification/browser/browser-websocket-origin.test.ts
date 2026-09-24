/**
 * Section 12.2 — WebSocket origin validation fixture test.
 *
 * Tests the websocket_origin browser probe family using mock browser
 * implementations. Verifies that cross-origin WebSocket connections
 * are correctly classified as confirmed (accepted) or refuted (rejected).
 */
import assert from 'node:assert/strict';
import { rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';

import {
  executeWebSocketOriginProbe,
  type BrowserProbeRequest,
} from './browser-probe-families.js';
import type { BrowserLauncher, Browser, BrowserContext, BrowserPage } from './browser-runner.js';

// ---------------------------------------------------------------------------
// Mock browser that simulates WebSocket probe execution
// ---------------------------------------------------------------------------

interface WsMockOptions {
  wsResult: {
    connected: boolean;
    error: string | null;
    closeCode: number | null;
    messageReceived: boolean;
  };
  consoleMessages?: Array<{ type: string; text: string }>;
}

function createWsMockLauncher(options: WsMockOptions): BrowserLauncher {
  return async () => {
    const consoleHandlers: Array<(msg: { type(): string; text(): string }) => void> = [];

    const page: BrowserPage = {
      async goto() {
        if (options.consoleMessages) {
          for (const msg of options.consoleMessages) {
            for (const handler of consoleHandlers) {
              handler({ type: () => msg.type, text: () => msg.text });
            }
          }
        }
        return { url: () => 'data:text/html;base64,ws-attack' };
      },
      url() { return 'data:text/html;base64,ws-attack'; },
      async screenshot() { return Buffer.from('ws-screenshot'); },
      async evaluate<T>(): Promise<T> {
        return options.wsResult as T;
      },
      on(event: string, handler: (msg: { type(): string; text(): string }) => void) {
        if (event === 'console') consoleHandlers.push(handler);
      },
      async close() { /* no-op */ },
    };

    const context: BrowserContext = {
      async newPage() { return page; },
      async cookies() { return []; },
      async close() { /* no-op */ },
    };

    const browser: Browser = {
      async newContext() { return context; },
      async close() { /* no-op */ },
    };

    return browser;
  };
}

function makeTempDir(): string {
  return join(tmpdir(), `ws-test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
}

function makeRequest(overrides?: Partial<BrowserProbeRequest>): BrowserProbeRequest {
  return {
    findingId: 'finding-ws-1',
    hypothesis: 'WebSocket endpoint accepts any origin',
    family: 'websocket_origin',
    variant: 'cross_origin_ws',
    targetBaseUrl: 'http://localhost:4000',
    targetPath: '/ws/stream',
    websocketPath: '/ws/stream',
    crossOriginUrl: 'https://evil.example.com',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test('executeWebSocketOriginProbe — confirms when cross-origin WS connection succeeds', async () => {
  const dir = makeTempDir();
  try {
    const launcher = createWsMockLauncher({
      wsResult: { connected: true, error: null, closeCode: 1000, messageReceived: false },
    });

    const result = await executeWebSocketOriginProbe(makeRequest(), launcher, dir);

    assert.equal(result.verdict, 'confirmed');
    assert.equal(result.family, 'websocket_origin');
    assert.equal(result.variant, 'cross_origin_ws');
    assert.ok(result.reasoning.includes('accepted'));
    assert.ok(result.reasoning.includes('Origin'));

    // DOM assertion
    assert.ok(result.domAssertions.length > 0);
    const wsAssertion = result.domAssertions.find((a) => a.selector === 'ws-connection');
    assert.ok(wsAssertion);
    assert.equal(wsAssertion.expected, 'rejected');
    assert.equal(wsAssertion.actual, 'connected');
    assert.equal(wsAssertion.passed, false);

    // Network observation
    assert.ok(result.networkObservation);
    assert.equal(result.networkObservation.responseStatus, 101);
    assert.equal(result.networkObservation.crossOriginBlocked, false);

    // Evidence captured
    assert.ok(result.evidence.bundleId);
    assert.ok(result.evidence.screenshots.length > 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('executeWebSocketOriginProbe — refutes when cross-origin WS is rejected', async () => {
  const dir = makeTempDir();
  try {
    const launcher = createWsMockLauncher({
      wsResult: { connected: false, error: 'connection_error', closeCode: null, messageReceived: false },
    });

    const result = await executeWebSocketOriginProbe(makeRequest(), launcher, dir);

    assert.equal(result.verdict, 'refuted');
    assert.ok(result.reasoning.includes('rejected'));
    assert.ok(result.reasoning.includes('Origin validation'));

    // DOM assertion passes (rejection is the safe outcome)
    const wsAssertion = result.domAssertions.find((a) => a.selector === 'ws-connection');
    assert.ok(wsAssertion);
    assert.equal(wsAssertion.passed, true);
    assert.equal(wsAssertion.actual, 'rejected');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('executeWebSocketOriginProbe — inconclusive when result is indeterminate', async () => {
  const dir = makeTempDir();
  try {
    const launcher = createWsMockLauncher({
      wsResult: { connected: false, error: null, closeCode: null, messageReceived: false },
    });

    const result = await executeWebSocketOriginProbe(makeRequest(), launcher, dir);

    assert.equal(result.verdict, 'inconclusive');
    assert.ok(result.reasoning.includes('indeterminate'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('executeWebSocketOriginProbe — handles runtime error gracefully', async () => {
  const dir = makeTempDir();
  try {
    const launcher: BrowserLauncher = async () => {
      throw new Error('Browser not available');
    };

    const result = await executeWebSocketOriginProbe(makeRequest(), launcher, dir);

    assert.equal(result.verdict, 'runtime_error');
    assert.ok(result.reasoning.includes('Browser not available'));
    assert.ok(result.durationMs >= 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('executeWebSocketOriginProbe — uses default WS path from targetPath', async () => {
  const dir = makeTempDir();
  try {
    const launcher = createWsMockLauncher({
      wsResult: { connected: true, error: null, closeCode: 1000, messageReceived: false },
    });

    const result = await executeWebSocketOriginProbe(
      makeRequest({ websocketPath: undefined, targetPath: '/api/socket' }),
      launcher,
      dir,
    );

    assert.equal(result.verdict, 'confirmed');
    assert.ok(result.reasoning.includes('/api/socket'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('executeWebSocketOriginProbe — uses custom crossOriginUrl', async () => {
  const dir = makeTempDir();
  try {
    const launcher = createWsMockLauncher({
      wsResult: { connected: true, error: null, closeCode: 1000, messageReceived: false },
    });

    const result = await executeWebSocketOriginProbe(
      makeRequest({ crossOriginUrl: 'https://competitor.example.com' }),
      launcher,
      dir,
    );

    assert.equal(result.verdict, 'confirmed');
    assert.ok(result.reasoning.includes('competitor.example.com'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
