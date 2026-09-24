/**
 * Section 12.2 — CSRF fixture test.
 *
 * Tests the CSRF / Origin / Referer browser probe family using
 * mock browser implementations to verify verdict classification,
 * evidence capture, and negative controls.
 */
import assert from 'node:assert/strict';
import { rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';

import {
  executeCsrfProbe,
  type BrowserProbeRequest,
} from './browser-probe-families.js';
import type { BrowserLauncher, Browser, BrowserContext, BrowserPage } from './browser-runner.js';

// ---------------------------------------------------------------------------
// Mock browser that simulates CSRF probe execution
// ---------------------------------------------------------------------------

interface CsrfMockOptions {
  /** What the fetch in the attack page returns. */
  probeResult: {
    status: number | null;
    body: string;
    error: string | null;
    credentialsSent: boolean;
  };
  /** Console messages to emit. */
  consoleMessages?: Array<{ type: string; text: string }>;
}

function createCsrfMockLauncher(options: CsrfMockOptions): BrowserLauncher {
  return async () => {
    const page: BrowserPage = {
      async goto() {
        // Simulate loading the attack page — emit console messages
        if (options.consoleMessages) {
          for (const msg of options.consoleMessages) {
            for (const handler of consoleHandlers) {
              handler({ type: () => msg.type, text: () => msg.text });
            }
          }
        }
        return { url: () => 'data:text/html;base64,attack' };
      },
      url() { return 'data:text/html;base64,attack'; },
      async screenshot() { return Buffer.from('csrf-screenshot'); },
      async evaluate<T>(): Promise<T> {
        return options.probeResult as T;
      },
      on(event: string, handler: (msg: { type(): string; text(): string }) => void) {
        if (event === 'console') consoleHandlers.push(handler);
      },
      async close() { /* no-op */ },
    };

    const consoleHandlers: Array<(msg: { type(): string; text(): string }) => void> = [];

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
  return join(tmpdir(), `csrf-test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
}

function makeRequest(overrides?: Partial<BrowserProbeRequest>): BrowserProbeRequest {
  return {
    findingId: 'finding-csrf-1',
    hypothesis: 'CSRF on POST /api/users/settings',
    family: 'csrf_origin',
    variant: 'cross_origin_post',
    targetBaseUrl: 'http://localhost:4000',
    targetPath: '/api/users/settings',
    method: 'POST',
    body: JSON.stringify({ theme: 'dark' }),
    crossOriginUrl: 'https://evil.example.com',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test('executeCsrfProbe — confirms CSRF when cross-origin POST succeeds', async () => {
  const dir = makeTempDir();
  try {
    const launcher = createCsrfMockLauncher({
      probeResult: { status: 200, body: '{"ok":true}', error: null, credentialsSent: true },
    });

    const result = await executeCsrfProbe(makeRequest(), launcher, dir);

    assert.equal(result.verdict, 'confirmed');
    assert.equal(result.family, 'csrf_origin');
    assert.equal(result.variant, 'cross_origin_post');
    assert.ok(result.reasoning.includes('succeeded'));
    assert.ok(result.reasoning.includes('CSRF'));
    assert.equal(result.findingId, 'finding-csrf-1');

    // Evidence captured
    assert.ok(result.evidence.bundleId);
    assert.ok(result.evidence.screenshots.length > 0);

    // DOM assertion recorded
    assert.ok(result.domAssertions.length > 0);
    assert.equal(result.domAssertions[0].passed, false);

    // Network observation
    assert.ok(result.networkObservation);
    assert.equal(result.networkObservation.requestMethod, 'POST');
    assert.equal(result.networkObservation.responseStatus, 200);
    assert.equal(result.networkObservation.credentialsIncluded, true);

    assert.ok(result.durationMs >= 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('executeCsrfProbe — refutes CSRF when request is blocked by CORS', async () => {
  const dir = makeTempDir();
  try {
    const launcher = createCsrfMockLauncher({
      probeResult: { status: null, body: '', error: 'TypeError: Failed to fetch', credentialsSent: false },
    });

    const result = await executeCsrfProbe(makeRequest(), launcher, dir);

    assert.equal(result.verdict, 'refuted');
    assert.ok(result.reasoning.includes('blocked'));

    // Network observation shows blocked
    assert.ok(result.networkObservation);
    assert.equal(result.networkObservation.crossOriginBlocked, true);
    assert.equal(result.networkObservation.responseStatus, null);

    // DOM assertion passes (the block is the safe outcome)
    assert.ok(result.domAssertions.length > 0);
    assert.equal(result.domAssertions[0].passed, true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('executeCsrfProbe — refutes CSRF when server returns 403', async () => {
  const dir = makeTempDir();
  try {
    const launcher = createCsrfMockLauncher({
      probeResult: { status: 403, body: 'Forbidden', error: null, credentialsSent: true },
    });

    const result = await executeCsrfProbe(makeRequest(), launcher, dir);

    assert.equal(result.verdict, 'refuted');
    assert.ok(result.reasoning.includes('rejected'));
    assert.ok(result.reasoning.includes('403'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('executeCsrfProbe — inconclusive on unexpected status', async () => {
  const dir = makeTempDir();
  try {
    const launcher = createCsrfMockLauncher({
      probeResult: { status: 302, body: '', error: null, credentialsSent: true },
    });

    const result = await executeCsrfProbe(makeRequest(), launcher, dir);

    assert.equal(result.verdict, 'inconclusive');
    assert.ok(result.reasoning.includes('Cannot definitively'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('executeCsrfProbe — captures console observations', async () => {
  const dir = makeTempDir();
  try {
    const launcher = createCsrfMockLauncher({
      probeResult: { status: null, body: '', error: 'CORS blocked', credentialsSent: false },
      consoleMessages: [
        { type: 'error', text: 'Access to fetch blocked by CORS policy' },
        { type: 'log', text: 'Page loaded' },
      ],
    });

    const result = await executeCsrfProbe(makeRequest(), launcher, dir);

    assert.equal(result.verdict, 'refuted');
    assert.ok(result.consoleObservations.length >= 2);

    const corsObs = result.consoleObservations.find((o) => o.text.includes('CORS'));
    assert.ok(corsObs);
    assert.equal(corsObs.isSecurityRelevant, true);

    const loadObs = result.consoleObservations.find((o) => o.text === 'Page loaded');
    assert.ok(loadObs);
    assert.equal(loadObs.isSecurityRelevant, false);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('executeCsrfProbe — handles runtime error gracefully', async () => {
  const dir = makeTempDir();
  try {
    const launcher: BrowserLauncher = async () => {
      throw new Error('Chromium not installed');
    };

    const result = await executeCsrfProbe(makeRequest(), launcher, dir);

    assert.equal(result.verdict, 'runtime_error');
    assert.ok(result.reasoning.includes('Chromium not installed'));
    assert.ok(result.durationMs >= 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('executeCsrfProbe — negative control: 401 means CSRF is refuted', async () => {
  const dir = makeTempDir();
  try {
    const launcher = createCsrfMockLauncher({
      probeResult: { status: 401, body: 'Unauthorized', error: null, credentialsSent: false },
    });

    const result = await executeCsrfProbe(makeRequest(), launcher, dir);

    assert.equal(result.verdict, 'refuted');
    assert.ok(result.reasoning.includes('rejected'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
