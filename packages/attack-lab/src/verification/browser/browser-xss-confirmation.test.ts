/**
 * Section 12.2 — Stored XSS confirmation fixture test.
 *
 * Tests the stored_xss browser probe family using mock browser
 * implementations. Verifies that XSS payloads are detected in
 * the DOM and through console canary execution.
 */
import assert from 'node:assert/strict';
import { rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';

import {
  executeStoredXssProbe,
  type BrowserProbeRequest,
} from './browser-probe-families.js';
import type { BrowserLauncher, Browser, BrowserContext, BrowserPage } from './browser-runner.js';

// ---------------------------------------------------------------------------
// Mock browser for XSS probe execution
// ---------------------------------------------------------------------------

interface XssMockOptions {
  /** HTML content returned by page DOM. */
  domContent: string;
  /** Console messages to emit (XSS canary fires if text contains marker). */
  consoleMessages?: Array<{ type: string; text: string }>;
}

function createXssMockLauncher(options: XssMockOptions): BrowserLauncher {
  return async () => {
    const consoleHandlers: Array<(msg: { type(): string; text(): string }) => void> = [];

    const page: BrowserPage = {
      async goto() {
        // After navigation, fire console messages (simulating XSS execution)
        if (options.consoleMessages) {
          for (const msg of options.consoleMessages) {
            for (const handler of consoleHandlers) {
              handler({ type: () => msg.type, text: () => msg.text });
            }
          }
        }
        return { url: () => 'http://localhost:4000/comments' };
      },
      url() { return 'http://localhost:4000/comments'; },
      async screenshot() { return Buffer.from('xss-screenshot'); },
      async evaluate<T>(): Promise<T> {
        // Return the DOM content for the XSS check
        return options.domContent as T;
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
  return join(tmpdir(), `xss-test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
}

function makeRequest(overrides?: Partial<BrowserProbeRequest>): BrowserProbeRequest {
  return {
    findingId: 'finding-xss-1',
    hypothesis: 'Stored XSS in comment field',
    family: 'stored_xss',
    variant: 'script_injection',
    targetBaseUrl: 'http://localhost:4000',
    targetPath: '/comments',
    xssPayload: '<script>alert(1)</script>',
    xssDomSelector: 'body',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test('executeStoredXssProbe — confirms when canary script fires', async () => {
  const dir = makeTempDir();
  try {
    const launcher = createXssMockLauncher({
      domContent: '<div class="comment"><script>console.log("__SECURITY_LAB_XSS_CANARY__")</script></div>',
      consoleMessages: [
        { type: 'log', text: '__SECURITY_LAB_XSS_CANARY__' },
      ],
    });

    const result = await executeStoredXssProbe(makeRequest(), launcher, dir);

    assert.equal(result.verdict, 'confirmed');
    assert.equal(result.family, 'stored_xss');
    assert.ok(result.reasoning.includes('canary script executed'));
    assert.ok(result.reasoning.includes('/comments'));

    // DOM assertion recorded
    assert.ok(result.domAssertions.length > 0);
    assert.equal(result.domAssertions[0].passed, false); // not passed = vulnerable

    // Console observation captured canary
    const canaryObs = result.consoleObservations.find((o) =>
      o.text.includes('__SECURITY_LAB_XSS_CANARY__'),
    );
    assert.ok(canaryObs);
    assert.equal(canaryObs.isSecurityRelevant, true);

    // Evidence captured
    assert.ok(result.evidence.bundleId);
    assert.ok(result.evidence.screenshots.length > 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('executeStoredXssProbe — confirms when payload is in DOM (no execution)', async () => {
  const dir = makeTempDir();
  try {
    const launcher = createXssMockLauncher({
      domContent: '<div class="comment"><script>alert(1)</script></div>',
      // No console messages — script didn't fire but payload is in DOM
    });

    const result = await executeStoredXssProbe(makeRequest(), launcher, dir);

    assert.equal(result.verdict, 'confirmed');
    assert.ok(result.reasoning.includes('unescaped HTML payload'));
    assert.ok(result.reasoning.includes('<script>'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('executeStoredXssProbe — refutes when payload is properly escaped', async () => {
  const dir = makeTempDir();
  try {
    const launcher = createXssMockLauncher({
      domContent: '<div class="comment">&lt;script&gt;alert(1)&lt;/script&gt;</div>',
    });

    const result = await executeStoredXssProbe(makeRequest(), launcher, dir);

    assert.equal(result.verdict, 'refuted');
    assert.ok(result.reasoning.includes('not confirmed'));
    assert.ok(result.reasoning.includes('sanitize'));

    // DOM assertion passes (escaped = safe)
    assert.ok(result.domAssertions.length > 0);
    assert.equal(result.domAssertions[0].passed, true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('executeStoredXssProbe — refutes when payload is not in DOM at all', async () => {
  const dir = makeTempDir();
  try {
    const launcher = createXssMockLauncher({
      domContent: '<div class="comment">Hello, world!</div>',
    });

    const result = await executeStoredXssProbe(makeRequest(), launcher, dir);

    assert.equal(result.verdict, 'refuted');
    assert.ok(result.reasoning.includes('not found'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('executeStoredXssProbe — handles event handler injection variant', async () => {
  const dir = makeTempDir();
  try {
    const launcher = createXssMockLauncher({
      domContent: '<img src=x onerror="alert(1)">',
    });

    const result = await executeStoredXssProbe(
      makeRequest({
        variant: 'event_handler_injection',
        xssPayload: 'onerror="alert(1)"',
      }),
      launcher,
      dir,
    );

    assert.equal(result.verdict, 'confirmed');
    assert.ok(result.reasoning.includes('onerror'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('executeStoredXssProbe — handles runtime error gracefully', async () => {
  const dir = makeTempDir();
  try {
    const launcher: BrowserLauncher = async () => {
      throw new Error('Playwright crashed');
    };

    const result = await executeStoredXssProbe(makeRequest(), launcher, dir);

    assert.equal(result.verdict, 'runtime_error');
    assert.ok(result.reasoning.includes('Playwright crashed'));
    assert.ok(result.durationMs >= 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('executeStoredXssProbe — uses default payload when none specified', async () => {
  const dir = makeTempDir();
  try {
    const launcher = createXssMockLauncher({
      domContent: '<div>safe content only</div>',
    });

    const result = await executeStoredXssProbe(
      makeRequest({ xssPayload: undefined }),
      launcher,
      dir,
    );

    assert.equal(result.verdict, 'refuted');
    // Default payload is '<script>' — should not be found
    assert.ok(result.reasoning.includes('<script>'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('executeStoredXssProbe — confirms DOM mutation variant', async () => {
  const dir = makeTempDir();
  try {
    const launcher = createXssMockLauncher({
      domContent: '<div class="post"><b>bold text</b> injected markup</div>',
    });

    const result = await executeStoredXssProbe(
      makeRequest({
        variant: 'dom_mutation',
        xssPayload: '<b>bold text</b>',
      }),
      launcher,
      dir,
    );

    assert.equal(result.verdict, 'confirmed');
    assert.ok(result.reasoning.includes('unescaped HTML'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
