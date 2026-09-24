/**
 * Section 12.1 — Tests for runBrowserSession.
 *
 * Uses mock Browser/BrowserContext/BrowserPage implementations
 * to verify end-to-end session flow, storage-state capture,
 * evidence collection, and error handling without Playwright.
 */
import assert from 'node:assert/strict';
import { readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';

import {
  runBrowserSession,
  type BrowserCapability,
  type BrowserLauncher,
  type Browser,
  type BrowserContext,
  type BrowserPage,
} from './browser-runner.js';

// ---------------------------------------------------------------------------
// Mock browser implementation
// ---------------------------------------------------------------------------

interface MockPageOptions {
  /** Pages the mock will navigate to. Keys are URLs. */
  responses?: Record<string, { url: string }>;
  /** Storage key counts returned by evaluate. */
  storageKeyCounts?: Record<string, { localStorage: number; sessionStorage: number }>;
  /** Console messages to emit after navigation. */
  consoleMessages?: Array<{ type: string; text: string }>;
  /** If set, goto will reject with this error. */
  gotoError?: Error;
}

function createMockPage(options: MockPageOptions = {}): BrowserPage {
  let currentUrl = 'about:blank';
  const consoleHandlers: Array<(msg: { type(): string; text(): string }) => void> = [];

  return {
    async goto(url: string) {
      if (options.gotoError) throw options.gotoError;
      const resp = options.responses?.[url];
      currentUrl = resp?.url ?? url;

      // Emit console messages after navigation
      if (options.consoleMessages) {
        for (const msg of options.consoleMessages) {
          for (const handler of consoleHandlers) {
            handler({ type: () => msg.type, text: () => msg.text });
          }
        }
        // Only emit once
        options.consoleMessages = undefined;
      }

      return { url: () => currentUrl };
    },
    url() {
      return currentUrl;
    },
    async screenshot() {
      return Buffer.from(`screenshot-of-${currentUrl}`);
    },
    async evaluate<T>(): Promise<T> {
      const counts = options.storageKeyCounts ?? {
        'http://localhost:3000': { localStorage: 0, sessionStorage: 0 },
      };
      return counts as T;
    },
    on(event: string, handler: (msg: { type(): string; text(): string }) => void) {
      if (event === 'console') {
        consoleHandlers.push(handler);
      }
    },
    async close() { /* no-op */ },
  };
}

function createMockContext(pageOptions: MockPageOptions = {}): BrowserContext & { cookies_: Array<{
  name: string; domain: string; path: string;
  httpOnly: boolean; secure: boolean; sameSite: 'Strict' | 'Lax' | 'None'; expires: number;
}> } {
  return {
    cookies_: [
      {
        name: 'session_id',
        domain: 'localhost',
        path: '/',
        httpOnly: true,
        secure: false,
        sameSite: 'Lax' as const,
        expires: -1,
      },
    ],
    async newPage() {
      return createMockPage(pageOptions);
    },
    async cookies() {
      return this.cookies_;
    },
    async close() { /* no-op */ },
  };
}

function createMockBrowser(pageOptions: MockPageOptions = {}): Browser {
  return {
    async newContext() {
      return createMockContext(pageOptions);
    },
    async close() { /* no-op */ },
  };
}

function createMockLauncher(pageOptions: MockPageOptions = {}): BrowserLauncher {
  return async () => createMockBrowser(pageOptions);
}

function makeTempDir(): string {
  return join(tmpdir(), `browser-runner-test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test('runBrowserSession — successful bootstrap with storage-state capture', async () => {
  const dir = makeTempDir();
  try {
    const capability: BrowserCapability = {
      enabled: true,
      bootstrapUrl: 'http://localhost:3000/login',
      storageStateExpectations: {
        expectedCookies: ['session_id'],
      },
    };

    const launcher = createMockLauncher({
      storageKeyCounts: {
        'http://localhost:3000': { localStorage: 3, sessionStorage: 1 },
      },
    });

    const result = await runBrowserSession(capability, launcher, dir);

    assert.equal(result.success, true);
    assert.equal(result.error, undefined);
    assert.ok(result.durationMs >= 0);

    // Evidence bundle should have content
    const { evidence } = result;
    assert.ok(evidence.bundleId.startsWith('browser-'));
    assert.equal(evidence.screenshots.length, 1);
    assert.equal(evidence.screenshots[0].label, 'after-bootstrap');
    assert.equal(evidence.urlTransitions.length, 1);
    assert.equal(evidence.urlTransitions[0].from, '');
    assert.equal(evidence.urlTransitions[0].to, 'http://localhost:3000/login');

    // Storage state captured
    assert.ok(evidence.storageState);
    assert.equal(evidence.storageState.cookies.length, 1);
    assert.equal(evidence.storageState.cookies[0].name, 'session_id');
    assert.equal(evidence.storageState.storageKeyCounts['http://localhost:3000'].localStorage, 3);

    // Storage-state validation passed
    assert.ok(result.storageStateValidation);
    assert.equal(result.storageStateValidation.passed, true);
    assert.equal(result.storageStateValidation.missingCookies.length, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('runBrowserSession — storage-state validation fails on missing cookies', async () => {
  const dir = makeTempDir();
  try {
    const capability: BrowserCapability = {
      enabled: true,
      bootstrapUrl: 'http://localhost:3000/',
      storageStateExpectations: {
        expectedCookies: ['session_id', 'csrf_token'],
        expectedStorageOrigins: ['http://localhost:3000', 'http://other.example.com'],
      },
    };

    const launcher = createMockLauncher({
      storageKeyCounts: {
        'http://localhost:3000': { localStorage: 1, sessionStorage: 0 },
      },
    });

    const result = await runBrowserSession(capability, launcher, dir);

    assert.equal(result.success, true);
    assert.ok(result.storageStateValidation);
    assert.equal(result.storageStateValidation.passed, false);
    assert.deepEqual(result.storageStateValidation.missingCookies, ['csrf_token']);
    assert.deepEqual(result.storageStateValidation.missingStorageOrigins, ['http://other.example.com']);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('runBrowserSession — evidence paths produce screenshots', async () => {
  const dir = makeTempDir();
  try {
    const capability: BrowserCapability = {
      enabled: true,
      bootstrapUrl: 'http://localhost:3000/',
      evidencePaths: ['/admin', '/settings'],
    };

    const launcher = createMockLauncher();
    const result = await runBrowserSession(capability, launcher, dir);

    assert.equal(result.success, true);
    // 1 bootstrap + 2 evidence paths = 3 screenshots
    assert.equal(result.evidence.screenshots.length, 3);
    assert.equal(result.evidence.screenshots[0].label, 'after-bootstrap');
    assert.ok(result.evidence.screenshots[1].label?.includes('admin'));
    assert.ok(result.evidence.screenshots[2].label?.includes('settings'));

    // 3 URL transitions (bootstrap + 2 evidence paths)
    assert.equal(result.evidence.urlTransitions.length, 3);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('runBrowserSession — captures console messages', async () => {
  const dir = makeTempDir();
  try {
    const capability: BrowserCapability = {
      enabled: true,
      bootstrapUrl: 'http://localhost:3000/',
    };

    const launcher = createMockLauncher({
      consoleMessages: [
        { type: 'error', text: 'Uncaught ReferenceError' },
        { type: 'warn', text: 'Deprecation notice' },
      ],
    });

    const result = await runBrowserSession(capability, launcher, dir);

    assert.equal(result.success, true);
    assert.equal(result.evidence.consoleLogs.length, 2);
    assert.equal(result.evidence.consoleLogs[0].level, 'error');
    assert.equal(result.evidence.consoleLogs[0].text, 'Uncaught ReferenceError');
    assert.equal(result.evidence.consoleLogs[1].level, 'warn');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('runBrowserSession — handles navigation error gracefully', async () => {
  const dir = makeTempDir();
  try {
    const capability: BrowserCapability = {
      enabled: true,
      bootstrapUrl: 'http://localhost:3000/',
    };

    const launcher = createMockLauncher({
      gotoError: new Error('net::ERR_CONNECTION_REFUSED'),
    });

    const result = await runBrowserSession(capability, launcher, dir);

    assert.equal(result.success, false);
    assert.ok(result.error?.includes('ERR_CONNECTION_REFUSED'));
    assert.ok(result.durationMs >= 0);
    // Evidence bundle is still finalized even on error
    assert.ok(result.evidence.bundleId);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('runBrowserSession — no bootstrap URL skips navigation', async () => {
  const dir = makeTempDir();
  try {
    const capability: BrowserCapability = {
      enabled: true,
      // No bootstrapUrl, no evidencePaths
    };

    const launcher = createMockLauncher();
    const result = await runBrowserSession(capability, launcher, dir);

    assert.equal(result.success, true);
    assert.equal(result.evidence.screenshots.length, 0);
    assert.equal(result.evidence.urlTransitions.length, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('runBrowserSession — bundle.json persisted to evidence directory', async () => {
  const dir = makeTempDir();
  try {
    const capability: BrowserCapability = {
      enabled: true,
      bootstrapUrl: 'http://localhost:3000/',
    };

    const launcher = createMockLauncher();
    const result = await runBrowserSession(capability, launcher, dir);

    // Verify the bundle file was written
    const bundlePath = join(dir, 'browser', result.evidence.bundleId, 'bundle.json');
    const raw = await readFile(bundlePath, 'utf8');
    const persisted = JSON.parse(raw);
    assert.equal(persisted.bundleId, result.evidence.bundleId);
    assert.ok(persisted.finalizedAt);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('runBrowserSession — no storage-state validation without expectations', async () => {
  const dir = makeTempDir();
  try {
    const capability: BrowserCapability = {
      enabled: true,
      bootstrapUrl: 'http://localhost:3000/',
      // No storageStateExpectations
    };

    const launcher = createMockLauncher();
    const result = await runBrowserSession(capability, launcher, dir);

    assert.equal(result.success, true);
    assert.equal(result.storageStateValidation, undefined);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
