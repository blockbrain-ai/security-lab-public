/**
 * Section 12.1 — Tests for BrowserEvidenceCollector.
 */
import assert from 'node:assert/strict';
import { readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';
import { BrowserEvidenceCollector } from './browser-evidence.js';
import type { BrowserStorageState } from './browser-evidence.js';

function makeTempDir(): string {
  return join(tmpdir(), `browser-evidence-test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
}

test('BrowserEvidenceCollector — records console entries', async () => {
  const dir = makeTempDir();
  try {
    const collector = new BrowserEvidenceCollector(dir, 'finding-1');
    collector.addConsoleEntry('error', 'Uncaught TypeError', 'http://localhost:3000/app');
    collector.addConsoleEntry('warn', 'Deprecation warning', 'http://localhost:3000/app');

    const bundle = await collector.finalize();

    assert.equal(bundle.consoleLogs.length, 2);
    assert.equal(bundle.consoleLogs[0].level, 'error');
    assert.equal(bundle.consoleLogs[0].text, 'Uncaught TypeError');
    assert.equal(bundle.consoleLogs[1].level, 'warn');
    assert.equal(bundle.findingId, 'finding-1');
    assert.ok(bundle.bundleId.startsWith('browser-'));
    assert.ok(bundle.finalizedAt);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('BrowserEvidenceCollector — records URL transitions', async () => {
  const dir = makeTempDir();
  try {
    const collector = new BrowserEvidenceCollector(dir);
    collector.addUrlTransition('', 'http://localhost:3000/login');
    collector.addUrlTransition('http://localhost:3000/login', 'http://localhost:3000/dashboard');

    const bundle = await collector.finalize();

    assert.equal(bundle.urlTransitions.length, 2);
    assert.equal(bundle.urlTransitions[0].from, '');
    assert.equal(bundle.urlTransitions[0].to, 'http://localhost:3000/login');
    assert.equal(bundle.urlTransitions[1].from, 'http://localhost:3000/login');
    assert.equal(bundle.urlTransitions[1].to, 'http://localhost:3000/dashboard');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('BrowserEvidenceCollector — captures storage state', async () => {
  const dir = makeTempDir();
  try {
    const collector = new BrowserEvidenceCollector(dir);
    const state: BrowserStorageState = {
      cookies: [
        {
          name: 'session_id',
          domain: 'localhost',
          path: '/',
          httpOnly: true,
          secure: false,
          sameSite: 'Lax',
          expires: -1,
        },
      ],
      storageKeyCounts: {
        'http://localhost:3000': { localStorage: 2, sessionStorage: 1 },
      },
      capturedAt: new Date().toISOString(),
    };

    collector.setStorageState(state);
    const bundle = await collector.finalize();

    assert.ok(bundle.storageState);
    assert.equal(bundle.storageState.cookies.length, 1);
    assert.equal(bundle.storageState.cookies[0].name, 'session_id');
    assert.equal(bundle.storageState.storageKeyCounts['http://localhost:3000'].localStorage, 2);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('BrowserEvidenceCollector — persists screenshots to disk', async () => {
  const dir = makeTempDir();
  try {
    const collector = new BrowserEvidenceCollector(dir, 'finding-2');
    const fakePng = Buffer.from('fake-png-data');
    const screenshot = await collector.addScreenshot(
      'http://localhost:3000/page',
      fakePng,
      'after-login',
    );

    assert.ok(screenshot.artifactId.startsWith('screenshot-'));
    assert.equal(screenshot.url, 'http://localhost:3000/page');
    assert.equal(screenshot.label, 'after-login');
    assert.ok(screenshot.relativePath.endsWith('.png'));

    // Verify file was written
    const fullPath = join(dir, screenshot.relativePath);
    const content = await readFile(fullPath);
    assert.deepEqual(content, fakePng);

    const bundle = await collector.finalize();
    assert.equal(bundle.screenshots.length, 1);
    assert.equal(bundle.screenshots[0].artifactId, screenshot.artifactId);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('BrowserEvidenceCollector — persists bundle.json to disk', async () => {
  const dir = makeTempDir();
  try {
    const collector = new BrowserEvidenceCollector(dir);
    collector.addConsoleEntry('log', 'hello', 'http://localhost/');
    const bundle = await collector.finalize();

    // Read the persisted bundle
    const bundlePath = join(dir, 'browser', bundle.bundleId, 'bundle.json');
    const raw = await readFile(bundlePath, 'utf8');
    const persisted = JSON.parse(raw);

    assert.equal(persisted.bundleId, bundle.bundleId);
    assert.equal(persisted.consoleLogs.length, 1);
    assert.equal(persisted.consoleLogs[0].text, 'hello');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('BrowserEvidenceCollector — empty bundle when nothing collected', async () => {
  const dir = makeTempDir();
  try {
    const collector = new BrowserEvidenceCollector(dir);
    const bundle = await collector.finalize();

    assert.equal(bundle.screenshots.length, 0);
    assert.equal(bundle.consoleLogs.length, 0);
    assert.equal(bundle.urlTransitions.length, 0);
    assert.equal(bundle.storageState, null);
    assert.equal(bundle.findingId, undefined);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
