/**
 * Section 12.2 — Tests for browser probe family contracts and helpers.
 *
 * Covers classification, registry lookups, target resolution,
 * summary accumulation, and the probe dispatcher.
 */
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  executeBrowserProbe,
  BROWSER_FAMILY_REGISTRY,
  classifyBrowserHypothesis,
  getBrowserFamilyDefinition,
  resolveTargetBrowserFamilies,
  emptyBrowserExploitFamilySummary,
  accumulateBrowserProbeResult,
  type BrowserProbeFamilyId,
  type BrowserProbeResult,
} from './browser-probe-families.js';

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

test('BROWSER_FAMILY_REGISTRY — has all four families', () => {
  const ids = BROWSER_FAMILY_REGISTRY.map((f) => f.id);
  assert.ok(ids.includes('csrf_origin'));
  assert.ok(ids.includes('samesite_cookie'));
  assert.ok(ids.includes('websocket_origin'));
  assert.ok(ids.includes('stored_xss'));
  assert.equal(BROWSER_FAMILY_REGISTRY.length, 4);
});

test('BROWSER_FAMILY_REGISTRY — each family has at least one variant', () => {
  for (const family of BROWSER_FAMILY_REGISTRY) {
    assert.ok(family.defaultVariants.length > 0, `${family.id} should have variants`);
    for (const v of family.defaultVariants) {
      assert.ok(v.key.length > 0);
      assert.ok(v.label.length > 0);
      assert.ok(v.description.length > 0);
    }
  }
});

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

test('classifyBrowserHypothesis — classifies CSRF hypotheses', () => {
  assert.equal(classifyBrowserHypothesis('CSRF token missing on POST /api/users'), 'csrf_origin');
  assert.equal(classifyBrowserHypothesis('cross-site request forgery on profile update'), 'csrf_origin');
  assert.equal(classifyBrowserHypothesis('anti-csrf token bypass'), 'csrf_origin');
});

test('classifyBrowserHypothesis — classifies SameSite/cookie hypotheses', () => {
  assert.equal(classifyBrowserHypothesis('SameSite cookie not set on session cookie'), 'samesite_cookie');
  assert.equal(classifyBrowserHypothesis('Session cookie missing HttpOnly flag'), 'samesite_cookie');
  assert.equal(classifyBrowserHypothesis('cookie attribute misconfiguration'), 'samesite_cookie');
});

test('classifyBrowserHypothesis — classifies WebSocket origin hypotheses', () => {
  assert.equal(classifyBrowserHypothesis('WebSocket connection accepts any origin'), 'websocket_origin');
  assert.equal(classifyBrowserHypothesis('CSWSH via cross-origin WS upgrade'), 'websocket_origin');
  assert.equal(classifyBrowserHypothesis('ws://localhost:8080/stream origin check missing'), 'websocket_origin');
});

test('classifyBrowserHypothesis — classifies stored XSS hypotheses', () => {
  assert.equal(classifyBrowserHypothesis('Stored XSS in user profile bio field'), 'stored_xss');
  assert.equal(classifyBrowserHypothesis('persistent XSS via markdown renderer'), 'stored_xss');
  assert.equal(classifyBrowserHypothesis('HTML injection in comment field'), 'stored_xss');
});

test('classifyBrowserHypothesis — returns undefined for non-browser hypotheses', () => {
  assert.equal(classifyBrowserHypothesis('SQL injection in login form'), undefined);
  assert.equal(classifyBrowserHypothesis('IDOR in /api/v1/decisions'), undefined);
  assert.equal(classifyBrowserHypothesis('path traversal in file upload'), undefined);
});

// ---------------------------------------------------------------------------
// Family lookup
// ---------------------------------------------------------------------------

test('getBrowserFamilyDefinition — returns definition for valid IDs', () => {
  const csrf = getBrowserFamilyDefinition('csrf_origin');
  assert.ok(csrf);
  assert.equal(csrf.id, 'csrf_origin');
  assert.ok(csrf.defaultVariants.length >= 2);

  const xss = getBrowserFamilyDefinition('stored_xss');
  assert.ok(xss);
  assert.equal(xss.id, 'stored_xss');
});

test('getBrowserFamilyDefinition — returns undefined for unknown ID', () => {
  assert.equal(getBrowserFamilyDefinition('nonexistent' as BrowserProbeFamilyId), undefined);
});

// ---------------------------------------------------------------------------
// Target resolution
// ---------------------------------------------------------------------------

test('resolveTargetBrowserFamilies — returns empty when browser disabled', () => {
  const result = resolveTargetBrowserFamilies(false, undefined);
  assert.equal(result.length, 0);
});

test('resolveTargetBrowserFamilies — returns all families when enabled without config', () => {
  const result = resolveTargetBrowserFamilies(true, undefined);
  assert.equal(result.length, 4);
  const ids = result.map((r) => r.family);
  assert.ok(ids.includes('csrf_origin'));
  assert.ok(ids.includes('samesite_cookie'));
  assert.ok(ids.includes('websocket_origin'));
  assert.ok(ids.includes('stored_xss'));
});

test('resolveTargetBrowserFamilies — respects explicit config', () => {
  const result = resolveTargetBrowserFamilies(true, [
    { family: 'csrf_origin', sessionCookieName: 'sid' },
    { family: 'stored_xss', disabledVariants: ['dom_mutation'] },
  ]);
  assert.equal(result.length, 2);
  assert.equal(result[0].family, 'csrf_origin');
  assert.equal(result[0].sessionCookieName, 'sid');
  assert.equal(result[1].family, 'stored_xss');
  assert.deepEqual(result[1].disabledVariants, ['dom_mutation']);
});

// ---------------------------------------------------------------------------
// Summary accumulation
// ---------------------------------------------------------------------------

test('emptyBrowserExploitFamilySummary — starts at zero', () => {
  const summary = emptyBrowserExploitFamilySummary();
  assert.equal(summary.totalBrowserProbes, 0);
  assert.deepEqual(summary.byFamily, {});
});

test('accumulateBrowserProbeResult — tracks probes by family', () => {
  const summary = emptyBrowserExploitFamilySummary();

  const makeResult = (family: BrowserProbeFamilyId, variant: string, verdict: string): BrowserProbeResult => ({
    findingId: 'f-1',
    hypothesis: 'test',
    family,
    variant,
    verdict: verdict as BrowserProbeResult['verdict'],
    reasoning: 'test reason',
    evidence: {
      bundleId: 'b-1',
      screenshots: [],
      consoleLogs: [],
      urlTransitions: [],
      storageState: null,
      finalizedAt: new Date().toISOString(),
    },
    domAssertions: [],
    consoleObservations: [],
    durationMs: 100,
  });

  accumulateBrowserProbeResult(summary, makeResult('csrf_origin', 'cross_origin_post', 'confirmed'));
  accumulateBrowserProbeResult(summary, makeResult('csrf_origin', 'missing_origin_header', 'refuted'));
  accumulateBrowserProbeResult(summary, makeResult('stored_xss', 'script_injection', 'confirmed'));

  assert.equal(summary.totalBrowserProbes, 3);
  assert.equal(summary.byFamily['csrf_origin'].probes, 2);
  assert.equal(summary.byFamily['csrf_origin'].confirmed, 1);
  assert.equal(summary.byFamily['csrf_origin'].refuted, 1);
  assert.deepEqual(summary.byFamily['csrf_origin'].variants, ['cross_origin_post', 'missing_origin_header']);
  assert.equal(summary.byFamily['stored_xss'].probes, 1);
  assert.equal(summary.byFamily['stored_xss'].confirmed, 1);
});

test('accumulateBrowserProbeResult — does not duplicate variant keys', () => {
  const summary = emptyBrowserExploitFamilySummary();

  const makeResult = (family: BrowserProbeFamilyId, variant: string, verdict: string): BrowserProbeResult => ({
    findingId: 'f-1',
    hypothesis: 'test',
    family,
    variant,
    verdict: verdict as BrowserProbeResult['verdict'],
    reasoning: 'test reason',
    evidence: {
      bundleId: 'b-1',
      screenshots: [],
      consoleLogs: [],
      urlTransitions: [],
      storageState: null,
      finalizedAt: new Date().toISOString(),
    },
    domAssertions: [],
    consoleObservations: [],
    durationMs: 100,
  });

  accumulateBrowserProbeResult(summary, makeResult('websocket_origin', 'cross_origin_ws', 'confirmed'));
  accumulateBrowserProbeResult(summary, makeResult('websocket_origin', 'cross_origin_ws', 'refuted'));

  assert.equal(summary.byFamily['websocket_origin'].probes, 2);
  assert.deepEqual(summary.byFamily['websocket_origin'].variants, ['cross_origin_ws']);
});

test('executeBrowserProbe does not launch a browser when the policy runtime blocks it', async () => {
  let launched = 0;
  const launcher = (async () => {
    launched += 1;
    throw new Error('launcher must not be called for a blocked probe');
  }) as never;

  const result = await executeBrowserProbe(
    {
      findingId: 'f-browser-gate',
      hypothesis: 'stored XSS in a shared field',
      family: 'stored_xss',
      variant: 'default',
      targetBaseUrl: 'https://staging.example',
      targetPath: '/records/1',
    },
    launcher,
    '/tmp/sl-browser-gate',
    {
      runtime: {
        authorizeProbe: () => ({
          allowed: false,
          observedSafetyState: 'blocked',
          reason: 'Shell-adjacent probes are disabled in staging',
          mode: 'declared',
        }),
      } as never,
      runtimeTargetContext: {
        id: 'staging-fixture',
        kind: 'http',
        environment: 'staging',
        baseUrl: 'https://staging.example',
      },
    },
  );

  assert.equal(result.verdict, 'not_authorized');
  assert.match(result.reasoning, /Shell-adjacent probes are disabled/);
  assert.equal(launched, 0, 'a blocked browser probe must not launch a browser');
  assert.equal(result.evidence.screenshots.length, 0);
});
