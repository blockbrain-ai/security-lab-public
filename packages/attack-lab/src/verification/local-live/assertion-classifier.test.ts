import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { classifyResponse, type ClassifierInput } from './assertion-classifier.js';
import type { LiveProbeRequest } from './contracts.js';

function makeProbe(overrides: Partial<LiveProbeRequest> = {}): LiveProbeRequest {
  return {
    findingId: 'f-1',
    hypothesis: 'test hypothesis',
    probeKind: 'http',
    identityId: 'user-a',
    http: { method: 'GET', path: '/api/v1/records', headers: {} },
    ...overrides,
  };
}

function makeInput(overrides: Partial<ClassifierInput> = {}): ClassifierInput {
  return {
    probe: makeProbe(),
    status: 200,
    headers: { 'content-type': 'application/json' },
    body: '{"records":[{"id":"1","name":"secret"}]}',
    path: '/api/v1/records',
    canaryMatched: 'exploitable',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// SPA shell suppression
// ---------------------------------------------------------------------------

describe('assertion-classifier SPA shell suppression', () => {
  it('does not confirm an API exploit from SPA HTML', () => {
    const spaBody = `<!DOCTYPE html>
<html><head><title>App</title></head>
<body><div id="root"></div>
<script type="module" src="/assets/main.abc123.js"></script>
</body></html>`;

    const result = classifyResponse(makeInput({
      status: 200,
      headers: { 'content-type': 'text/html' },
      body: spaBody,
      canaryMatched: 'exploitable',
    }));

    assert.equal(result.verdict, 'inconclusive');
    assert.equal(result.reason, 'spa_fallback');
    assert.equal(result.routeKind, 'spa_shell');
    assert.equal(result.isMeaningfulAttempt, false);
  });
});

// ---------------------------------------------------------------------------
// Empty collection suppression
// ---------------------------------------------------------------------------

describe('assertion-classifier empty collection suppression', () => {
  it('does not confirm exfiltration from empty array', () => {
    const result = classifyResponse(makeInput({
      body: '[]',
      canaryMatched: 'exploitable',
    }));

    assert.equal(result.verdict, 'inconclusive');
    assert.equal(result.reason, 'empty_authorized_state');
    assert.equal(result.isMeaningfulAttempt, false);
  });

  it('does not confirm exfiltration from empty object', () => {
    const result = classifyResponse(makeInput({
      body: '{}',
      canaryMatched: 'exploitable',
    }));

    assert.equal(result.verdict, 'inconclusive');
    assert.equal(result.reason, 'empty_authorized_state');
    assert.equal(result.isMeaningfulAttempt, false);
  });

  it('does not confirm exfiltration from {"data":[]}', () => {
    const result = classifyResponse(makeInput({
      body: '{"data":[]}',
      canaryMatched: 'exploitable',
    }));

    assert.equal(result.verdict, 'inconclusive');
    assert.equal(result.reason, 'empty_authorized_state');
  });

  it('does not confirm exfiltration from {"results":[],"items":[]}', () => {
    const result = classifyResponse(makeInput({
      body: '{"results":[],"items":[]}',
      canaryMatched: 'exploitable',
    }));

    assert.equal(result.verdict, 'inconclusive');
    assert.equal(result.reason, 'empty_authorized_state');
  });
});

// ---------------------------------------------------------------------------
// Explicit refutation
// ---------------------------------------------------------------------------

describe('assertion-classifier explicit refutation', () => {
  it('refutes on 403 with guard message', () => {
    const result = classifyResponse(makeInput({
      status: 403,
      body: '{"error":"Forbidden","message":"Access denied"}',
      canaryMatched: 'safe',
    }));

    assert.equal(result.verdict, 'refuted');
    assert.equal(result.reason, 'explicit_refutation');
    assert.equal(result.isMeaningfulAttempt, true);
  });

  it('refutes on 401 with authentication required', () => {
    const result = classifyResponse(makeInput({
      status: 401,
      body: '{"error":"Authentication required"}',
      canaryMatched: undefined,
    }));

    assert.equal(result.verdict, 'refuted');
    assert.equal(result.reason, 'explicit_refutation');
  });

  it('refutes on 401 even without guard message', () => {
    const result = classifyResponse(makeInput({
      status: 401,
      body: '',
      canaryMatched: undefined,
    }));

    assert.equal(result.verdict, 'refuted');
    assert.equal(result.reason, 'explicit_refutation');
  });
});

// ---------------------------------------------------------------------------
// Redirect suppression
// ---------------------------------------------------------------------------

describe('assertion-classifier redirect suppression', () => {
  it('does not confirm from a 302 redirect', () => {
    const result = classifyResponse(makeInput({
      status: 302,
      headers: { location: '/login' },
      body: '',
      canaryMatched: undefined,
    }));

    assert.equal(result.verdict, 'inconclusive');
    assert.equal(result.reason, 'redirect_not_confirmation');
    assert.equal(result.routeKind, 'redirect_bootstrap');
    assert.equal(result.isMeaningfulAttempt, false);
  });
});

// ---------------------------------------------------------------------------
// Static asset suppression
// ---------------------------------------------------------------------------

describe('assertion-classifier static asset suppression', () => {
  it('does not confirm from a CSS file', () => {
    const result = classifyResponse(makeInput({
      path: '/assets/style.css',
      status: 200,
      headers: { 'content-type': 'text/css' },
      body: 'body { color: red; }',
      canaryMatched: 'exploitable',
    }));

    assert.equal(result.verdict, 'inconclusive');
    assert.equal(result.reason, 'static_asset_not_confirmation');
    assert.equal(result.isMeaningfulAttempt, false);
  });
});

// ---------------------------------------------------------------------------
// WebSocket upgrade suppression
// ---------------------------------------------------------------------------

describe('assertion-classifier websocket suppression', () => {
  it('does not confirm from a websocket upgrade', () => {
    const result = classifyResponse(makeInput({
      status: 101,
      headers: { upgrade: 'websocket' },
      body: '',
      path: '/ws',
      canaryMatched: undefined,
    }));

    assert.equal(result.verdict, 'inconclusive');
    assert.equal(result.reason, 'websocket_upgrade_not_confirmation');
    assert.equal(result.isMeaningfulAttempt, false);
  });
});

// ---------------------------------------------------------------------------
// Identity differential
// ---------------------------------------------------------------------------

describe('assertion-classifier identity differential', () => {
  it('detects privilege escalation via identity differential', () => {
    const result = classifyResponse(makeInput({
      status: 200,
      body: '{"secrets":["key1","key2"]}',
      canaryMatched: undefined,
      identityDifferential: {
        baselineIdentityId: 'anonymous',
        baselineBody: '{"error":"Forbidden"}',
        baselineStatus: 403,
      },
    }));

    assert.equal(result.verdict, 'confirmed');
    assert.equal(result.reason, 'identity_differential_match');
    assert.equal(result.isMeaningfulAttempt, true);
  });

  it('detects no-change across identities', () => {
    const body = '{"public":"data"}';
    const result = classifyResponse(makeInput({
      status: 200,
      body,
      canaryMatched: undefined,
      identityDifferential: {
        baselineIdentityId: 'anonymous',
        baselineBody: body,
        baselineStatus: 200,
      },
    }));

    assert.equal(result.verdict, 'inconclusive');
    assert.equal(result.reason, 'identity_differential_no_change');
    assert.equal(result.isMeaningfulAttempt, true);
  });
});

// ---------------------------------------------------------------------------
// Canary-based classification with shape awareness
// ---------------------------------------------------------------------------

describe('assertion-classifier canary with shape awareness', () => {
  it('confirms when canary matches exploitable with substantive content', () => {
    const result = classifyResponse(makeInput({
      body: '{"records":[{"id":"1","name":"secret"}]}',
      canaryMatched: 'exploitable',
    }));

    assert.equal(result.verdict, 'confirmed');
    assert.equal(result.reason, 'response_shape_match');
    assert.equal(result.isMeaningfulAttempt, true);
  });

  it('downgrades canary exploitable match when JSON body is empty', () => {
    const result = classifyResponse(makeInput({
      body: '[]',
      canaryMatched: 'exploitable',
    }));

    // Empty collection suppression fires before canary
    assert.equal(result.verdict, 'inconclusive');
    assert.equal(result.reason, 'empty_authorized_state');
  });

  it('classifies safe canary match as refuted', () => {
    const result = classifyResponse(makeInput({
      status: 404,
      body: '{"error":"Not found"}',
      canaryMatched: 'safe',
    }));

    assert.equal(result.verdict, 'refuted');
    assert.equal(result.reason, 'canary_match');
    assert.equal(result.isMeaningfulAttempt, true);
  });

  it('classifies no canary match as inconclusive', () => {
    const result = classifyResponse(makeInput({
      status: 500,
      body: '{"error":"Internal server error"}',
      canaryMatched: 'neither',
    }));

    assert.equal(result.verdict, 'inconclusive');
    assert.equal(result.reason, 'response_shape_mismatch');
  });

  it('downgrades canary exploitable match when JSON body has only empty arrays', () => {
    const result = classifyResponse(makeInput({
      body: '{"items":[],"users":[]}',
      canaryMatched: 'exploitable',
    }));

    assert.equal(result.verdict, 'inconclusive');
    assert.equal(result.reason, 'empty_authorized_state');
  });
});

// ---------------------------------------------------------------------------
// HTML page (non-SPA) handling
// ---------------------------------------------------------------------------

describe('assertion-classifier HTML page handling', () => {
  it('does not auto-confirm HTML page even with canary match', () => {
    const htmlBody = `<!DOCTYPE html><html><body>
<h1>Admin Panel</h1><p>Welcome, you have access to all resources in the system and can manage them as needed.</p>
</body></html>`;

    const result = classifyResponse(makeInput({
      status: 200,
      headers: { 'content-type': 'text/html' },
      body: htmlBody,
      canaryMatched: 'exploitable',
    }));

    // HTML page with canary match — the classifier defers to canary
    // since the page is content-rich (not SPA shell)
    assert.equal(result.verdict, 'confirmed');
    assert.equal(result.reason, 'response_shape_match');
  });
});
