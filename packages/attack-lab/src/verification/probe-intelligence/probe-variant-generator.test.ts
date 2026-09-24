import test from 'node:test';
import assert from 'node:assert/strict';

import { classifyHypothesis, getFamilyDefinition } from './probe-families.js';
import { generateFamilyVariants, type VariantGenerationRequest } from './probe-variant-generator.js';

// ---------------------------------------------------------------------------
// classifyHypothesis
// ---------------------------------------------------------------------------

test('classifyHypothesis identifies header-trust hypotheses', () => {
  assert.equal(classifyHypothesis('The app trusts X-Forwarded-Host without validation'), 'header_trust');
  assert.equal(classifyHypothesis('Host header injection in redirect'), 'header_trust');
  assert.equal(classifyHypothesis('Header-sourced org-id is trusted'), 'header_trust');
  assert.equal(classifyHypothesis('Referer spoofing bypasses CSRF check'), 'header_trust');
});

test('classifyHypothesis identifies identity-differential hypotheses', () => {
  assert.equal(classifyHypothesis('IDOR on GET /api/v1/users/:userId'), 'identity_differential');
  assert.equal(classifyHypothesis('Cross-tenant data leak via company endpoint'), 'identity_differential');
  assert.equal(classifyHypothesis('Privilege escalation through role assignment'), 'identity_differential');
  assert.equal(classifyHypothesis('Broken access control on admin resource'), 'identity_differential');
});

test('classifyHypothesis identifies SSRF hypotheses', () => {
  assert.equal(classifyHypothesis('SSRF via webhook URL parameter'), 'ssrf');
  assert.equal(classifyHypothesis('Server-side request forgery in image proxy'), 'ssrf');
  assert.equal(classifyHypothesis('URL fetch endpoint allows internal service access'), 'ssrf');
});

test('classifyHypothesis identifies WebSocket hypotheses', () => {
  assert.equal(classifyHypothesis('WebSocket upgrade lacks origin validation'), 'websocket_origin');
  assert.equal(classifyHypothesis('ws:// endpoint allows cross-company connections'), 'websocket_origin');
});

test('classifyHypothesis identifies bootstrap-token-flow hypotheses', () => {
  assert.equal(classifyHypothesis('Invite token can be reused after claim'), 'bootstrap_token_flow');
  assert.equal(classifyHypothesis('Bootstrap token reuse in onboarding flow'), 'bootstrap_token_flow');
  assert.equal(classifyHypothesis('Magic link token does not expire'), 'bootstrap_token_flow');
});

test('classifyHypothesis identifies mutation-guard hypotheses', () => {
  assert.equal(classifyHypothesis('Mass assignment on user update endpoint'), 'mutation_guard');
  assert.equal(classifyHypothesis('State tampering via unvalidated update'), 'mutation_guard');
  assert.equal(classifyHypothesis('Parameter tampering injects admin role'), 'mutation_guard');
});

test('classifyHypothesis returns generic for unrecognized hypotheses', () => {
  assert.equal(classifyHypothesis('The server returns 500 on malformed input'), 'generic');
  assert.equal(classifyHypothesis('SQL injection via search parameter'), 'generic');
});

// ---------------------------------------------------------------------------
// getFamilyDefinition
// ---------------------------------------------------------------------------

test('getFamilyDefinition returns definition for known families', () => {
  const def = getFamilyDefinition('header_trust');
  assert.ok(def);
  assert.equal(def.id, 'header_trust');
  assert.ok(def.defaultVariants.length >= 3);
});

test('getFamilyDefinition returns undefined for generic', () => {
  assert.equal(getFamilyDefinition('generic'), undefined);
});

// ---------------------------------------------------------------------------
// generateFamilyVariants — header_trust
// ---------------------------------------------------------------------------

test('header-trust hypothesis generates forwarded/origin header variants', () => {
  const request: VariantGenerationRequest = {
    findingId: 'f-1',
    hypothesis: 'The app trusts X-Forwarded-Host without validation',
    basePath: '/api/v1/dashboard',
    baseMethod: 'GET',
    availableIdentities: ['guest', 'user_a'],
  };

  const result = generateFamilyVariants(request);

  assert.equal(result.family, 'header_trust');
  assert.ok(result.probes.length >= 3, `Expected at least 3 probes, got ${result.probes.length}`);

  // Every probe should have probeFamily and probeVariant set
  for (const probe of result.probes) {
    assert.equal(probe.probeFamily, 'header_trust');
    assert.ok(probe.probeVariant, 'probeVariant should be set');
  }

  // Check that specific header variants are present
  const variantKeys = result.probes.map((p) => p.probeVariant);
  assert.ok(variantKeys.includes('x_forwarded_host'), 'Should include X-Forwarded-Host variant');
  assert.ok(variantKeys.includes('origin_spoof'), 'Should include Origin spoof variant');

  // Verify headers are actually set on the probes
  const xfhProbe = result.probes.find((p) => p.probeVariant === 'x_forwarded_host');
  assert.ok(xfhProbe);
  assert.equal(xfhProbe.http?.headers?.['X-Forwarded-Host'], 'evil.example.com');
});

// ---------------------------------------------------------------------------
// generateFamilyVariants — identity_differential
// ---------------------------------------------------------------------------

test('identity-differential hypothesis generates cross-identity variants', () => {
  const request: VariantGenerationRequest = {
    findingId: 'f-2',
    hypothesis: 'IDOR on GET /api/v1/users/:userId allows cross-tenant access',
    basePath: '/api/v1/users/123',
    baseMethod: 'GET',
    availableIdentities: ['guest', 'user_a', 'user_b', 'admin_canary'],
  };

  const result = generateFamilyVariants(request);

  assert.equal(result.family, 'identity_differential');
  assert.ok(result.probes.length >= 3, `Expected at least 3 probes, got ${result.probes.length}`);

  // Should produce probes for different identity tiers
  const identities = new Set(result.probes.map((p) => p.identityId));
  assert.ok(identities.has('guest'), 'Should include guest identity');
  assert.ok(identities.has('user_b'), 'Should include user_b (cross-tenant)');
  assert.ok(identities.has('admin_canary'), 'Should include admin');

  // Family and variant metadata should be present
  for (const probe of result.probes) {
    assert.equal(probe.probeFamily, 'identity_differential');
    assert.ok(probe.probeVariant);
  }
});

test('identity-differential filters to available identities', () => {
  const request: VariantGenerationRequest = {
    findingId: 'f-3',
    hypothesis: 'IDOR vulnerability on project endpoint',
    basePath: '/api/v1/projects/42',
    baseMethod: 'GET',
    // Only guest and user_a_low available — no user_b or admin
    availableIdentities: ['guest', 'user_a_low'],
  };

  const result = generateFamilyVariants(request);
  assert.equal(result.family, 'identity_differential');
  // Should only produce probes for available identities
  for (const probe of result.probes) {
    assert.ok(
      ['guest', 'user_a_low'].includes(probe.identityId),
      `Unexpected identity ${probe.identityId}`,
    );
  }
});

// ---------------------------------------------------------------------------
// generateFamilyVariants — ssrf
// ---------------------------------------------------------------------------

test('SSRF hypothesis generates multiple destination class variants', () => {
  const request: VariantGenerationRequest = {
    findingId: 'f-4',
    hypothesis: 'SSRF via webhook URL in notification config',
    basePath: '/api/v1/webhooks',
    baseMethod: 'POST',
    availableIdentities: ['user_a'],
  };

  const result = generateFamilyVariants(request);

  assert.equal(result.family, 'ssrf');
  assert.ok(result.probes.length >= 3, `Expected at least 3 SSRF probes, got ${result.probes.length}`);

  const variantKeys = result.probes.map((p) => p.probeVariant);
  assert.ok(variantKeys.includes('loopback'), 'Should include loopback variant');
  assert.ok(variantKeys.includes('metadata_canary'), 'Should include metadata canary');
  assert.ok(variantKeys.includes('internal_canary'), 'Should include internal canary');

  // Verify SSRF destinations are in the probe bodies
  const loopback = result.probes.find((p) => p.probeVariant === 'loopback');
  assert.ok(loopback);
  assert.ok(loopback.http?.body?.includes('127.0.0.1'), 'Loopback probe should target 127.0.0.1');

  const metaProbe = result.probes.find((p) => p.probeVariant === 'metadata_canary');
  assert.ok(metaProbe);
  assert.ok(metaProbe.http?.body?.includes('169.254.169.254'), 'Metadata probe should target metadata IP');
});

// ---------------------------------------------------------------------------
// generateFamilyVariants — websocket_origin
// ---------------------------------------------------------------------------

test('WebSocket hypothesis generates upgrade/origin variants', () => {
  const request: VariantGenerationRequest = {
    findingId: 'f-5',
    hypothesis: 'WebSocket upgrade endpoint lacks origin validation',
    basePath: '/ws/events',
    baseMethod: 'GET',
    availableIdentities: ['user_a', 'user_b'],
  };

  const result = generateFamilyVariants(request);

  assert.equal(result.family, 'websocket_origin');
  assert.ok(result.probes.length >= 2, `Expected at least 2 WebSocket probes, got ${result.probes.length}`);

  // Verify upgrade headers are present
  for (const probe of result.probes) {
    assert.equal(probe.http?.headers?.['Upgrade'], 'websocket');
    assert.equal(probe.http?.headers?.['Connection'], 'Upgrade');
  }

  const variantKeys = result.probes.map((p) => p.probeVariant);
  assert.ok(variantKeys.includes('cookie_upgrade'), 'Should include cookie-backed upgrade');
  assert.ok(variantKeys.includes('origin_variant'), 'Should include cross-origin variant');

  // Cross-origin variant should have evil origin
  const crossOrigin = result.probes.find((p) => p.probeVariant === 'origin_variant');
  assert.ok(crossOrigin);
  assert.equal(crossOrigin.http?.headers?.['Origin'], 'https://evil.example.com');
});

// ---------------------------------------------------------------------------
// generateFamilyVariants — bootstrap_token_flow
// ---------------------------------------------------------------------------

test('bootstrap-token hypothesis generates token reuse variants', () => {
  const request: VariantGenerationRequest = {
    findingId: 'f-6',
    hypothesis: 'Invite token can be reused after initial claim',
    basePath: '/api/v1/invites/claim',
    baseMethod: 'POST',
    availableIdentities: ['guest'],
  };

  const result = generateFamilyVariants(request);

  assert.equal(result.family, 'bootstrap_token_flow');
  assert.ok(result.probes.length >= 2);

  const variantKeys = result.probes.map((p) => p.probeVariant);
  assert.ok(variantKeys.includes('expired_token'), 'Should include expired token variant');
  assert.ok(variantKeys.includes('tampered_token'), 'Should include tampered token variant');
});

// ---------------------------------------------------------------------------
// generateFamilyVariants — mutation_guard
// ---------------------------------------------------------------------------

test('mutation-guard hypothesis generates field injection variants', () => {
  const request: VariantGenerationRequest = {
    findingId: 'f-7',
    hypothesis: 'Mass assignment allows injecting admin role on user update',
    basePath: '/api/v1/users/me',
    baseMethod: 'PUT',
    availableIdentities: ['user_a'],
  };

  const result = generateFamilyVariants(request);

  assert.equal(result.family, 'mutation_guard');
  assert.ok(result.probes.length >= 2);

  const variantKeys = result.probes.map((p) => p.probeVariant);
  assert.ok(variantKeys.includes('inject_role'), 'Should include role injection variant');
  assert.ok(variantKeys.includes('inject_org'), 'Should include org injection variant');

  // Verify bodies contain injected fields
  const roleProbe = result.probes.find((p) => p.probeVariant === 'inject_role');
  assert.ok(roleProbe);
  assert.ok(roleProbe.http?.body?.includes('admin'), 'Role probe should inject admin');
});

// ---------------------------------------------------------------------------
// generateFamilyVariants — generic
// ---------------------------------------------------------------------------

test('generic hypothesis returns empty probes', () => {
  const request: VariantGenerationRequest = {
    findingId: 'f-8',
    hypothesis: 'The server crashes on large payloads',
    basePath: '/api/v1/data',
    baseMethod: 'POST',
    availableIdentities: ['user_a'],
  };

  const result = generateFamilyVariants(request);

  assert.equal(result.family, 'generic');
  assert.equal(result.probes.length, 0);
  assert.equal(result.variantKeysExercised.length, 0);
});

// ---------------------------------------------------------------------------
// Evidence: probes record family and variant identity
// ---------------------------------------------------------------------------

test('all family probes have probeFamily and probeVariant fields', () => {
  const families = [
    { hypothesis: 'X-Forwarded-Host trust issue', expected: 'header_trust' },
    { hypothesis: 'IDOR on user endpoint', expected: 'identity_differential' },
    { hypothesis: 'SSRF in webhook handler', expected: 'ssrf' },
    { hypothesis: 'WebSocket lacks origin check', expected: 'websocket_origin' },
    { hypothesis: 'Bootstrap token reuse', expected: 'bootstrap_token_flow' },
    { hypothesis: 'Mass assignment on update', expected: 'mutation_guard' },
  ] as const;

  for (const { hypothesis, expected } of families) {
    const result = generateFamilyVariants({
      findingId: 'f-evidence',
      hypothesis,
      basePath: '/api/v1/test',
      baseMethod: 'POST',
      availableIdentities: ['guest', 'user_a', 'user_b', 'admin_canary'],
    });

    assert.equal(result.family, expected, `Family for "${hypothesis}"`);
    assert.ok(result.probes.length > 0, `Should produce probes for ${expected}`);

    for (const probe of result.probes) {
      assert.equal(probe.probeFamily, expected, `probeFamily should be ${expected}`);
      assert.ok(typeof probe.probeVariant === 'string' && probe.probeVariant.length > 0,
        `probeVariant should be non-empty string for ${expected}`);
    }
  }
});

// ---------------------------------------------------------------------------
// Different families produce different probe shapes
// ---------------------------------------------------------------------------

test('different families produce structurally different probes', () => {
  const base = {
    findingId: 'f-diff',
    basePath: '/api/v1/resource',
    baseMethod: 'POST' as const,
    availableIdentities: ['guest', 'user_a', 'user_b', 'admin_canary'],
  };

  const headerResult = generateFamilyVariants({
    ...base,
    hypothesis: 'X-Forwarded-Host header trust vulnerability',
  });

  const idorResult = generateFamilyVariants({
    ...base,
    hypothesis: 'IDOR cross-tenant access on resource endpoint',
  });

  const ssrfResult = generateFamilyVariants({
    ...base,
    hypothesis: 'SSRF via URL parameter in resource',
  });

  // Header-trust probes should have injected headers
  const headerProbeHeaders = headerResult.probes.flatMap((p) => Object.keys(p.http?.headers ?? {}));
  assert.ok(
    headerProbeHeaders.some((h) => /forwarded|origin|referer|host/i.test(h)),
    'Header-trust probes should inject forwarded/origin/referer headers',
  );

  // Identity-differential probes should use different identities
  const idorIdentities = new Set(idorResult.probes.map((p) => p.identityId));
  assert.ok(idorIdentities.size >= 2, 'Identity-differential should test multiple identities');

  // SSRF probes should have destination URLs in body
  const ssrfBodies = ssrfResult.probes.map((p) => p.http?.body ?? '');
  assert.ok(
    ssrfBodies.some((b) => b.includes('127.0.0.1') || b.includes('169.254') || b.includes('internal.local')),
    'SSRF probes should contain canary destinations in body',
  );
});

// ---------------------------------------------------------------------------
// Target family capabilities — disabled variants
// ---------------------------------------------------------------------------

test('disabled variants are excluded from generation', () => {
  const request: VariantGenerationRequest = {
    findingId: 'f-cap',
    hypothesis: 'X-Forwarded-Host header trust issue',
    basePath: '/api/v1/test',
    baseMethod: 'GET',
    availableIdentities: ['user_a'],
    familyCapabilities: [
      {
        family: 'header_trust',
        disabledVariants: ['host_override', 'referer_spoof'],
      },
    ],
  };

  const result = generateFamilyVariants(request);
  const variantKeys = result.probes.map((p) => p.probeVariant);

  assert.ok(!variantKeys.includes('host_override'), 'host_override should be disabled');
  assert.ok(!variantKeys.includes('referer_spoof'), 'referer_spoof should be disabled');
  assert.ok(variantKeys.includes('x_forwarded_host'), 'x_forwarded_host should still be present');
});

// ---------------------------------------------------------------------------
// Target family capabilities — extra headers
// ---------------------------------------------------------------------------

test('extra headers from capability are merged into probes', () => {
  const request: VariantGenerationRequest = {
    findingId: 'f-extra',
    hypothesis: 'X-Forwarded-Host header trust',
    basePath: '/api/v1/test',
    baseMethod: 'GET',
    availableIdentities: ['user_a'],
    familyCapabilities: [
      {
        family: 'header_trust',
        extraHeaders: { 'X-Custom-Tenant': 'tenant-123' },
      },
    ],
  };

  const result = generateFamilyVariants(request);
  for (const probe of result.probes) {
    assert.equal(
      probe.http?.headers?.['X-Custom-Tenant'],
      'tenant-123',
      'Extra header should be merged into all probes',
    );
  }
});

// ---------------------------------------------------------------------------
// maxVariants limit
// ---------------------------------------------------------------------------

test('maxVariants limits the number of generated probes', () => {
  const request: VariantGenerationRequest = {
    findingId: 'f-limit',
    hypothesis: 'X-Forwarded-Host header trust vulnerability',
    basePath: '/api/v1/test',
    baseMethod: 'GET',
    availableIdentities: ['user_a'],
    maxVariants: 2,
  };

  const result = generateFamilyVariants(request);
  assert.ok(result.probes.length <= 2, `Expected at most 2 probes, got ${result.probes.length}`);
});
