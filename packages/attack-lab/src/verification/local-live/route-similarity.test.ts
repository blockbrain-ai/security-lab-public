import test from 'node:test';
import assert from 'node:assert/strict';
import type { RouteSurface } from '../../intelligence/contracts.js';
import { rankRoutesByRelevance } from './route-similarity.js';

function makeRoutes(): RouteSurface[] {
  return [
    { method: 'POST', path: '/api/v1/actions/execute', file: 'src/api/routes/actions.ts', hasAuth: true, authObservation: 'handler_local', authEvidence: [], hasValidation: true, provenance: 'static' as never },
    { method: 'POST', path: '/api/v1/approvals/:id/approve', file: 'src/api/routes/approvals.ts', hasAuth: true, authObservation: 'handler_local', authEvidence: [], hasValidation: true, provenance: 'static' as never },
    { method: 'GET', path: '/api/v1/decisions/:id', file: 'src/api/routes/decisions.ts', hasAuth: true, authObservation: 'handler_local', authEvidence: [], hasValidation: false, provenance: 'static' as never },
    { method: 'GET', path: '/buyer-room', file: 'src/api/routes/buyer-room.ts', hasAuth: false, authObservation: 'not_observed', authEvidence: [], hasValidation: false, provenance: 'static' as never },
    { method: 'GET', path: '/api/v1/health', file: 'src/api/routes/health.ts', hasAuth: false, authObservation: 'not_observed', authEvidence: [], hasValidation: false, provenance: 'static' as never },
    { method: 'GET', path: '/api/v1/admin/agents', file: 'src/api/routes/admin.ts', hasAuth: true, authObservation: 'handler_local', authEvidence: [], hasValidation: false, provenance: 'static' as never },
  ];
}

test('rankRoutesByRelevance ranks execute route highest for action-related hypothesis', () => {
  const ranked = rankRoutesByRelevance(
    'An attacker could execute actions without authentication via the action runtime.',
    makeRoutes(),
    3,
  );

  assert.ok(ranked.length > 0);
  assert.equal(ranked[0]!.path, '/api/v1/actions/execute');
});

test('rankRoutesByRelevance ranks approval route highest for approval-related hypothesis', () => {
  const ranked = rankRoutesByRelevance(
    'Cross-tenant access to approvals — user from Org A can approve requests owned by Org B.',
    makeRoutes(),
    3,
  );

  assert.ok(ranked.length > 0);
  assert.ok(ranked[0]!.path.includes('/approvals/'));
});

test('rankRoutesByRelevance ranks decision route for IDOR hypothesis', () => {
  const ranked = rankRoutesByRelevance(
    'IDOR on decisions endpoint allows cross-tenant data access to decisions.',
    makeRoutes(),
    3,
  );

  assert.ok(ranked.length > 0);
  assert.ok(ranked[0]!.path.includes('/decisions/'));
});

test('rankRoutesByRelevance returns empty array for empty routes', () => {
  const ranked = rankRoutesByRelevance('some hypothesis', [], 5);
  assert.equal(ranked.length, 0);
});

test('rankRoutesByRelevance boosts routes without auth for auth-bypass hypothesis', () => {
  const ranked = rankRoutesByRelevance(
    'Anonymous guest access to unprotected buyer-room route without authentication.',
    makeRoutes(),
    3,
  );

  assert.ok(ranked.length > 0);
  // buyer-room has no auth and matches keywords, should be ranked high
  assert.ok(ranked.some((r) => r.path === '/buyer-room'));
});

test('rankRoutesByRelevance respects topN limit', () => {
  const ranked = rankRoutesByRelevance(
    'Check all routes for authentication issues.',
    makeRoutes(),
    2,
  );

  assert.ok(ranked.length <= 2);
});
