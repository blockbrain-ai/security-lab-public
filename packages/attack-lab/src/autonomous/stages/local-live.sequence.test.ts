/**
 * Section 11.4 — Integration test for multi-step probe sequences
 * and identity differentials within the local-live lane.
 *
 * Verifies:
 * - Step 1 captures a stateful value and step 2 consumes it.
 * - Cross-identity sequence produces a meaningful differential.
 * - Reversible write sequences remain bounded and auditable.
 * - Report rendering distinguishes sequence vs single-step outcomes.
 */

import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { executeProbeSequence } from '../../verification/local-live/probe-sequence.js';
import { executeIdentityDifferentialProbe, executeIdentityDifferentialSequence } from '../../verification/local-live/identity-differential.js';
import { executeLiveProbe } from '../../verification/local-live/live-replay.js';
import { renderInvestigationReport } from '../../../../evidence-plane/src/investigation-report.js';
import type { InvestigationReportData } from '../../../../evidence-plane/src/investigation-report.js';
import type { ProbeSequenceDefinition, LiveProbeRequest } from '../../verification/local-live/contracts.js';
import { IdentityLadder } from '../../verification/local-live/identity-ladder.js';
import { RateLimiter } from '../../verification/local-live/rate-limiter.js';
import { MutationJournal } from '../../verification/local-live/reversible-mutation.js';

function buildOptions(fetchFn: typeof fetch) {
  return {
    baseUrl: 'http://localhost:4000',
    identityLadder: new IdentityLadder([
      { id: 'guest', kind: 'anonymous' as const },
      { id: 'user-a', kind: 'anonymous' as const },
      { id: 'admin', kind: 'anonymous' as const },
    ]),
    rateLimiter: new RateLimiter({
      requestsPerSecond: 100,
      maxRequestsPerCampaign: 500,
      autoStopOn5xxStreak: 5,
      autoStopOnLatencyDoubling: false,
    }),
    mutationJournal: new MutationJournal(),
    fetchFn,
    allowMutations: true,
  };
}

// ---------------------------------------------------------------------------
// Integration: stateful value captured in step 1 and consumed in step 2
// ---------------------------------------------------------------------------

describe('Section 11.4 integration: multi-step sequence with state passthrough', () => {
  it('step 1 obtains a CSRF token and step 2 uses it for a mutation', async () => {
    const requestLog: Array<{ url: string; headers: Record<string, string>; body?: string }> = [];
    const fetchFn: typeof fetch = async (input, init) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
      const headers = (init?.headers ?? {}) as Record<string, string>;
      requestLog.push({ url, headers, body: init?.body as string | undefined });

      if (url.includes('/csrf-token')) {
        return new Response(
          JSON.stringify({ csrf: 'tok-xyz-999' }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      if (url.includes('/api/transfer') && url.includes('tok-xyz-999')) {
        return new Response(
          JSON.stringify({ status: 'transferred', amount: 1000 }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response('bad request', { status: 400 });
    };

    const definition: ProbeSequenceDefinition = {
      sequenceId: 'seq-csrf-bypass',
      findingId: 'f-csrf-1',
      hypothesis: 'CSRF token obtained anonymously can authorize a privileged transfer',
      defaultIdentityId: 'guest',
      steps: [
        {
          stepId: 'get_csrf',
          label: 'Obtain CSRF token',
          http: { method: 'GET', path: '/csrf-token' },
          extractOutputs: {
            csrf: { kind: 'jsonPath', path: 'csrf' },
          },
        },
        {
          stepId: 'execute_transfer',
          label: 'Execute transfer with stolen CSRF',
          http: {
            method: 'POST',
            path: '/api/transfer?csrf={{get_csrf.csrf}}',
            body: '{"amount":1000,"to":"attacker"}',
          },
          expectedWhenSafe: { statusIn: [401, 403] },
          expectedWhenExploitable: { status: 200 },
        },
      ],
      rollback: [
        { method: 'POST', path: '/api/transfer/rollback' },
      ],
    };

    const { result, stats } = await executeProbeSequence(definition, buildOptions(fetchFn));

    // Step 1 extracted the CSRF token
    assert.equal(result.stepResults[0].extractedOutputs['csrf'], 'tok-xyz-999');

    // Step 2 consumed the CSRF token (state passthrough counted)
    assert.ok(stats.statePassthroughCount >= 1, `Expected >=1 state passthrough, got ${stats.statePassthroughCount}`);

    // Step 2's request URL should contain the resolved token
    assert.ok(
      requestLog[1].url.includes('tok-xyz-999'),
      'Step 2 URL should contain the CSRF token from step 1',
    );

    // Sequence verdict is confirmed (step 2 got 200 with substantive data)
    assert.equal(result.verdict, 'confirmed');

    // Rollback was executed
    assert.equal(result.rollbackExecuted, true);
    assert.ok(stats.rollbackExecuted);
    assert.ok(requestLog.some((r) => r.url.includes('/api/transfer/rollback')));

    // Evidence: all steps have results
    assert.equal(result.stepResults.length, 2);
    assert.equal(result.stepResults[0].stepId, 'get_csrf');
    assert.equal(result.stepResults[1].stepId, 'execute_transfer');
  });
});

// ---------------------------------------------------------------------------
// Integration: cross-identity differential
// ---------------------------------------------------------------------------

describe('Section 11.4 integration: identity differential', () => {
  it('single-probe differential detects privilege escalation', async () => {
    let callIndex = 0;
    const fetchFn: typeof fetch = async () => {
      callIndex += 1;
      // guest (call 1) → gets data, admin (call 2) → denied
      if (callIndex === 1) {
        return new Response(
          JSON.stringify({ records: [{ id: 'r1', secret: 'leaked' }] }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response('forbidden', { status: 403 });
    };

    const probe: LiveProbeRequest = {
      findingId: 'f-idor-diff',
      hypothesis: 'Guest can read admin-only records',
      probeKind: 'http',
      identityId: 'guest',
      http: { method: 'GET', path: '/api/admin/records' },
      expectedWhenSafe: { statusIn: [401, 403] },
      expectedWhenExploitable: { status: 200 },
    };

    const result = await executeIdentityDifferentialProbe(
      probe,
      { identityIds: ['guest', 'admin'] },
      buildOptions(fetchFn),
    );

    assert.equal(result.entries.length, 2);
    assert.equal(result.deltas.length, 1);
    assert.equal(result.deltas[0].privilegeEscalationDetected, true);
    assert.equal(result.verdict, 'confirmed');
  });

  it('sequence differential across identities detects access control gap', async () => {
    let callIndex = 0;
    const fetchFn: typeof fetch = async (input) => {
      callIndex += 1;
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;

      // Both identities get a session token
      if (url.includes('/auth/session')) {
        return new Response(
          JSON.stringify({ session: `sess-${callIndex}` }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }

      // Guest (calls 1-2): denied on protected resource
      // Admin (calls 3-4): allowed on protected resource
      if (callIndex <= 2) {
        return new Response('forbidden', { status: 403 });
      }
      return new Response(
        JSON.stringify({ data: [{ secret: 'admin-only' }] }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    };

    const definition: ProbeSequenceDefinition = {
      sequenceId: 'seq-session-diff',
      findingId: 'f-session-diff',
      hypothesis: 'Session token grants different access levels',
      defaultIdentityId: 'guest',
      steps: [
        {
          stepId: 'auth',
          label: 'Obtain session',
          http: { method: 'POST', path: '/auth/session' },
          extractOutputs: {
            session: { kind: 'jsonPath', path: 'session' },
          },
        },
        {
          stepId: 'access',
          label: 'Access protected resource',
          http: { method: 'GET', path: '/api/protected?session={{auth.session}}' },
          expectedWhenSafe: { statusIn: [401, 403] },
          expectedWhenExploitable: { status: 200 },
        },
      ],
    };

    const { result } = await executeIdentityDifferentialSequence(
      definition,
      { identityIds: ['guest', 'admin'] },
      buildOptions(fetchFn),
    );

    assert.equal(result.entries.length, 2);
    assert.ok(result.entries[0].sequenceResult, 'Guest entry should have sequence result');
    assert.ok(result.entries[1].sequenceResult, 'Admin entry should have sequence result');
    assert.equal(result.deltas.length, 1);
    assert.equal(result.deltas[0].privilegeEscalationDetected, true);
    assert.equal(result.verdict, 'confirmed');
  });
});

// ---------------------------------------------------------------------------
// Integration: report rendering distinguishes sequence outcomes
// ---------------------------------------------------------------------------

describe('Section 11.4 integration: report rendering', () => {
  it('renders sequence execution summary in the report', () => {
    const reportData: InvestigationReportData = {
      campaignId: 'test-campaign',
      targetId: 'test-target',
      targetLabel: 'Test Target',
      targetKind: 'web-api',
      environment: 'local',
      mode: 'smoke',
      startedAt: '2026-04-12T00:00:00Z',
      completedAt: '2026-04-12T00:01:00Z',
      iterations: 1,
      totalCostUsd: 0,
      signalsFound: 0,
      signalsDormant: 0,
      signalsReactivated: 0,
      hypothesesTested: 3,
      chainHypothesesTested: 0,
      directHypothesesTested: 3,
      hypothesesConfirmed: 1,
      hypothesesRefuted: 1,
      maxChainLength: 0,
      chainLengthDistribution: {},
      findings: [],
      topSignals: [],
      refutedHypotheses: [],
      telemetrySummary: '',
      sequenceExecution: {
        sequencesExecuted: 2,
        totalStepsExecuted: 6,
        sequencesConfirmed: 1,
        sequencesRefuted: 1,
        sequencesInconclusive: 0,
        differentialsExecuted: 1,
        differentialsWithEscalation: 1,
        statePassthroughCount: 4,
        rollbacksExecuted: 1,
      },
    };

    const report = renderInvestigationReport(reportData);

    // The report should contain the sequence execution section
    assert.ok(report.includes('Sequence & Identity-Differential Execution'), 'Report should have sequence section');
    assert.ok(report.includes('Multi-step sequences: 2'), 'Report should show sequence count');
    assert.ok(report.includes('6 total steps'), 'Report should show step count');
    assert.ok(report.includes('State passthrough'), 'Report should show state passthrough');
    assert.ok(report.includes('Identity differentials: 1'), 'Report should show differential count');
    assert.ok(report.includes('Privilege escalation detected: 1'), 'Report should show escalation count');
  });

  it('omits sequence section when no sequences or differentials executed', () => {
    const reportData: InvestigationReportData = {
      campaignId: 'test-campaign',
      targetId: 'test-target',
      targetLabel: 'Test Target',
      targetKind: 'web-api',
      environment: 'local',
      mode: 'smoke',
      startedAt: '2026-04-12T00:00:00Z',
      completedAt: '2026-04-12T00:01:00Z',
      iterations: 1,
      totalCostUsd: 0,
      signalsFound: 0,
      signalsDormant: 0,
      signalsReactivated: 0,
      hypothesesTested: 0,
      chainHypothesesTested: 0,
      directHypothesesTested: 0,
      hypothesesConfirmed: 0,
      hypothesesRefuted: 0,
      maxChainLength: 0,
      chainLengthDistribution: {},
      findings: [],
      topSignals: [],
      refutedHypotheses: [],
      telemetrySummary: '',
    };

    const report = renderInvestigationReport(reportData);
    assert.ok(!report.includes('Sequence & Identity-Differential'), 'Report should not have sequence section');
  });
});

// ---------------------------------------------------------------------------
// Integration: existing single-step probes still work unchanged
// ---------------------------------------------------------------------------

describe('Section 11.4 integration: backward compatibility', () => {
  it('single-step probes continue to work without sequence overhead', async () => {
    const fetchFn: typeof fetch = async () => {
      return new Response(
        JSON.stringify({ data: 'ok' }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    };

    const result = await executeLiveProbe(
      {
        findingId: 'f-compat',
        hypothesis: 'Single-step probe still works',
        probeKind: 'http',
        identityId: 'guest',
        http: { method: 'GET', path: '/api/health' },
        expectedWhenExploitable: { status: 200 },
      },
      buildOptions(fetchFn),
    );

    // No sequence-related fields on single-probe results
    assert.ok(result.probeId);
    assert.ok(result.response.status === 200);
    assert.ok(result.classification);
  });
});
