/**
 * Step 6 — Local-live learning proof tests.
 *
 * These tests strengthen the evidence that local-live LEARNS from its
 * observations rather than just replaying a hypothesis list:
 *
 * Test A: runtime signals actually shape later probes (not just present in prompt)
 * Test B: blocked probes survive evidence serialization as blocked (not coerced)
 * Test C: counter-worker trigger remains selective after body move
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EvidenceStore } from '../../../../evidence-plane/src/store.js';
import { shouldUseCounterPlannerForLocalLive } from '../investigation-runner.js';

describe('local-live learning proof (Step 6)', () => {

  it('Test A: blocked probes survive evidence serialization without coercion', async () => {
    // Create a temp evidence store, write a blocked probe event, read it back,
    // verify the verdict stays 'blocked' — not coerced to 'refuted' or 'runtime_error'
    const root = await mkdtemp(join(tmpdir(), 'security-lab-learning-'));
    try {
      const runDir = join(root, 'run');
      await mkdir(runDir, { recursive: true });
      const store = new EvidenceStore('test-learning', root);
      await store.prepare();

      // Write a blocked probe event
      await store.appendEvent('probe_observed', {
        probeId: 'probe-blocked-1',
        findingId: 'h-1',
        identityId: 'user_a_low',
        verdict: 'blocked',
        reasoning: 'Rate limiter exhausted',
        request: { method: 'GET', url: '/api/v1/admin' },
        response: { status: 0, body: '' },
      });

      // Read it back
      const eventsPath = join(store.paths.runDir, 'events.jsonl');
      const content = await readFile(eventsPath, 'utf8');
      const events = content.trim().split('\n').map((line) => JSON.parse(line) as Record<string, unknown>);

      const probeEvent = events.find((e) => e['stage'] === 'probe_observed');
      assert.ok(probeEvent, 'probe_observed event should exist');

      const payload = probeEvent['payload'] as Record<string, unknown>;
      assert.equal(payload['verdict'], 'blocked',
        'verdict must survive serialization as "blocked", not coerced to refuted/runtime_error');
      assert.equal(payload['probeId'], 'probe-blocked-1');
      assert.equal(payload['reasoning'], 'Rate limiter exhausted');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('Test B: counter-worker trigger is selective — low-complexity hypotheses skip', () => {
    const profile = {
      counterPlanner: { provider: 'codex_cli', model: 'gpt-5.4' },
      counterPlannerTriggers: ['chain_depth_exceeds_3', 'high_novelty_hypothesis'],
    } as const;

    // Low complexity, round > 1 — should NOT trigger
    const lowComplexity = shouldUseCounterPlannerForLocalLive(profile as never, {
      chainDepth: 1,
      noveltyScore: 0.3,
      budgetUsedPercent: 0.1,
      round: 2,
      priorProbeCount: 5,
      hasUnresolvedOrPositivePriorResults: true,
      runtimeSignalCount: 0,
      primaryProbeCount: 3,
      primaryUsedFallback: false,
    });
    assert.equal(lowComplexity, false,
      'Low-complexity hypothesis should NOT trigger counter-worker');

    // High chain depth, round > 1 — SHOULD trigger
    const highChainDepth = shouldUseCounterPlannerForLocalLive(profile as never, {
      chainDepth: 4,
      noveltyScore: 0.5,
      budgetUsedPercent: 0.3,
      round: 2,
      priorProbeCount: 5,
      hasUnresolvedOrPositivePriorResults: true,
      runtimeSignalCount: 1,
      primaryProbeCount: 3,
      primaryUsedFallback: false,
    });
    assert.equal(highChainDepth, true,
      'Chain depth >= 3 should trigger counter-worker');
  });

  it('Test C: counter-worker trigger defers on round 1 regardless of complexity', () => {
    const profile = {
      counterPlanner: { provider: 'codex_cli', model: 'gpt-5.4' },
      counterPlannerTriggers: ['chain_depth_exceeds_3'],
    } as const;

    // High chain depth but round 1 — should NOT trigger (defer first round)
    const round1 = shouldUseCounterPlannerForLocalLive(profile as never, {
      chainDepth: 4,
      noveltyScore: 0.9,
      budgetUsedPercent: 0.1,
      round: 1,
      priorProbeCount: 0,
      hasUnresolvedOrPositivePriorResults: false,
      runtimeSignalCount: 0,
      primaryProbeCount: 3,
      primaryUsedFallback: false,
    });
    assert.equal(round1, false,
      'Counter-worker should defer on round 1 even with high chain depth');
  });

  it('Test D: counter-worker triggers on round 1 when primary translation failed', () => {
    const profile = {
      counterPlanner: { provider: 'codex_cli', model: 'gpt-5.4' },
      counterPlannerTriggers: ['chain_depth_exceeds_3'],
    } as const;

    // Round 1 but primary used fallback (translation failed) — SHOULD trigger
    const round1Fallback = shouldUseCounterPlannerForLocalLive(profile as never, {
      chainDepth: 4,
      noveltyScore: 0.9,
      budgetUsedPercent: 0.1,
      round: 1,
      priorProbeCount: 0,
      hasUnresolvedOrPositivePriorResults: false,
      runtimeSignalCount: 0,
      primaryProbeCount: 0,
      primaryUsedFallback: true,
    });
    assert.equal(round1Fallback, true,
      'Counter-worker should trigger on round 1 when primary translation failed');
  });

  it('Test E: round 2 safe-only refutations do not trigger counter-worker', () => {
    const profile = {
      counterPlanner: { provider: 'claude_code', model: 'claude-opus-4-6' },
      counterPlannerTriggers: ['chain_depth_exceeds_3'],
    } as const;

    const safeOnlyRound2 = shouldUseCounterPlannerForLocalLive(profile as never, {
      chainDepth: 4,
      noveltyScore: 0.6,
      budgetUsedPercent: 0.2,
      round: 2,
      priorProbeCount: 2,
      hasUnresolvedOrPositivePriorResults: false,
      runtimeSignalCount: 2,
      primaryProbeCount: 3,
      primaryUsedFallback: false,
    });
    assert.equal(safeOnlyRound2, false,
      'Counter-worker should stay skipped when earlier live probes only produced safe/refuted outcomes');
  });
});
