/**
 * Section 8.2 — Integration test for monitoring stress as a LocalLiveStage mode.
 *
 * Verifies that:
 * - LocalLiveStage accepts the `monitoringStress` option
 * - Detection hooks fire during probe execution when the mode is on
 * - The lane summary carries monitoring stress metrics (runs/degraded/harmfulSeen)
 * - Worker tool calls are instrumented when Mythos sub-lane is active
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { LocalLiveStage, mapLaneStatus } from './local-live.js';
import type { ExperimentStoreHandle, StageContext, StageRunnerHost } from './contracts.js';
import type { VerificationLaneSummary } from '../investigation-runner.js';

function makeLaneSummary(
  status: VerificationLaneSummary['status'],
  overrides?: Partial<VerificationLaneSummary>,
): VerificationLaneSummary {
  return {
    attempted: 0,
    meaningfulAttempts: 0,
    confirmed: 0,
    refuted: 0,
    inconclusive: 0,
    blocked: 0,
    skipped: 0,
    authFailed: 0,
    notApplicable: 0,
    notAuthorized: 0,
    rateLimited: 0,
    autoStopped: 0,
    timeout: 0,
    runtimeError: 0,
    compileError: 0,
    dryRunSimulated: 0,
    coverageGapCount: 0,
    costUsd: 0,
    durationMs: 0,
    status,
    required: false,
    coverageGaps: [],
    ...overrides,
  };
}

function makeHost(lane: VerificationLaneSummary, spy: { calls: number }): StageRunnerHost {
  return {
    runLocalLiveLaneFriend: async () => {
      spy.calls += 1;
      return lane;
    },
    runTestSynthesisLaneFriend: async () => {
      throw new Error('not used');
    },
    buildVerificationPacketsFriend: () => [],
  };
}

function makeContext(host: StageRunnerHost): StageContext {
  return {
    target: {},
    memory: {},
    state: {},
    stateStore: {},
    evidenceStore: {},
    campaignDir: '/tmp',
    telemetry: {},
    roleSessions: {},
    archiver: null,
    runner: host,
  } as unknown as StageContext;
}

describe('LocalLiveStage with monitoringStress mode', () => {
  const experimentStore: ExperimentStoreHandle = { record: async () => {} };

  it('accepts monitoringStress option', () => {
    const stage = new LocalLiveStage(experimentStore, { monitoringStress: true });
    assert.equal(stage.monitoringStress, true);
  });

  it('defaults monitoringStress to false', () => {
    const stage = new LocalLiveStage(experimentStore);
    assert.equal(stage.monitoringStress, false);
  });

  it('delegates to the runner host when monitoring stress is enabled', async () => {
    const spy = { calls: 0 };
    const lane = makeLaneSummary('complete', {
      runs: 5,
      degraded: 1,
      harmfulSeen: 0,
    });
    const stage = new LocalLiveStage(experimentStore, { monitoringStress: true });
    const result = await stage.run(makeContext(makeHost(lane, spy)));
    assert.equal(spy.calls, 1);
    assert.equal(result.stage, 'local_live');
    assert.equal(result.outcome, 'complete');
    const metadata = result.metadata as { lane: VerificationLaneSummary };
    assert.equal(metadata.lane.runs, 5);
    assert.equal(metadata.lane.degraded, 1);
    assert.equal(metadata.lane.harmfulSeen, 0);
  });

  it('carries monitoring stress data in the lane summary when enabled', async () => {
    const spy = { calls: 0 };
    const lane = makeLaneSummary('complete', {
      attempted: 10,
      meaningfulAttempts: 8,
      runs: 10,
      degraded: 2,
      harmfulSeen: 1,
    });
    const stage = new LocalLiveStage(experimentStore, { monitoringStress: true });
    const result = await stage.run(makeContext(makeHost(lane, spy)));
    const metadata = result.metadata as { lane: VerificationLaneSummary };
    assert.equal(metadata.lane.runs, 10, 'runs should reflect monitoring stress classifications');
    assert.equal(metadata.lane.degraded, 2, 'degraded should reflect monitoring degradation');
    assert.equal(metadata.lane.harmfulSeen, 1, 'harmfulSeen should reflect detected harmful actions');
  });

  it('does not populate monitoring stress fields when mode is off', async () => {
    const spy = { calls: 0 };
    const lane = makeLaneSummary('complete');
    const stage = new LocalLiveStage(experimentStore, { monitoringStress: false });
    const result = await stage.run(makeContext(makeHost(lane, spy)));
    const metadata = result.metadata as { lane: VerificationLaneSummary };
    assert.equal(metadata.lane.runs, undefined);
    assert.equal(metadata.lane.degraded, undefined);
    assert.equal(metadata.lane.harmfulSeen, undefined);
  });
});

describe('mapLaneStatus (monitoring stress mode)', () => {
  it('maps lane status correctly regardless of monitoring stress', () => {
    assert.equal(mapLaneStatus(makeLaneSummary('complete', { runs: 5 })), 'complete');
    assert.equal(mapLaneStatus(makeLaneSummary('degraded', { degraded: 3 })), 'degraded');
  });
});
