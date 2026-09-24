/**
 * Section 5.1 — LocalLiveStage tests.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { LocalLiveStage, mapLaneStatus } from './local-live.js';
import type {
  ExperimentStoreHandle,
  StageContext,
  StageRunnerHost,
} from './contracts.js';
import type { VerificationLaneSummary } from '../investigation-runner.js';

function makeLaneSummary(status: VerificationLaneSummary['status']): VerificationLaneSummary {
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

describe('LocalLiveStage', () => {
  const experimentStore: ExperimentStoreHandle = { record: async () => {} };

  it('has the canonical stage name', () => {
    const stage = new LocalLiveStage(experimentStore);
    assert.equal(stage.name, 'local_live');
  });

  it('delegates to the runner host and forwards the lane summary', async () => {
    const spy = { calls: 0 };
    const lane = makeLaneSummary('complete');
    const stage = new LocalLiveStage(experimentStore);
    const result = await stage.run(makeContext(makeHost(lane, spy)));
    assert.equal(spy.calls, 1);
    assert.equal(result.stage, 'local_live');
    assert.equal(result.outcome, 'complete');
    assert.equal((result.metadata as { lane: VerificationLaneSummary }).lane, lane);
  });

  it('surfaces a degraded lane as a degraded stage outcome', async () => {
    const spy = { calls: 0 };
    const stage = new LocalLiveStage(experimentStore);
    const result = await stage.run(makeContext(makeHost(makeLaneSummary('degraded'), spy)));
    assert.equal(result.outcome, 'degraded');
  });

  it('surfaces an incomplete lane as incomplete', async () => {
    const spy = { calls: 0 };
    const stage = new LocalLiveStage(experimentStore);
    const result = await stage.run(makeContext(makeHost(makeLaneSummary('incomplete'), spy)));
    assert.equal(result.outcome, 'incomplete');
  });
});

describe('mapLaneStatus', () => {
  it('maps each execution status correctly', () => {
    assert.equal(mapLaneStatus(makeLaneSummary('complete')), 'complete');
    assert.equal(mapLaneStatus(makeLaneSummary('degraded')), 'degraded');
    assert.equal(mapLaneStatus(makeLaneSummary('incomplete')), 'incomplete');
    assert.equal(mapLaneStatus(makeLaneSummary('blocked')), 'blocked');
  });
});
