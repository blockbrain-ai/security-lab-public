/**
 * Section 5.1 — TestSynthesisStage tests.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { TestSynthesisStage } from './test-synthesis.js';
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

function makeHost(
  lane: VerificationLaneSummary,
  calls: { n: number },
): StageRunnerHost {
  return {
    runTestSynthesisLaneFriend: async () => {
      calls.n += 1;
      return lane;
    },
    runLocalLiveLaneFriend: async () => {
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

describe('TestSynthesisStage', () => {
  const experimentStore: ExperimentStoreHandle = { record: async () => {} };

  it('has the canonical stage name', () => {
    const stage = new TestSynthesisStage(experimentStore);
    assert.equal(stage.name, 'test_synthesis');
  });

  it('delegates to the runner host and forwards the lane summary', async () => {
    const calls = { n: 0 };
    const lane = makeLaneSummary('complete');
    const stage = new TestSynthesisStage(experimentStore);
    const result = await stage.run(makeContext(makeHost(lane, calls)));
    assert.equal(calls.n, 1);
    assert.equal(result.stage, 'test_synthesis');
    assert.equal(result.outcome, 'complete');
    assert.equal((result.metadata as { lane: VerificationLaneSummary }).lane, lane);
  });

  it('propagates degraded lane outcome', async () => {
    const calls = { n: 0 };
    const stage = new TestSynthesisStage(experimentStore);
    const result = await stage.run(
      makeContext(makeHost(makeLaneSummary('degraded'), calls)),
    );
    assert.equal(result.outcome, 'degraded');
  });

  it('propagates incomplete lane outcome', async () => {
    const calls = { n: 0 };
    const stage = new TestSynthesisStage(experimentStore);
    const result = await stage.run(
      makeContext(makeHost(makeLaneSummary('incomplete'), calls)),
    );
    assert.equal(result.outcome, 'incomplete');
  });
});
