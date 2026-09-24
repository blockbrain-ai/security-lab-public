import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateMidPipelineReadiness } from './mode.js';

describe('evaluateMidPipelineReadiness', () => {
  const base = {
    mode: 'serious-local' as const,
    signalCount: 5,
    requiresSourceScan: true,
    liveTargetConfigured: true,
    requiredIdentitiesMissing: [],
    localLiveTransportReady: true,
    testSynthesisRequired: false,
    testSynthesisTransportReady: true,
    liveTargetReachable: true,
    localLiveRequired: true,
    linuxRuntimeRequired: false,
    linuxRuntimeAvailable: null,
    rollbackAvailable: true,
    mutationCanariesPresent: true,
    rollbackRequired: true,
  };

  it('passes when all readiness checks are met', () => {
    const result = evaluateMidPipelineReadiness(base);
    assert.equal(result.passed, true);
    assert.equal(result.shouldAbort, false);
    assert.equal(result.gaps.length, 0);
  });

  it('fails in serious mode when static scan produced zero signals', () => {
    const result = evaluateMidPipelineReadiness({
      ...base,
      signalCount: 0,
    });
    assert.equal(result.passed, false);
    assert.equal(result.shouldAbort, true);
    assert.ok(result.gaps.some((g) => g.code === 'zero_signals_after_static'));
  });

  it('fails in serious mode when required identities are missing', () => {
    const result = evaluateMidPipelineReadiness({
      ...base,
      requiredIdentitiesMissing: ['user_a_low', 'admin_canary'],
    });
    assert.equal(result.shouldAbort, true);
    assert.ok(result.gaps.some((g) => g.code === 'required_identities_missing'));
  });

  it('fails in serious mode when local-live target is not configured', () => {
    const result = evaluateMidPipelineReadiness({
      ...base,
      liveTargetConfigured: false,
    });
    assert.equal(result.shouldAbort, true);
    assert.ok(result.gaps.some((g) => g.code === 'live_target_missing'));
  });

  it('fails in serious mode when local-live transport is unavailable', () => {
    const result = evaluateMidPipelineReadiness({
      ...base,
      localLiveTransportReady: false,
    });
    assert.equal(result.shouldAbort, true);
    assert.ok(result.gaps.some((g) => g.code === 'local_live_transport_unavailable'));
  });

  it('fails in serious mode when test-synthesis transport is unavailable', () => {
    const result = evaluateMidPipelineReadiness({
      ...base,
      testSynthesisRequired: true,
      testSynthesisTransportReady: false,
    });
    assert.equal(result.shouldAbort, true);
    assert.ok(result.gaps.some((g) => g.code === 'test_synthesis_transport_unavailable'));
  });

  it('fails in serious mode when live target is unreachable', () => {
    const result = evaluateMidPipelineReadiness({
      ...base,
      liveTargetReachable: false,
    });
    assert.equal(result.shouldAbort, true);
    assert.ok(result.gaps.some((g) => g.code === 'live_target_unreachable'));
  });

  it('fails in serious mode when Linux runtime is required but unavailable', () => {
    const result = evaluateMidPipelineReadiness({
      ...base,
      linuxRuntimeRequired: true,
      linuxRuntimeAvailable: false,
    });
    assert.equal(result.shouldAbort, true);
    assert.ok(result.gaps.some((g) => g.code === 'linux_runtime_unavailable'));
  });

  it('fails in serious mode when rollback is missing for mutation canaries', () => {
    const result = evaluateMidPipelineReadiness({
      ...base,
      rollbackAvailable: false,
    });
    assert.equal(result.shouldAbort, true);
    assert.ok(result.gaps.some((g) => g.code === 'rollback_unavailable'));
  });

  it('degrades in smoke mode instead of aborting', () => {
    const result = evaluateMidPipelineReadiness({
      ...base,
      mode: 'smoke',
      signalCount: 0,
      requiredIdentitiesMissing: ['user_a_low'],
      liveTargetReachable: false,
    });
    assert.equal(result.shouldAbort, false);
    assert.equal(result.passed, false);
    assert.ok(result.gaps.length >= 2);
  });

  it('skips live target check when local-live is not required', () => {
    const result = evaluateMidPipelineReadiness({
      ...base,
      localLiveRequired: false,
      liveTargetReachable: false,
    });
    assert.equal(result.passed, true);
    assert.equal(result.shouldAbort, false);
  });

  it('skips rollback check when no mutation canaries are present', () => {
    const result = evaluateMidPipelineReadiness({
      ...base,
      mutationCanariesPresent: false,
      rollbackAvailable: false,
    });
    assert.equal(result.passed, true);
    assert.equal(result.shouldAbort, false);
  });
});
