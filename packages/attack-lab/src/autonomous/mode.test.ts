import test from 'node:test';
import assert from 'node:assert/strict';

import {
  DEFAULT_RUN_MODE,
  RUN_MODES,
  describeRunMode,
  evaluateCoverageAgainstMode,
  inferModeFromPreset,
  isRunMode,
  type RunMode,
} from './mode.js';
import type { CoverageGap } from './investigation-runner.js';
import { getSeriousVerificationProfile } from '../orchestration/portfolio-profiles.js';

function gap(lane: string, code = 'missing_identity', required = true): CoverageGap {
  return {
    lane,
    code,
    message: `${code} in ${lane}`,
    severity: 'incomplete',
    required,
  };
}

test('RUN_MODES includes exactly the three ratified modes', () => {
  assert.deepEqual([...RUN_MODES], ['smoke', 'serious-local', 'serious-end-to-end']);
  assert.equal(DEFAULT_RUN_MODE, 'smoke');
});

test('isRunMode accepts valid values and rejects others', () => {
  assert.equal(isRunMode('smoke'), true);
  assert.equal(isRunMode('serious-local'), true);
  assert.equal(isRunMode('serious-end-to-end'), true);
  assert.equal(isRunMode('serious'), false);
  assert.equal(isRunMode(''), false);
  assert.equal(isRunMode(undefined), false);
});

test('inferModeFromPreset maps the known presets', () => {
  assert.equal(inferModeFromPreset('serious-local'), 'serious-local');
  assert.equal(inferModeFromPreset('serious-end-to-end'), 'serious-end-to-end');
  assert.equal(inferModeFromPreset('smoke'), 'smoke');
  assert.equal(inferModeFromPreset('diagnostic'), null);
  assert.equal(inferModeFromPreset(undefined), null);
});

test('describeRunMode returns a non-empty blurb for each mode', () => {
  for (const mode of RUN_MODES) {
    const description = describeRunMode(mode);
    assert.ok(description.length > 0);
  }
});

test('smoke mode: every gap is degraded, never fails closed', () => {
  const result = evaluateCoverageAgainstMode(
    [gap('local-live'), gap('hosted'), gap('test-synthesis', 'irrelevant', false)],
    ['local-live', 'hosted'],
    'smoke',
  );
  assert.equal(result.executionStatus, 'degraded');
  assert.equal(result.failClosed, false);
  assert.equal(result.incompleteGaps.length, 0);
  assert.equal(result.degradedGaps.length, 3);
});

test('serious-local: required-lane gap (not hosted) fails closed', () => {
  const result = evaluateCoverageAgainstMode(
    [gap('local-live')],
    ['local-live', 'hosted'],
    'serious-local',
  );
  assert.equal(result.executionStatus, 'incomplete');
  assert.equal(result.failClosed, true);
  assert.equal(result.incompleteGaps.length, 1);
  assert.equal(result.incompleteGaps[0]!.lane, 'local-live');
});

test('serious-local: hosted gap alone degrades but does not fail closed', () => {
  const result = evaluateCoverageAgainstMode(
    [gap('hosted')],
    ['local-live', 'hosted'],
    'serious-local',
  );
  assert.equal(result.executionStatus, 'degraded');
  assert.equal(result.failClosed, false);
});

test('serious-end-to-end: hosted gap fails closed', () => {
  const result = evaluateCoverageAgainstMode(
    [gap('hosted')],
    ['local-live', 'hosted'],
    'serious-end-to-end',
  );
  assert.equal(result.executionStatus, 'incomplete');
  assert.equal(result.failClosed, true);
});

test('serious modes: non-required gap is degraded, never incomplete', () => {
  for (const mode of ['serious-local', 'serious-end-to-end'] as RunMode[]) {
    const result = evaluateCoverageAgainstMode(
      [gap('monitoring-stress', 'optional', false)],
      ['local-live'],
      mode,
    );
    assert.equal(result.executionStatus, 'degraded');
    assert.equal(result.failClosed, false);
  }
});

test('no gaps at all => complete regardless of mode', () => {
  for (const mode of RUN_MODES) {
    const result = evaluateCoverageAgainstMode([], ['local-live', 'hosted'], mode);
    assert.equal(result.executionStatus, 'complete');
    assert.equal(result.failClosed, false);
  }
});

test('getSeriousVerificationProfile returns a profile without implying strict verification', () => {
  const profile = getSeriousVerificationProfile();
  // The PortfolioProfile interface has no strictVerification field. This test
  // documents the Phase 3.2 decision: strict/fail-closed behavior is the mode's
  // job, not a property of the portfolio.
  assert.equal((profile as unknown as { strictVerification?: unknown }).strictVerification, undefined);
  assert.ok(profile.planner);
  assert.ok(profile.judge);
});
