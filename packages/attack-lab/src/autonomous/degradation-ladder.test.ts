import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  createDegradationState,
  behaviorForLevel,
  recordAnomaly,
  recordProgress,
  checkNoProgressTimeout,
  gateClassToAnomalyKind,
  DEFAULT_THRESHOLDS,
  type DegradationThresholds,
  type AnomalyEvent,
} from './degradation-ladder.js';

// ---------------------------------------------------------------------------
// createDegradationState
// ---------------------------------------------------------------------------

describe('createDegradationState', () => {
  it('starts at level 0', () => {
    const state = createDegradationState();
    assert.equal(state.currentLevel, 0);
    assert.equal(state.anomalyHistory.length, 0);
    assert.equal(state.levelHistory.length, 1);
    assert.equal(state.levelHistory[0].level, 0);
    assert.equal(state.levelHistory[0].trigger, 'init');
  });

  it('initializes all anomaly counts to 0', () => {
    const state = createDegradationState();
    for (const count of Object.values(state.anomalyCounts)) {
      assert.equal(count, 0);
    }
  });
});

// ---------------------------------------------------------------------------
// behaviorForLevel
// ---------------------------------------------------------------------------

describe('behaviorForLevel', () => {
  it('level 0 is normal — everything enabled', () => {
    const b = behaviorForLevel(0);
    assert.equal(b.enableAudit, true);
    assert.equal(b.enableSecondaryFollowups, true);
    assert.equal(b.allowBorderlineRuntimeEscalation, true);
    assert.equal(b.allowNonCriticalRuntime, true);
    assert.equal(b.halt, false);
  });

  it('level 1 disables audit and defense critic', () => {
    const b = behaviorForLevel(1);
    assert.equal(b.enableAudit, false);
    assert.equal(b.enableSecondaryFollowups, false);
    assert.equal(b.allowBorderlineRuntimeEscalation, true);
    assert.equal(b.allowNonCriticalRuntime, true);
    assert.equal(b.halt, false);
  });

  it('level 2 restricts to critical-only runtime', () => {
    const b = behaviorForLevel(2);
    assert.equal(b.enableAudit, false);
    assert.equal(b.enableSecondaryFollowups, false);
    assert.equal(b.allowBorderlineRuntimeEscalation, false);
    assert.equal(b.allowNonCriticalRuntime, false);
    assert.equal(b.halt, false);
  });

  it('level 3 halts', () => {
    const b = behaviorForLevel(3);
    assert.equal(b.halt, true);
  });
});

// ---------------------------------------------------------------------------
// gateClassToAnomalyKind
// ---------------------------------------------------------------------------

describe('gateClassToAnomalyKind', () => {
  it('maps format_no_json to format_repair', () => {
    assert.equal(gateClassToAnomalyKind('format_no_json'), 'format_repair');
  });

  it('maps format_schema_mismatch to format_repair', () => {
    assert.equal(gateClassToAnomalyKind('format_schema_mismatch'), 'format_repair');
  });

  it('maps format_markdown_wrapped to format_repair', () => {
    assert.equal(gateClassToAnomalyKind('format_markdown_wrapped'), 'format_repair');
  });

  it('maps schema_mismatch to format_repair', () => {
    assert.equal(gateClassToAnomalyKind('schema_mismatch'), 'format_repair');
  });

  it('maps partial_schema_mismatch to format_repair', () => {
    assert.equal(gateClassToAnomalyKind('partial_schema_mismatch'), 'format_repair');
  });

  it('maps context_exhaustion', () => {
    assert.equal(gateClassToAnomalyKind('context_exhaustion'), 'context_exhaustion');
  });

  it('maps tool_loop_stall to tool_loop', () => {
    assert.equal(gateClassToAnomalyKind('tool_loop_stall'), 'tool_loop');
  });

  it('maps evidence_fabricated to evidence_fabrication', () => {
    assert.equal(gateClassToAnomalyKind('evidence_fabricated'), 'evidence_fabrication');
  });

  it('returns null for unknown class', () => {
    assert.equal(gateClassToAnomalyKind('some_other_thing'), null);
  });
});

// ---------------------------------------------------------------------------
// recordProgress
// ---------------------------------------------------------------------------

describe('recordProgress', () => {
  it('updates lastActivityAt', () => {
    const state = createDegradationState();
    const at = '2026-04-27T10:00:00.000Z';
    recordProgress(state, at);
    assert.equal(state.lastActivityAt, at);
  });
});

// ---------------------------------------------------------------------------
// recordAnomaly — escalation sequence
// ---------------------------------------------------------------------------

describe('recordAnomaly escalation', () => {
  function event(kind: AnomalyEvent['kind']): AnomalyEvent {
    return { at: new Date().toISOString(), kind };
  }

  it('does not escalate below threshold', () => {
    const state = createDegradationState();
    const result = recordAnomaly(state, event('format_repair'));
    assert.equal(result.escalated, false);
    assert.equal(result.newLevel, 0);
    assert.equal(state.anomalyCounts.format_repair, 1);
  });

  it('escalates L0 → L1 at format_repair limit', () => {
    const state = createDegradationState();
    for (let i = 0; i < DEFAULT_THRESHOLDS.formatRepairLimit - 1; i++) {
      recordAnomaly(state, event('format_repair'));
    }
    assert.equal(state.currentLevel, 0);
    const result = recordAnomaly(state, event('format_repair'));
    assert.equal(result.escalated, true);
    assert.equal(result.newLevel, 1);
  });

  it('escalates L0 → L1 at context_exhaustion limit', () => {
    const state = createDegradationState();
    for (let i = 0; i < DEFAULT_THRESHOLDS.contextExhaustionLimit - 1; i++) {
      recordAnomaly(state, event('context_exhaustion'));
    }
    const result = recordAnomaly(state, event('context_exhaustion'));
    assert.equal(result.escalated, true);
    assert.equal(result.newLevel, 1);
  });

  it('escalates L0 → L1 at tool_loop limit', () => {
    const state = createDegradationState();
    for (let i = 0; i < DEFAULT_THRESHOLDS.toolLoopLimit - 1; i++) {
      recordAnomaly(state, event('tool_loop'));
    }
    const result = recordAnomaly(state, event('tool_loop'));
    assert.equal(result.escalated, true);
    assert.equal(result.newLevel, 1);
  });

  it('escalates L1 → L2 at fabrication limit', () => {
    const state = createDegradationState();
    state.currentLevel = 1;
    for (let i = 0; i < DEFAULT_THRESHOLDS.fabricationLimit - 1; i++) {
      recordAnomaly(state, event('evidence_fabrication'));
    }
    const result = recordAnomaly(state, event('evidence_fabrication'));
    assert.equal(result.escalated, true);
    assert.equal(result.newLevel, 2);
  });

  it('escalates L1 → L2 at docker_failure limit', () => {
    const state = createDegradationState();
    state.currentLevel = 1;
    for (let i = 0; i < DEFAULT_THRESHOLDS.dockerFailureLimit - 1; i++) {
      recordAnomaly(state, event('docker_failure'));
    }
    const result = recordAnomaly(state, event('docker_failure'));
    assert.equal(result.escalated, true);
    assert.equal(result.newLevel, 2);
  });

  it('escalates L1 → L2 at cumulative half-threshold', () => {
    const state = createDegradationState();
    state.currentLevel = 1;
    const halfThreshold = Math.floor(DEFAULT_THRESHOLDS.cumulativeHaltThreshold / 2);
    for (let i = 0; i < halfThreshold - 1; i++) {
      recordAnomaly(state, event('format_repair'));
    }
    assert.equal(state.currentLevel, 1);
    const result = recordAnomaly(state, event('format_repair'));
    assert.equal(result.escalated, true);
    assert.equal(result.newLevel, 2);
  });

  it('escalates to L3 at cumulative threshold', () => {
    const state = createDegradationState();
    state.currentLevel = 2;
    for (let i = 0; i < DEFAULT_THRESHOLDS.cumulativeHaltThreshold - 1; i++) {
      recordAnomaly(state, event('format_repair'));
    }
    const result = recordAnomaly(state, event('format_repair'));
    assert.equal(result.escalated, true);
    assert.equal(result.newLevel, 3);
  });

  it('never de-escalates', () => {
    const state = createDegradationState();
    state.currentLevel = 2;
    const result = recordAnomaly(state, event('format_repair'));
    assert.equal(result.newLevel, 2);
    assert.equal(result.escalated, false);
  });

  it('records anomaly history', () => {
    const state = createDegradationState();
    recordAnomaly(state, event('format_repair'));
    recordAnomaly(state, event('tool_loop'));
    assert.equal(state.anomalyHistory.length, 2);
    assert.equal(state.anomalyHistory[0].kind, 'format_repair');
    assert.equal(state.anomalyHistory[1].kind, 'tool_loop');
  });

  it('does not treat anomalies as progress for lastActivityAt', () => {
    const state = createDegradationState();
    const initial = state.lastActivityAt;
    recordAnomaly(state, event('format_repair'));
    assert.equal(state.lastActivityAt, initial);
  });

  it('records level history on escalation', () => {
    const state = createDegradationState();
    for (let i = 0; i < DEFAULT_THRESHOLDS.formatRepairLimit; i++) {
      recordAnomaly(state, event('format_repair'));
    }
    assert.equal(state.levelHistory.length, 2);
    assert.equal(state.levelHistory[1].level, 1);
    assert.equal(state.levelHistory[1].trigger, 'format_repair');
  });
});

// ---------------------------------------------------------------------------
// recordAnomaly — custom thresholds
// ---------------------------------------------------------------------------

describe('recordAnomaly custom thresholds', () => {
  function event(kind: AnomalyEvent['kind']): AnomalyEvent {
    return { at: new Date().toISOString(), kind };
  }

  it('respects custom format repair limit', () => {
    const thresholds: DegradationThresholds = { ...DEFAULT_THRESHOLDS, formatRepairLimit: 2 };
    const state = createDegradationState();
    recordAnomaly(state, event('format_repair'), thresholds);
    assert.equal(state.currentLevel, 0);
    const result = recordAnomaly(state, event('format_repair'), thresholds);
    assert.equal(result.escalated, true);
    assert.equal(result.newLevel, 1);
  });

  it('respects custom cumulative halt threshold', () => {
    const thresholds: DegradationThresholds = { ...DEFAULT_THRESHOLDS, cumulativeHaltThreshold: 4 };
    const state = createDegradationState();
    state.currentLevel = 2;
    for (let i = 0; i < 3; i++) {
      recordAnomaly(state, event('format_repair'), thresholds);
    }
    assert.equal(state.currentLevel, 2);
    const result = recordAnomaly(state, event('format_repair'), thresholds);
    assert.equal(result.escalated, true);
    assert.equal(result.newLevel, 3);
  });
});

// ---------------------------------------------------------------------------
// checkNoProgressTimeout
// ---------------------------------------------------------------------------

describe('checkNoProgressTimeout', () => {
  it('does not escalate within timeout', () => {
    const state = createDegradationState();
    const now = new Date();
    const last = new Date(now.getTime() - 10_000).toISOString();
    const result = checkNoProgressTimeout(state, last, now.toISOString());
    assert.equal(result.escalated, false);
  });

  it('escalates L0 → L2 after timeout', () => {
    const state = createDegradationState();
    const now = new Date();
    const last = new Date(now.getTime() - DEFAULT_THRESHOLDS.noProgressTimeoutMs - 1000).toISOString();
    const result = checkNoProgressTimeout(state, last, now.toISOString());
    assert.equal(result.escalated, true);
    assert.equal(result.newLevel, 2);
  });

  it('escalates L2 → L3 after timeout', () => {
    const state = createDegradationState();
    state.currentLevel = 2;
    const now = new Date();
    const last = new Date(now.getTime() - DEFAULT_THRESHOLDS.noProgressTimeoutMs - 1000).toISOString();
    const result = checkNoProgressTimeout(state, last, now.toISOString());
    assert.equal(result.escalated, true);
    assert.equal(result.newLevel, 3);
  });

  it('does not escalate beyond L3', () => {
    const state = createDegradationState();
    state.currentLevel = 3;
    const now = new Date();
    const last = new Date(now.getTime() - DEFAULT_THRESHOLDS.noProgressTimeoutMs - 1000).toISOString();
    const result = checkNoProgressTimeout(state, last, now.toISOString());
    assert.equal(result.escalated, false);
    assert.equal(result.newLevel, 3);
  });

  it('records no_progress anomaly', () => {
    const state = createDegradationState();
    const now = new Date();
    const last = new Date(now.getTime() - DEFAULT_THRESHOLDS.noProgressTimeoutMs - 1000).toISOString();
    checkNoProgressTimeout(state, last, now.toISOString());
    assert.equal(state.anomalyCounts.no_progress, 1);
    assert.equal(state.anomalyHistory.length, 1);
    assert.equal(state.anomalyHistory[0].kind, 'no_progress');
  });

  it('respects custom timeout', () => {
    const thresholds: DegradationThresholds = { ...DEFAULT_THRESHOLDS, noProgressTimeoutMs: 60_000 };
    const state = createDegradationState();
    const now = new Date();
    const last = new Date(now.getTime() - 61_000).toISOString();
    const result = checkNoProgressTimeout(state, last, now.toISOString(), thresholds);
    assert.equal(result.escalated, true);
  });
});

// ---------------------------------------------------------------------------
// Full escalation sequence L0 → L1 → L2 → L3
// ---------------------------------------------------------------------------

describe('full escalation sequence', () => {
  function event(kind: AnomalyEvent['kind']): AnomalyEvent {
    return { at: new Date().toISOString(), kind };
  }

  it('progresses through all levels', () => {
    const state = createDegradationState();
    assert.equal(state.currentLevel, 0);

    // L0 → L1: hit format repair limit
    for (let i = 0; i < DEFAULT_THRESHOLDS.formatRepairLimit; i++) {
      recordAnomaly(state, event('format_repair'));
    }
    assert.equal(state.currentLevel, 1);

    // L1 → L2: hit fabrication limit
    for (let i = 0; i < DEFAULT_THRESHOLDS.fabricationLimit; i++) {
      recordAnomaly(state, event('evidence_fabrication'));
    }
    assert.equal(state.currentLevel, 2);

    // L2 → L3: hit cumulative threshold
    const remaining = DEFAULT_THRESHOLDS.cumulativeHaltThreshold -
      state.anomalyCounts.format_repair -
      state.anomalyCounts.evidence_fabrication;
    for (let i = 0; i < remaining; i++) {
      recordAnomaly(state, event('docker_failure'));
    }
    assert.equal(state.currentLevel, 3);

    // Verify level history
    assert.equal(state.levelHistory.length, 4);
    assert.deepEqual(state.levelHistory.map(h => h.level), [0, 1, 2, 3]);
  });
});
