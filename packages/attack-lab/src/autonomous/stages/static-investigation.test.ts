/**
 * Section 5.1 — StaticInvestigationStage tests.
 *
 * Covers the selective counter-worker trigger helper and the stage wrapper.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  StaticInvestigationStage,
  shouldInvokeCounterWorker,
} from './static-investigation.js';
import type { ChainHypothesis } from '../contracts.js';
import type { StageContext } from './contracts.js';

function makeHypothesis(overrides: Partial<ChainHypothesis> = {}): ChainHypothesis {
  return {
    id: 'hyp-1',
    synthesizedAt: '2026-04-11T00:00:00.000Z',
    iteration: 1,
    description: 'A harmless log message is written to /tmp/foo on startup.',
    severity: 'low',
    signalIds: ['sig-1'],
    prerequisites: [],
    status: 'proposed',
    attempts: [],
    ...overrides,
  };
}

describe('shouldInvokeCounterWorker', () => {
  it('does NOT fire on a plain low-complexity hypothesis', () => {
    const hypothesis = makeHypothesis();
    assert.equal(shouldInvokeCounterWorker({ hypothesis }), false);
  });

  it('fires on a cross-boundary claim (boundaryCrossing set)', () => {
    const hypothesis = makeHypothesis({
      boundaryCrossing: { from: 'user', to: 'admin', mechanism: 'jwt claim' },
    });
    assert.equal(shouldInvokeCounterWorker({ hypothesis }), true);
  });

  it('fires on a cross-boundary claim detected via keyword in description', () => {
    const hypothesis = makeHypothesis({
      description: 'JWT token leaks across request scope boundary.',
    });
    assert.equal(shouldInvokeCounterWorker({ hypothesis }), true);
  });

  it('fires on an identity/tenant claim', () => {
    const hypothesis = makeHypothesis({
      description: 'Tenant isolation bypass via org_id parameter tampering.',
    });
    assert.equal(shouldInvokeCounterWorker({ hypothesis }), true);
  });

  it('fires on privilege delta (identity escalation)', () => {
    const hypothesis = makeHypothesis({
      description: 'A benign config file.',
      privilegeDelta: { before: 'user', after: 'admin', escalationType: 'vertical' },
    });
    assert.equal(shouldInvokeCounterWorker({ hypothesis }), true);
  });

  it('fires when chain depth is at least 3', () => {
    const hypothesis = makeHypothesis({
      signalIds: ['sig-1', 'sig-2', 'sig-3'],
    });
    assert.equal(shouldInvokeCounterWorker({ hypothesis }), true);
  });

  it('does NOT fire when chain depth is below 3', () => {
    const hypothesis = makeHypothesis({ signalIds: ['sig-1', 'sig-2'] });
    assert.equal(shouldInvokeCounterWorker({ hypothesis }), false);
  });

  it('fires when the hypothesis resurfaces a dormant signal (explicit flag)', () => {
    const hypothesis = makeHypothesis();
    assert.equal(
      shouldInvokeCounterWorker({ hypothesis, resurfacedFromDormant: true }),
      true,
    );
  });

  it('fires when one of the hypothesis signals is currently dormant', () => {
    const hypothesis = makeHypothesis({ signalIds: ['sig-1', 'sig-2'] });
    assert.equal(
      shouldInvokeCounterWorker({
        hypothesis,
        dormantSignalIds: new Set(['sig-2']),
      }),
      true,
    );
  });

  it('fires on a disputed judge panel (unanimous=false)', () => {
    const hypothesis = makeHypothesis();
    assert.equal(
      shouldInvokeCounterWorker({
        hypothesis,
        judgePanelResult: {
          unanimous: false,
          distinctVerdicts: 2,
          consensusVerdict: null,
        },
      }),
      true,
    );
  });

  it('fires on an inconclusive judge panel verdict', () => {
    const hypothesis = makeHypothesis();
    assert.equal(
      shouldInvokeCounterWorker({
        hypothesis,
        judgePanelResult: {
          unanimous: true,
          distinctVerdicts: 1,
          consensusVerdict: 'inconclusive',
        },
      }),
      true,
    );
  });

  it('does NOT fire on a unanimous, conclusive panel (low-complexity hypothesis)', () => {
    const hypothesis = makeHypothesis();
    assert.equal(
      shouldInvokeCounterWorker({
        hypothesis,
        judgePanelResult: {
          unanimous: true,
          distinctVerdicts: 1,
          consensusVerdict: 'continue',
        },
      }),
      false,
    );
  });
});

describe('StaticInvestigationStage', () => {
  it('has the canonical stage name from SL6', () => {
    const stage = new StaticInvestigationStage();
    assert.equal(stage.name, 'static');
  });

  it('run() returns a complete stage result', async () => {
    const stage = new StaticInvestigationStage();
    const result = await stage.run({} as unknown as StageContext);
    assert.equal(result.stage, 'static');
    assert.equal(result.outcome, 'complete');
    assert.deepEqual(result.coverageGaps, []);
  });
});
