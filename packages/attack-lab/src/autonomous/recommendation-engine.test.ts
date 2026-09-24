import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  detectMissingRuntimeCapability,
  detectSourcePrecisionGap,
  detectDefenseReasoningGap,
  detectFormatStabilityGap,
  detectDockerEnvironmentGap,
  detectRegressionFromBaseline,
  generateRecommendations,
  formatRecommendationsMd,
} from './recommendation-engine.js';
import type { SourceVerificationArtifact } from './source-verify-schemas.js';
import type { RuntimeVerificationArtifact } from './runtime-verify-schemas.js';
import type { RunMonitor } from './run-monitor.js';
import type { ParityScorecard } from './parity-scorecard.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeSourceArtifact(candidates: Array<{
  candidateId: string;
  status: string;
  confidence: number;
  sourceRefs?: Array<{ file: string; line?: number; snippet: string }>;
  defenseMechanismsObserved?: string[];
  preValidationStatus?: string;
  reviewPolicy?: { riskTier: string; requireRuntime: boolean; hardFailOnMiss: boolean };
}>): SourceVerificationArtifact {
  return {
    campaignId: 'test',
    targetId: 'test-target',
    timestamp: new Date().toISOString(),
    candidates: candidates.map(c => ({
      candidateId: c.candidateId,
      claim: `Claim for ${c.candidateId}`,
      status: c.status as 'supported' | 'weakened' | 'refuted' | 'needs_runtime',
      rootCause: 'test root cause',
      sourceRefs: c.sourceRefs ?? [{ file: 'test.py', line: 1, snippet: 'code' }],
      preconditions: [],
      defenseMechanismsObserved: c.defenseMechanismsObserved ?? [],
      assumptions: [],
      validationNotes: [],
      confidence: c.confidence,
      preValidationStatus: c.preValidationStatus as 'supported' | 'weakened' | 'refuted' | 'needs_runtime' | undefined,
      reviewPolicy: c.reviewPolicy as any,
    })),
  };
}

function makeRuntimeArtifact(opts: {
  dockerSetupSuccess: boolean;
  candidates: Array<{ candidateId: string; status: string; pvrReady?: boolean }>;
}): RuntimeVerificationArtifact {
  return {
    campaignId: 'test',
    targetId: 'test-target',
    timestamp: new Date().toISOString(),
    dockerSetupSuccess: opts.dockerSetupSuccess,
    candidates: opts.candidates.map(c => ({
      modelResult: {
        candidateId: c.candidateId,
        claim: `Claim for ${c.candidateId}`,
        status: c.status as any,
        rootCause: 'test',
        reproducerCommands: [],
        httpEvidence: [],
        pvrReady: c.pvrReady ?? false,
        confidence: 0.8,
      },
      validatedResult: {
        candidateId: c.candidateId,
        claim: `Claim for ${c.candidateId}`,
        status: c.status as any,
        rootCause: 'test',
        reproducerCommands: [],
        httpEvidence: [],
        pvrReady: c.pvrReady ?? false,
        confidence: 0.8,
      },
      wasDowngraded: false,
      validationNotes: [],
    })),
  };
}

function makeMockMonitor(overrides?: {
  gateRepairsByClass?: Record<string, { total: number; succeeded: number; costUsd: number }>;
  downgradeCount?: number;
}): RunMonitor {
  return {
    getGateRepairsByClass: () => overrides?.gateRepairsByClass ?? {},
    getDowngradeCount: () => overrides?.downgradeCount ?? 0,
    getEvents: () => [],
    getAnomalies: () => [],
  } as unknown as RunMonitor;
}

function makeScorecard(overrides?: Partial<ParityScorecard>): ParityScorecard {
  return {
    schemaVersion: 1,
    runId: 'test-run',
    profileId: null,
    configHash: 'abc123',
    targetId: 'test-target',
    timestamp: new Date().toISOString(),
    totalCostUsd: 0,
    totalDurationMs: 1000,
    lanes: {},
    baselineDelta: null,
    frontierDelta: null,
    recommendation: 'hold',
    recommendationReason: 'test',
    anomalyCount: 0,
    anomalySummary: [],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// detectMissingRuntimeCapability
// ---------------------------------------------------------------------------

describe('detectMissingRuntimeCapability', () => {
  it('returns empty when no source artifact', () => {
    assert.deepEqual(detectMissingRuntimeCapability(undefined, undefined), []);
  });

  it('detects supported findings without runtime verification', () => {
    const source = makeSourceArtifact([
      { candidateId: 'c-1', status: 'supported', confidence: 0.9 },
      { candidateId: 'c-2', status: 'refuted', confidence: 0.3 },
    ]);
    const recs = detectMissingRuntimeCapability(source, undefined);
    assert.equal(recs.length, 1);
    assert.equal(recs[0].class, 'missing_runtime_capability');
    assert.deepEqual(recs[0].affectedCandidates, ['c-1']);
  });

  it('does not flag supported findings that have runtime results', () => {
    const source = makeSourceArtifact([
      { candidateId: 'c-1', status: 'supported', confidence: 0.9 },
    ]);
    const runtime = makeRuntimeArtifact({
      dockerSetupSuccess: true,
      candidates: [{ candidateId: 'c-1', status: 'confirmed' }],
    });
    const recs = detectMissingRuntimeCapability(source, runtime);
    const noRuntimeRecs = recs.filter(r => r.id === 'mrc-no-runtime-for-supported');
    assert.equal(noRuntimeRecs.length, 0);
  });

  it('detects source-supported but runtime blocked', () => {
    const source = makeSourceArtifact([
      { candidateId: 'c-1', status: 'supported', confidence: 0.9 },
    ]);
    const runtime = makeRuntimeArtifact({
      dockerSetupSuccess: true,
      candidates: [{ candidateId: 'c-1', status: 'blocked' }],
    });
    const recs = detectMissingRuntimeCapability(source, runtime);
    const blocked = recs.filter(r => r.id === 'mrc-runtime-blocked');
    assert.equal(blocked.length, 1);
  });

  it('detects policy-required runtime when only source was run', () => {
    const source = makeSourceArtifact([
      {
        candidateId: 'c-1', status: 'supported', confidence: 0.9,
        reviewPolicy: { riskTier: 'critical', requireRuntime: true, hardFailOnMiss: true },
      },
    ]);
    const recs = detectMissingRuntimeCapability(source, undefined);
    const policyRecs = recs.filter(r => r.id === 'mrc-policy-requires-runtime');
    assert.equal(policyRecs.length, 1);
    assert.equal(policyRecs[0].priority, 'critical');
  });

  it('escalates priority when critical-tier findings are affected', () => {
    const source = makeSourceArtifact([
      {
        candidateId: 'c-1', status: 'supported', confidence: 0.9,
        reviewPolicy: { riskTier: 'critical', requireRuntime: true, hardFailOnMiss: true },
      },
    ]);
    const recs = detectMissingRuntimeCapability(source, undefined);
    assert.ok(recs.some(r => r.priority === 'critical'));
  });
});

// ---------------------------------------------------------------------------
// detectSourcePrecisionGap
// ---------------------------------------------------------------------------

describe('detectSourcePrecisionGap', () => {
  it('returns empty when no source artifact', () => {
    assert.deepEqual(detectSourcePrecisionGap(undefined), []);
  });

  it('detects supported findings with weak grounding', () => {
    const source = makeSourceArtifact([
      {
        candidateId: 'c-1', status: 'supported', confidence: 0.4,
        sourceRefs: [{ file: 'test.py', snippet: 'code' }],
      },
    ]);
    const recs = detectSourcePrecisionGap(source);
    assert.equal(recs.length, 1);
    assert.equal(recs[0].class, 'source_precision_gap');
    assert.deepEqual(recs[0].affectedCandidates, ['c-1']);
  });

  it('does not flag well-grounded supported findings', () => {
    const source = makeSourceArtifact([
      {
        candidateId: 'c-1', status: 'supported', confidence: 0.9,
        sourceRefs: [{ file: 'test.py', line: 42, snippet: 'code' }],
      },
    ]);
    const recs = detectSourcePrecisionGap(source);
    assert.equal(recs.length, 0);
  });

  it('ignores non-supported findings', () => {
    const source = makeSourceArtifact([
      { candidateId: 'c-1', status: 'weakened', confidence: 0.3 },
    ]);
    const recs = detectSourcePrecisionGap(source);
    assert.equal(recs.length, 0);
  });
});

// ---------------------------------------------------------------------------
// detectDefenseReasoningGap
// ---------------------------------------------------------------------------

describe('detectDefenseReasoningGap', () => {
  it('returns empty when no source artifact', () => {
    assert.deepEqual(detectDefenseReasoningGap(undefined), []);
  });

  it('detects defended findings downgraded to needs_runtime', () => {
    const source = makeSourceArtifact([
      {
        candidateId: 'c-1', status: 'needs_runtime', confidence: 0.6,
        defenseMechanismsObserved: ['html.escape() at views.py:45'],
        preValidationStatus: 'supported',
      },
    ]);
    const recs = detectDefenseReasoningGap(source);
    assert.equal(recs.length, 1);
    assert.equal(recs[0].class, 'defense_reasoning_gap');
  });

  it('ignores findings without defenses', () => {
    const source = makeSourceArtifact([
      { candidateId: 'c-1', status: 'needs_runtime', confidence: 0.6, preValidationStatus: 'supported' },
    ]);
    const recs = detectDefenseReasoningGap(source);
    assert.equal(recs.length, 0);
  });

  it('ignores findings that were not downgraded', () => {
    const source = makeSourceArtifact([
      {
        candidateId: 'c-1', status: 'supported', confidence: 0.9,
        defenseMechanismsObserved: ['html.escape()'],
      },
    ]);
    const recs = detectDefenseReasoningGap(source);
    assert.equal(recs.length, 0);
  });
});

// ---------------------------------------------------------------------------
// detectFormatStabilityGap
// ---------------------------------------------------------------------------

describe('detectFormatStabilityGap', () => {
  it('returns empty when no monitor', () => {
    assert.deepEqual(detectFormatStabilityGap(undefined), []);
  });

  it('detects excessive JSON format repairs', () => {
    const monitor = makeMockMonitor({
      gateRepairsByClass: {
        format_no_json: { total: 4, succeeded: 3, costUsd: 0 },
      },
    });
    const recs = detectFormatStabilityGap(monitor);
    assert.ok(recs.some(r => r.id === 'fsg-format-json'));
  });

  it('detects schema mismatches', () => {
    const monitor = makeMockMonitor({
      gateRepairsByClass: {
        format_schema_mismatch: { total: 3, succeeded: 2, costUsd: 0 },
      },
    });
    const recs = detectFormatStabilityGap(monitor);
    assert.ok(recs.some(r => r.id === 'fsg-schema-mismatch'));
  });

  it('treats truncated/invalid JSON repairs as format stability gaps', () => {
    const monitor = makeMockMonitor({
      gateRepairsByClass: {
        format_truncated: { total: 2, succeeded: 2, costUsd: 0 },
        format_invalid_json: { total: 1, succeeded: 1, costUsd: 0 },
      },
    });
    const recs = detectFormatStabilityGap(monitor);
    assert.ok(recs.some(r => r.id === 'fsg-format-json'));
  });

  it('detects evidence fabrication', () => {
    const monitor = makeMockMonitor({
      gateRepairsByClass: {
        evidence_fabricated: { total: 1, succeeded: 0, costUsd: 0 },
      },
    });
    const recs = detectFormatStabilityGap(monitor);
    const fab = recs.filter(r => r.id === 'fsg-fabrication');
    assert.equal(fab.length, 1);
    assert.equal(fab[0].priority, 'high');
  });

  it('returns empty when counts below thresholds', () => {
    const monitor = makeMockMonitor({
      gateRepairsByClass: {
        format_no_json: { total: 1, succeeded: 1, costUsd: 0 },
        format_schema_mismatch: { total: 1, succeeded: 1, costUsd: 0 },
      },
    });
    const recs = detectFormatStabilityGap(monitor);
    assert.equal(recs.length, 0);
  });
});

// ---------------------------------------------------------------------------
// detectDockerEnvironmentGap
// ---------------------------------------------------------------------------

describe('detectDockerEnvironmentGap', () => {
  it('returns empty when no runtime artifact', () => {
    assert.deepEqual(detectDockerEnvironmentGap(undefined), []);
  });

  it('detects Docker setup failure', () => {
    const runtime = makeRuntimeArtifact({
      dockerSetupSuccess: false,
      candidates: [{ candidateId: 'c-1', status: 'blocked' }],
    });
    const recs = detectDockerEnvironmentGap(runtime);
    assert.equal(recs.length, 1);
    assert.equal(recs[0].id, 'deg-docker-setup-failed');
  });

  it('detects all candidates blocked despite successful Docker', () => {
    const runtime = makeRuntimeArtifact({
      dockerSetupSuccess: true,
      candidates: [
        { candidateId: 'c-1', status: 'blocked' },
        { candidateId: 'c-2', status: 'blocked' },
      ],
    });
    const recs = detectDockerEnvironmentGap(runtime);
    assert.equal(recs.length, 1);
    assert.equal(recs[0].id, 'deg-all-blocked');
  });

  it('returns empty when Docker succeeds and candidates verified', () => {
    const runtime = makeRuntimeArtifact({
      dockerSetupSuccess: true,
      candidates: [{ candidateId: 'c-1', status: 'confirmed' }],
    });
    const recs = detectDockerEnvironmentGap(runtime);
    assert.equal(recs.length, 0);
  });
});

// ---------------------------------------------------------------------------
// detectRegressionFromBaseline
// ---------------------------------------------------------------------------

describe('detectRegressionFromBaseline', () => {
  it('returns empty when no scorecard', () => {
    assert.deepEqual(detectRegressionFromBaseline(undefined, null), []);
  });

  it('returns empty when no baseline', () => {
    const sc = makeScorecard();
    assert.deepEqual(detectRegressionFromBaseline(sc, null), []);
  });

  it('detects format stability regression', () => {
    const sc = makeScorecard({
      baselineDelta: {
        formatStabilityDelta: -0.2,
      },
    });
    const baseline = makeScorecard();
    const recs = detectRegressionFromBaseline(sc, baseline);
    assert.equal(recs.length, 1);
    assert.equal(recs[0].class, 'regression_from_baseline');
    assert.equal(recs[0].priority, 'critical');
  });

  it('detects parse success regression', () => {
    const sc = makeScorecard({
      baselineDelta: {
        parseSuccessRateDelta: -0.15,
      },
    });
    const recs = detectRegressionFromBaseline(sc, makeScorecard());
    assert.equal(recs.length, 1);
  });

  it('ignores small regressions', () => {
    const sc = makeScorecard({
      baselineDelta: {
        formatStabilityDelta: -0.05,
        parseSuccessRateDelta: -0.03,
      },
    });
    const recs = detectRegressionFromBaseline(sc, makeScorecard());
    assert.equal(recs.length, 0);
  });
});

// ---------------------------------------------------------------------------
// generateRecommendations
// ---------------------------------------------------------------------------

describe('generateRecommendations', () => {
  it('aggregates all detectors', () => {
    const source = makeSourceArtifact([
      { candidateId: 'c-1', status: 'supported', confidence: 0.9 },
    ]);
    const summary = generateRecommendations({
      targetId: 'test-target',
      sourceArtifact: source,
    });
    assert.equal(summary.targetId, 'test-target');
    assert.ok(summary.recommendations.length > 0);
    assert.equal(summary.metrics.sourceVerified, 1);
  });

  it('sorts by priority', () => {
    const source = makeSourceArtifact([
      {
        candidateId: 'c-1', status: 'supported', confidence: 0.9,
        reviewPolicy: { riskTier: 'critical', requireRuntime: true, hardFailOnMiss: true },
      },
      {
        candidateId: 'c-2', status: 'supported', confidence: 0.4,
        sourceRefs: [{ file: 'test.py', snippet: 'code' }],
      },
    ]);
    const summary = generateRecommendations({
      targetId: 'test-target',
      sourceArtifact: source,
    });
    const priorities = summary.recommendations.map(r => r.priority);
    for (let i = 1; i < priorities.length; i++) {
      const order = { critical: 0, high: 1, medium: 2, low: 3 };
      assert.ok(order[priorities[i]] >= order[priorities[i - 1]],
        `Expected ${priorities[i]} to come after ${priorities[i - 1]}`);
    }
  });

  it('handles empty inputs', () => {
    const summary = generateRecommendations({
      targetId: 'empty',
    });
    assert.equal(summary.recommendations.length, 0);
    assert.equal(summary.metrics.totalCandidates, 0);
  });

  it('computes metrics from artifacts', () => {
    const source = makeSourceArtifact([
      { candidateId: 'c-1', status: 'supported', confidence: 0.9 },
      { candidateId: 'c-2', status: 'weakened', confidence: 0.5 },
    ]);
    const runtime = makeRuntimeArtifact({
      dockerSetupSuccess: true,
      candidates: [
        { candidateId: 'c-1', status: 'confirmed', pvrReady: true },
      ],
    });
    const summary = generateRecommendations({
      targetId: 'test',
      sourceArtifact: source,
      runtimeArtifact: runtime,
    });
    assert.equal(summary.metrics.sourceVerified, 2);
    assert.equal(summary.metrics.runtimeVerified, 1);
    assert.equal(summary.metrics.pvrReady, 1);
  });
});

// ---------------------------------------------------------------------------
// formatRecommendationsMd
// ---------------------------------------------------------------------------

describe('formatRecommendationsMd', () => {
  it('renders empty recommendations', () => {
    const md = formatRecommendationsMd({
      generatedAt: '2026-04-27T00:00:00Z',
      targetId: 'test',
      recommendations: [],
      metrics: {
        totalCandidates: 0, sourceVerified: 0, runtimeVerified: 0,
        gateFailures: 0, downgrades: 0, pvrReady: 0, costUsd: 0,
      },
    });
    assert.match(md, /No recommendations generated/);
  });

  it('renders grouped recommendations', () => {
    const md = formatRecommendationsMd({
      generatedAt: '2026-04-27T00:00:00Z',
      targetId: 'test',
      recommendations: [
        {
          id: 'r-1',
          class: 'missing_runtime_capability',
          priority: 'critical',
          title: 'Missing runtime',
          detail: 'Detail here',
          metrics: {},
          affectedCandidates: ['c-1'],
          suggestedAction: 'Fix it',
        },
        {
          id: 'r-2',
          class: 'source_precision_gap',
          priority: 'medium',
          title: 'Weak grounding',
          detail: 'Some detail',
          metrics: {},
          affectedCandidates: [],
          suggestedAction: 'Review',
        },
      ],
      metrics: {
        totalCandidates: 5, sourceVerified: 5, runtimeVerified: 0,
        gateFailures: 1, downgrades: 0, pvrReady: 0, costUsd: 0,
      },
    });
    assert.match(md, /CRITICAL \(1\)/);
    assert.match(md, /MEDIUM \(1\)/);
    assert.match(md, /Missing runtime/);
    assert.match(md, /c-1/);
  });
});
