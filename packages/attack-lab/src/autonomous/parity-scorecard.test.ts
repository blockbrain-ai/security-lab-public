import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  ParityScorecardSchema,
  computeSourceMetrics,
  computeRuntimeMetrics,
  deriveRecommendation,
  computeScorecard,
  renderScorecardMarkdown,
  writeScorecard,
  readScorecard,
  type ParityScorecard,
} from './parity-scorecard.js';
import { RunMonitor } from './run-monitor.js';
import type { SourceVerificationArtifact } from './source-verify-schemas.js';
import type { RuntimeVerificationArtifact, ValidatedCandidate } from './runtime-verify-schemas.js';
import type { VerificationManifest } from './verification-manifest.js';
import { BenchmarkRegistry } from './benchmark-registry.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type StatusLiteral = 'supported' | 'weakened' | 'refuted' | 'needs_runtime';

function makeSourceArtifact(candidates: Array<{ id: string; status: string; preCriticStatus?: StatusLiteral }>): SourceVerificationArtifact {
  return {
    campaignId: 'test',
    targetId: 'test-target',
    timestamp: new Date().toISOString(),
    candidates: candidates.map((c) => ({
      candidateId: c.id,
      claim: 'test claim',
      status: c.status as StatusLiteral,
      rootCause: 'test root cause',
      sourceRefs: [{ file: 'test.ts', line: 1, snippet: 'test' }],
      preconditions: [],
      defenseMechanismsObserved: [],
      assumptions: [],
      validationNotes: [],
      confidence: 0.8,
      ...(c.preCriticStatus ? { preCriticStatus: c.preCriticStatus } : {}),
    })),
  };
}

function makeRuntimeArtifact(candidates: Array<{ id: string; status: string; pvrReady?: boolean; wasDowngraded?: boolean; fabricated?: boolean }>): RuntimeVerificationArtifact {
  return {
    campaignId: 'test',
    targetId: 'test-target',
    timestamp: new Date().toISOString(),
    dockerSetupSuccess: true,
    candidates: candidates.map((c): ValidatedCandidate => ({
      modelResult: {
        candidateId: c.id,
        claim: 'test',
        status: c.status as 'confirmed' | 'partially_confirmed' | 'not_reproducible' | 'blocked' | 'refuted',
        rootCause: 'test',
        reproducerCommands: [],
        httpEvidence: [],
        confidence: 0.8,
        pvrReady: c.pvrReady ?? false,
      },
      validatedResult: {
        candidateId: c.id,
        claim: 'test',
        status: c.status as 'confirmed' | 'partially_confirmed' | 'not_reproducible' | 'blocked' | 'refuted',
        rootCause: 'test',
        reproducerCommands: [],
        httpEvidence: [],
        confidence: 0.8,
        pvrReady: c.pvrReady ?? false,
      },
      wasDowngraded: c.wasDowngraded ?? false,
      validationNotes: c.fabricated
        ? [{ rule: 'evidence_fabrication_check', detail: 'fabricated evidence detected' }]
        : [],
    })),
  };
}

function makeManifest(overrides?: Partial<VerificationManifest>): VerificationManifest {
  return {
    schemaVersion: 1,
    runId: 'verify-test-1234',
    profileId: 'qwen_default',
    targetId: 'test-target',
    mode: 'full',
    git: { commitHash: 'abc123', branch: 'main', isDirty: false },
    lanes: {
      source: { provider: 'bounded_local', model: 'qwen3.6-27b' },
      runtime: { provider: 'bounded_local', model: 'qwen3.6-27b' },
    },
    cliOptions: {},
    artifactPaths: {},
    configHash: 'abcdef0123456789',
    startedAt: new Date().toISOString(),
    finalizedAt: new Date().toISOString(),
    durationMs: 60000,
    exitStatus: 'success',
    telemetrySummary: {
      totalCostUsd: 0,
      totalInputTokens: 5000,
      totalOutputTokens: 2000,
      invocationCount: 10,
    },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Schema validation
// ---------------------------------------------------------------------------

test('ParityScorecardSchema validates a minimal scorecard', () => {
  const sc = ParityScorecardSchema.parse({
    schemaVersion: 1,
    runId: 'test',
    profileId: null,
    configHash: 'abc',
    targetId: 'target',
    timestamp: new Date().toISOString(),
    totalCostUsd: 0,
    totalDurationMs: 0,
    lanes: {},
    baselineDelta: null,
    frontierDelta: null,
    recommendation: 'hold',
    recommendationReason: 'test',
    anomalyCount: 0,
    anomalySummary: [],
  });
  assert.equal(sc.recommendation, 'hold');
});

// ---------------------------------------------------------------------------
// computeSourceMetrics
// ---------------------------------------------------------------------------

test('computeSourceMetrics counts status distribution', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scorecard-'));
  try {
    const monitor = new RunMonitor(dir);
    await monitor.prepare();

    const artifact = makeSourceArtifact([
      { id: 'c1', status: 'supported' },
      { id: 'c2', status: 'supported' },
      { id: 'c3', status: 'refuted' },
      { id: 'c4', status: 'needs_runtime' },
    ]);

    const metrics = computeSourceMetrics(artifact, monitor, 1000, 0);
    assert.equal(metrics.candidateCount, 4);
    assert.equal(metrics.statusDistribution.supported, 2);
    assert.equal(metrics.statusDistribution.refuted, 1);
    assert.equal(metrics.statusDistribution.needs_runtime, 1);
    assert.equal(metrics.formatStabilityRate, 1);
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('computeSourceMetrics tracks gate repairs and format stability', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scorecard-'));
  try {
    const monitor = new RunMonitor(dir);
    await monitor.prepare();

    // Simulate: c1 has gate repair, c2 does not
    await monitor.emitCandidateStart('c1', 'source');
    await monitor.emitGateRepair('c1', 'format_no_json', true, 0, 'source');
    await monitor.emitCandidateEnd('c1', 'source');
    await monitor.emitCandidateStart('c2', 'source');
    await monitor.emitCandidateEnd('c2', 'source');

    const artifact = makeSourceArtifact([
      { id: 'c1', status: 'supported' },
      { id: 'c2', status: 'supported' },
    ]);

    const metrics = computeSourceMetrics(artifact, monitor, 1000, 0);
    assert.equal(metrics.candidateCount, 2);
    assert.equal(metrics.formatStabilityRate, 0.5);
    assert.equal(metrics.gateRepairRate, 0.5);
    assert.ok(metrics.gateRepairsByClass.format_no_json);
    assert.equal(metrics.gateRepairsByClass.format_no_json, 1);
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('computeSourceMetrics counts defense critic overrides', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scorecard-'));
  try {
    const monitor = new RunMonitor(dir);
    await monitor.prepare();

    const artifact = makeSourceArtifact([
      { id: 'c1', status: 'weakened', preCriticStatus: 'refuted' },
      { id: 'c2', status: 'supported' },
    ]);

    const metrics = computeSourceMetrics(artifact, monitor, 1000, 0);
    assert.equal(metrics.defenseCriticOverrideCount, 1);
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('computeSourceMetrics treats parse_failure candidate ends as parse failures', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scorecard-'));
  try {
    const monitor = new RunMonitor(dir);
    await monitor.prepare();

    await monitor.emitCandidateStart('c1', 'source');
    await monitor.emitCandidateEnd('c1', 'source', { status: 'supported' });
    await monitor.emitCandidateStart('c2', 'source');
    await monitor.emitCandidateEnd('c2', 'source', { status: 'needs_runtime', error: 'parse_failure' });

    const artifact = makeSourceArtifact([
      { id: 'c1', status: 'supported' },
      { id: 'c2', status: 'needs_runtime' },
    ]);

    const metrics = computeSourceMetrics(artifact, monitor, 1000, 0);
    assert.equal(metrics.parseSuccessRate, 0.5);
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('computeSourceMetrics ignores runtime gate repairs and runtime downgrades', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scorecard-'));
  try {
    const monitor = new RunMonitor(dir);
    await monitor.prepare();

    await monitor.emitCandidateStart('c1', 'source');
    await monitor.emitCandidateEnd('c1', 'source', { status: 'supported' });
    await monitor.emitGateRepair('c1', 'format_truncated', true, 0, 'runtime');
    await monitor.emitValidatorDowngrade('c1', 'confirmed', 'blocked', ['runtime only'], 'runtime');

    const artifact = makeSourceArtifact([{ id: 'c1', status: 'supported' }]);
    const metrics = computeSourceMetrics(artifact, monitor, 1000, 0);

    assert.equal(metrics.formatStabilityRate, 1);
    assert.equal(metrics.gateRepairRate, 0);
    assert.deepEqual(metrics.gateRepairsByClass, {});
    assert.equal(metrics.proofObligationDowngradeCount, 0);
  } finally {
    await rm(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// computeRuntimeMetrics
// ---------------------------------------------------------------------------

test('computeRuntimeMetrics counts status distribution', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scorecard-'));
  try {
    const monitor = new RunMonitor(dir);
    await monitor.prepare();

    const artifact = makeRuntimeArtifact([
      { id: 'c1', status: 'confirmed', pvrReady: true },
      { id: 'c2', status: 'blocked' },
      { id: 'c3', status: 'not_reproducible' },
    ]);

    const metrics = computeRuntimeMetrics(artifact, monitor, 2000, 0);
    assert.equal(metrics.candidateCount, 3);
    assert.equal(metrics.validatedCount, 2);
    assert.equal(metrics.blockedCount, 1);
    assert.equal(metrics.pvrReadyCount, 1);
    assert.equal(metrics.statusDistribution.confirmed, 1);
    assert.equal(metrics.statusDistribution.blocked, 1);
    assert.equal(metrics.dockerSetupSuccess, true);
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('computeRuntimeMetrics counts fabrication downgrades', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scorecard-'));
  try {
    const monitor = new RunMonitor(dir);
    await monitor.prepare();

    const artifact = makeRuntimeArtifact([
      { id: 'c1', status: 'confirmed', fabricated: true, wasDowngraded: true },
      { id: 'c2', status: 'confirmed' },
    ]);

    const metrics = computeRuntimeMetrics(artifact, monitor, 2000, 0);
    assert.equal(metrics.fabricatedEvidenceDowngradeCount, 1);
    assert.equal(metrics.validatorDowngradeCount, 1);
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('computeRuntimeMetrics treats parse_failure candidate ends as parse failures', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scorecard-'));
  try {
    const monitor = new RunMonitor(dir);
    await monitor.prepare();

    await monitor.emitCandidateStart('c1', 'runtime');
    await monitor.emitCandidateEnd('c1', 'runtime', { status: 'confirmed' });
    await monitor.emitCandidateStart('c2', 'runtime');
    await monitor.emitCandidateEnd('c2', 'runtime', { status: 'not_reproducible', error: 'parse_failure' });

    const artifact = makeRuntimeArtifact([
      { id: 'c1', status: 'confirmed' },
      { id: 'c2', status: 'not_reproducible' },
    ]);

    const metrics = computeRuntimeMetrics(artifact, monitor, 2000, 0);
    assert.equal(metrics.parseSuccessRate, 0.5);
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('computeRuntimeMetrics ignores source gate repairs', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scorecard-'));
  try {
    const monitor = new RunMonitor(dir);
    await monitor.prepare();

    await monitor.emitCandidateStart('c1', 'runtime');
    await monitor.emitCandidateEnd('c1', 'runtime', { status: 'confirmed' });
    await monitor.emitGateRepair('c1', 'format_no_json', true, 0, 'source');

    const artifact = makeRuntimeArtifact([{ id: 'c1', status: 'confirmed' }]);
    const metrics = computeRuntimeMetrics(artifact, monitor, 2000, 0);

    assert.equal(metrics.formatStabilityRate, 1);
    assert.equal(metrics.gateRepairRate, 0);
    assert.deepEqual(metrics.gateRepairsByClass, {});
  } finally {
    await rm(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// deriveRecommendation
// ---------------------------------------------------------------------------

test('deriveRecommendation never promotes a run that processed zero candidates', () => {
  // Missing rates default to 1, so a zero-evidence run looks perfect unless it
  // is explicitly blocked from promotion.
  const noEvidence = {
    source: { formatStabilityRate: 1, parseSuccessRate: 1, candidateCount: 0 },
    runtime: { formatStabilityRate: 1, parseSuccessRate: 1, fabricatedEvidenceDowngradeCount: 0, candidateCount: 0 },
    anomalyCount: 0,
    baselineDelta: null,
  } as unknown as ParityScorecard;

  const withoutBaseline = deriveRecommendation(noEvidence);
  assert.equal(withoutBaseline.recommendation, 'hold');
  assert.match(withoutBaseline.reason, /No candidates were processed/);

  const withBaseline = deriveRecommendation(noEvidence, noEvidence);
  assert.equal(withBaseline.recommendation, 'hold');
  assert.match(withBaseline.reason, /No candidates were processed/);
});

test('deriveRecommendation still rejects a zero-candidate run that failed its thresholds', () => {
  const broken = {
    source: { formatStabilityRate: 0.4, parseSuccessRate: 0.9, candidateCount: 0 },
    runtime: { formatStabilityRate: 1, parseSuccessRate: 1, fabricatedEvidenceDowngradeCount: 0, candidateCount: 0 },
    anomalyCount: 0,
    baselineDelta: null,
  } as unknown as ParityScorecard;

  assert.equal(deriveRecommendation(broken).recommendation, 'reject');
});

test('deriveRecommendation rejects when format stability below 50%', () => {
  const sc = {
    source: { formatStabilityRate: 0.4, parseSuccessRate: 0.9 },
    runtime: { formatStabilityRate: 1, parseSuccessRate: 1, fabricatedEvidenceDowngradeCount: 0 },
    anomalyCount: 0,
    baselineDelta: null,
  } as unknown as ParityScorecard;

  const { recommendation } = deriveRecommendation(sc);
  assert.equal(recommendation, 'reject');
});

test('deriveRecommendation rejects when parse success below 60%', () => {
  const sc = {
    source: { formatStabilityRate: 0.8, parseSuccessRate: 0.5, candidateCount: 10 },
    runtime: { formatStabilityRate: 1, parseSuccessRate: 1, fabricatedEvidenceDowngradeCount: 0, candidateCount: 0 },
    anomalyCount: 0,
    baselineDelta: null,
  } as unknown as ParityScorecard;

  const { recommendation } = deriveRecommendation(sc);
  assert.equal(recommendation, 'reject');
});

test('deriveRecommendation rejects on high fabrication rate', () => {
  const sc = {
    source: { formatStabilityRate: 0.9, parseSuccessRate: 0.9, candidateCount: 5 },
    runtime: { formatStabilityRate: 0.9, parseSuccessRate: 0.9, fabricatedEvidenceDowngradeCount: 3, candidateCount: 5 },
    anomalyCount: 0,
    baselineDelta: null,
  } as unknown as ParityScorecard;

  const { recommendation } = deriveRecommendation(sc);
  assert.equal(recommendation, 'reject');
});

test('deriveRecommendation holds when anomaly count exceeds threshold', () => {
  const sc = {
    source: { formatStabilityRate: 0.9, parseSuccessRate: 0.9, candidateCount: 5 },
    runtime: { formatStabilityRate: 0.9, parseSuccessRate: 0.9, fabricatedEvidenceDowngradeCount: 0, candidateCount: 5 },
    anomalyCount: 4,
    baselineDelta: null,
  } as unknown as ParityScorecard;

  const { recommendation } = deriveRecommendation(sc);
  assert.equal(recommendation, 'hold');
});

test('deriveRecommendation holds on baseline regression', () => {
  const sc = {
    source: { formatStabilityRate: 0.7, parseSuccessRate: 0.8, candidateCount: 5 },
    anomalyCount: 0,
    baselineDelta: { formatStabilityDelta: -0.15 },
  } as unknown as ParityScorecard;

  const baseline = {} as ParityScorecard;
  const { recommendation } = deriveRecommendation(sc, baseline);
  assert.equal(recommendation, 'hold');
});

test('deriveRecommendation promotes when no baseline and metrics good', () => {
  const sc = {
    source: { formatStabilityRate: 0.8, parseSuccessRate: 0.9, candidateCount: 5 },
    runtime: { formatStabilityRate: 0.8, parseSuccessRate: 0.9, fabricatedEvidenceDowngradeCount: 0, candidateCount: 5 },
    anomalyCount: 0,
    baselineDelta: null,
  } as unknown as ParityScorecard;

  const { recommendation } = deriveRecommendation(sc);
  assert.equal(recommendation, 'promote');
});

test('deriveRecommendation holds when no baseline and metrics marginal', () => {
  const sc = {
    source: { formatStabilityRate: 0.65, parseSuccessRate: 0.75, candidateCount: 5 },
    anomalyCount: 0,
    baselineDelta: null,
  } as unknown as ParityScorecard;

  const { recommendation } = deriveRecommendation(sc);
  assert.equal(recommendation, 'hold');
});

test('deriveRecommendation promotes with baseline and no regressions', () => {
  const sc = {
    source: { formatStabilityRate: 0.85, parseSuccessRate: 0.9, candidateCount: 5 },
    runtime: { formatStabilityRate: 0.9, parseSuccessRate: 0.9, fabricatedEvidenceDowngradeCount: 0, candidateCount: 5 },
    anomalyCount: 0,
    baselineDelta: { formatStabilityDelta: 0.05, parseSuccessRateDelta: 0.0 },
  } as unknown as ParityScorecard;

  const baseline = {} as ParityScorecard;
  const { recommendation } = deriveRecommendation(sc, baseline);
  assert.equal(recommendation, 'promote');
});

// ---------------------------------------------------------------------------
// computeScorecard (integration)
// ---------------------------------------------------------------------------

test('computeScorecard produces valid scorecard', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scorecard-'));
  try {
    const monitor = new RunMonitor(dir);
    await monitor.prepare();
    await monitor.emitRunStart();

    const sourceArtifact = makeSourceArtifact([
      { id: 'c1', status: 'supported' },
      { id: 'c2', status: 'refuted' },
    ]);

    const manifest = makeManifest();

    const sc = computeScorecard({
      runId: manifest.runId,
      profileId: manifest.profileId ?? null,
      configHash: manifest.configHash,
      targetId: manifest.targetId,
      manifest,
      monitor,
      sourceArtifact,
    });

    ParityScorecardSchema.parse(sc);
    assert.equal(sc.schemaVersion, 1);
    assert.equal(sc.targetId, 'test-target');
    assert.ok(sc.source);
    assert.equal(sc.source.candidateCount, 2);
    assert.equal(sc.runtime, undefined);
    assert.ok(['promote', 'hold', 'reject'].includes(sc.recommendation));
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('computeScorecard uses observed stage duration for single-lane runs', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scorecard-'));
  try {
    const monitor = new RunMonitor(dir);
    await monitor.prepare();
    await monitor.emitStageExit('source', 12_000);

    const manifest = makeManifest({ durationMs: 60_000, telemetrySummary: {
      totalCostUsd: 1.2,
      totalInputTokens: 100,
      totalOutputTokens: 50,
      invocationCount: 2,
    } });

    const sc = computeScorecard({
      runId: manifest.runId,
      profileId: manifest.profileId ?? null,
      configHash: manifest.configHash,
      targetId: manifest.targetId,
      manifest,
      monitor,
      sourceArtifact: makeSourceArtifact([{ id: 'c1', status: 'supported' }]),
    });

    assert.equal(sc.source?.durationMs, 12_000);
    assert.equal(sc.source?.costUsd, 1.2);
  } finally {
    await rm(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// renderScorecardMarkdown
// ---------------------------------------------------------------------------

test('renderScorecardMarkdown includes key sections', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scorecard-'));
  try {
    const monitor = new RunMonitor(dir);
    await monitor.prepare();

    const manifest = makeManifest();
    const sc = computeScorecard({
      runId: manifest.runId,
      profileId: 'qwen_default',
      configHash: manifest.configHash,
      targetId: manifest.targetId,
      manifest,
      monitor,
      sourceArtifact: makeSourceArtifact([{ id: 'c1', status: 'supported' }]),
    });

    const md = renderScorecardMarkdown(sc);
    assert.ok(md.includes('Parity Scorecard'));
    assert.ok(md.includes('qwen_default'));
    assert.ok(md.includes('Source Verification'));
    assert.ok(md.includes('Recommendation'));
  } finally {
    await rm(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// writeScorecard + readScorecard round-trip
// ---------------------------------------------------------------------------

test('writeScorecard + readScorecard round-trip', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scorecard-rw-'));
  try {
    const monitor = new RunMonitor(dir);
    await monitor.prepare();

    const manifest = makeManifest();
    const sc = computeScorecard({
      runId: manifest.runId,
      profileId: 'test_profile',
      configHash: manifest.configHash,
      targetId: manifest.targetId,
      manifest,
      monitor,
      sourceArtifact: makeSourceArtifact([{ id: 'c1', status: 'supported' }]),
    });

    const { jsonPath, mdPath } = await writeScorecard(dir, sc);
    const loaded = await readScorecard(jsonPath);

    assert.equal(loaded.runId, sc.runId);
    assert.equal(loaded.profileId, 'test_profile');
    assert.equal(loaded.recommendation, sc.recommendation);

    // Verify MD was written
    const md = await readFile(mdPath, 'utf8');
    assert.ok(md.includes('test_profile'));
  } finally {
    await rm(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// BenchmarkRegistry
// ---------------------------------------------------------------------------

test('BenchmarkRegistry CRUD round-trip', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bench-'));
  try {
    const registry = new BenchmarkRegistry('test-target', dir);
    await registry.prepare();

    const monitor = new RunMonitor(join(dir, 'output'));
    await monitor.prepare();

    const manifest = makeManifest();
    const sc = computeScorecard({
      runId: 'run-1',
      profileId: 'qwen_default',
      configHash: 'hash-a',
      targetId: 'test-target',
      manifest,
      monitor,
      sourceArtifact: makeSourceArtifact([{ id: 'c1', status: 'supported' }]),
    });

    await registry.recordRun({
      runId: 'run-1',
      label: 'smoke-1',
      profileId: 'qwen_default',
      configHash: 'hash-a',
      targetId: 'test-target',
      timestamp: new Date().toISOString(),
      manifestPath: '/tmp/manifest.json',
      scorecardPath: '/tmp/scorecard.json',
    }, sc);

    const runs = await registry.listRuns();
    assert.equal(runs.length, 1);
    assert.equal(runs[0].runId, 'run-1');
    assert.ok(runs[0].scorecardPath.endsWith('/runs/run-1.json'));

    // Baseline not yet promoted
    const baseline = await registry.getBaseline('hash-a');
    assert.equal(baseline, null);

    // Promote
    await registry.promoteBaseline('run-1');
    const promoted = await registry.getBaseline('hash-a');
    assert.ok(promoted);
    assert.equal(promoted.runId, 'run-1');
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('BenchmarkRegistry deduplicates runs', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bench-'));
  try {
    const registry = new BenchmarkRegistry('test-target', dir);
    await registry.prepare();

    const monitor = new RunMonitor(join(dir, 'output'));
    await monitor.prepare();

    const manifest = makeManifest();
    const sc = computeScorecard({
      runId: 'run-1',
      profileId: null,
      configHash: 'hash-a',
      targetId: 'test-target',
      manifest,
      monitor,
    });

    const entry = {
      runId: 'run-1',
      label: 'dup-test',
      profileId: null,
      configHash: 'hash-a',
      targetId: 'test-target',
      timestamp: new Date().toISOString(),
      manifestPath: '/tmp/manifest.json',
      scorecardPath: '/tmp/scorecard.json',
    };

    await registry.recordRun(entry, sc);
    await registry.recordRun(entry, sc);

    const runs = await registry.listRuns();
    assert.equal(runs.length, 1);
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('BenchmarkRegistry renderMatrixSummary with 2+ runs', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bench-'));
  try {
    const registry = new BenchmarkRegistry('test-target', dir);
    await registry.prepare();

    for (let i = 1; i <= 2; i++) {
      const monitor = new RunMonitor(join(dir, `output-${i}`));
      await monitor.prepare();

      const manifest = makeManifest({ runId: `run-${i}` });
      const sc = computeScorecard({
        runId: `run-${i}`,
        profileId: i === 1 ? 'qwen_default' : 'r1_source',
        configHash: `hash-${i}`,
        targetId: 'test-target',
        manifest,
        monitor,
        sourceArtifact: makeSourceArtifact([{ id: 'c1', status: 'supported' }]),
      });

      await registry.recordRun({
        runId: `run-${i}`,
        label: `label-${i}`,
        profileId: sc.profileId,
        configHash: `hash-${i}`,
        targetId: 'test-target',
        timestamp: new Date().toISOString(),
        manifestPath: '/tmp/manifest.json',
        scorecardPath: '/tmp/scorecard.json',
      }, sc);
    }

    const matrix = await registry.renderMatrixSummary();
    assert.ok(matrix.includes('Benchmark Matrix'));
    assert.ok(matrix.includes('qwen_default'));
    assert.ok(matrix.includes('r1_source'));
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('BenchmarkRegistry renderMatrixSummary returns empty for <2 runs', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bench-'));
  try {
    const registry = new BenchmarkRegistry('test-target', dir);
    await registry.prepare();
    const matrix = await registry.renderMatrixSummary();
    assert.equal(matrix, '');
  } finally {
    await rm(dir, { recursive: true });
  }
});
