import { z } from 'zod';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { LaneConfigSchema } from './verification-manifest.js';
import type { VerificationManifest } from './verification-manifest.js';
import type { SourceVerificationArtifact } from './source-verify-schemas.js';
import type { RuntimeVerificationArtifact } from './runtime-verify-schemas.js';
import type { RunMonitor } from './run-monitor.js';

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

export const SourceMetricsSchema = z.object({
  candidateCount: z.number(),
  parseSuccessRate: z.number(),
  formatStabilityRate: z.number(),
  gateRepairRate: z.number(),
  gateRepairsByClass: z.record(z.number()),
  proofObligationDowngradeCount: z.number(),
  statusDistribution: z.object({
    supported: z.number(),
    weakened: z.number(),
    refuted: z.number(),
    needs_runtime: z.number(),
  }),
  defenseCriticOverrideCount: z.number(),
  costUsd: z.number(),
  durationMs: z.number(),
});

export type SourceMetrics = z.infer<typeof SourceMetricsSchema>;

export const RuntimeMetricsSchema = z.object({
  candidateCount: z.number(),
  parseSuccessRate: z.number(),
  formatStabilityRate: z.number(),
  gateRepairRate: z.number(),
  gateRepairsByClass: z.record(z.number()),
  validatedCount: z.number(),
  blockedCount: z.number(),
  fabricatedEvidenceDowngradeCount: z.number(),
  validatorDowngradeCount: z.number(),
  pvrReadyCount: z.number(),
  statusDistribution: z.object({
    confirmed: z.number(),
    partially_confirmed: z.number(),
    not_reproducible: z.number(),
    blocked: z.number(),
    refuted: z.number(),
  }),
  dockerSetupSuccess: z.boolean(),
  costUsd: z.number(),
  durationMs: z.number(),
});

export type RuntimeMetrics = z.infer<typeof RuntimeMetricsSchema>;

export const BaselineDeltaSchema = z.object({
  formatStabilityDelta: z.number().optional(),
  parseSuccessRateDelta: z.number().optional(),
  gateRepairRateDelta: z.number().optional(),
  proofObligationDowngradeDelta: z.number().optional(),
  validatorDowngradeDelta: z.number().optional(),
  costDelta: z.number().optional(),
  durationDelta: z.number().optional(),
});

export const FrontierDeltaSchema = z.object({
  formatStabilityDelta: z.number().optional(),
  parseSuccessRateDelta: z.number().optional(),
  validatorDowngradeDelta: z.number().optional(),
  costDelta: z.number().optional(),
});

export const ParityScorecardSchema = z.object({
  schemaVersion: z.literal(1),
  runId: z.string(),
  profileId: z.string().nullable(),
  configHash: z.string(),
  targetId: z.string(),
  timestamp: z.string(),

  source: SourceMetricsSchema.optional(),
  runtime: RuntimeMetricsSchema.optional(),

  totalCostUsd: z.number(),
  totalDurationMs: z.number(),
  lanes: z.object({
    source: LaneConfigSchema.optional(),
    runtime: LaneConfigSchema.optional(),
    sourceCritic: LaneConfigSchema.optional(),
    runtimeSetup: LaneConfigSchema.optional(),
    runtimeProbe: LaneConfigSchema.optional(),
  }),

  baselineDelta: BaselineDeltaSchema.nullable(),
  frontierDelta: FrontierDeltaSchema.nullable(),

  recommendation: z.enum(['promote', 'hold', 'reject']),
  recommendationReason: z.string(),
  anomalyCount: z.number(),
  anomalySummary: z.array(z.string()),
});

export type ParityScorecard = z.infer<typeof ParityScorecardSchema>;

// ---------------------------------------------------------------------------
// Source metrics computation
// ---------------------------------------------------------------------------

function countGateRepairsByClass(
  events: Array<{ kind: string; stage?: string; detail?: Record<string, unknown> }>,
  stage: 'source' | 'runtime',
): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const event of events) {
    if (event.kind !== 'gate_repair' || event.stage !== stage || !event.detail) continue;
    const failureClass = event.detail.failureClass;
    if (typeof failureClass !== 'string') continue;
    counts[failureClass] = (counts[failureClass] ?? 0) + 1;
  }
  return counts;
}

function getStageDurationMs(
  monitor: RunMonitor,
  stage: 'source' | 'runtime',
): number | undefined {
  const exitEvents = monitor
    .getEvents()
    .filter((e) => e.kind === 'stage_exit' && e.stage === stage && typeof e.durationMs === 'number');
  if (exitEvents.length === 0) return undefined;
  return exitEvents.reduce((sum, event) => sum + (event.durationMs ?? 0), 0);
}

function splitDurationAndCost(
  manifest: VerificationManifest,
  monitor: RunMonitor,
  hasSource: boolean,
  hasRuntime: boolean,
): {
  sourceDurationMs: number;
  runtimeDurationMs: number;
  sourceCostUsd: number;
  runtimeCostUsd: number;
} {
  const totalDurationMs = manifest.durationMs ?? 0;
  const totalCostUsd = manifest.telemetrySummary?.totalCostUsd ?? 0;

  if (hasSource && !hasRuntime) {
    const sourceDurationMs = getStageDurationMs(monitor, 'source') ?? totalDurationMs;
    return {
      sourceDurationMs,
      runtimeDurationMs: 0,
      sourceCostUsd: totalCostUsd,
      runtimeCostUsd: 0,
    };
  }

  if (!hasSource && hasRuntime) {
    const runtimeDurationMs = getStageDurationMs(monitor, 'runtime') ?? totalDurationMs;
    return {
      sourceDurationMs: 0,
      runtimeDurationMs,
      sourceCostUsd: 0,
      runtimeCostUsd: totalCostUsd,
    };
  }

  const observedSourceDurationMs = getStageDurationMs(monitor, 'source');
  const observedRuntimeDurationMs = getStageDurationMs(monitor, 'runtime');
  const sourceDurationMs =
    observedSourceDurationMs ??
    (observedRuntimeDurationMs !== undefined ? Math.max(0, totalDurationMs - observedRuntimeDurationMs) : Math.round(totalDurationMs * 0.5));
  const runtimeDurationMs =
    observedRuntimeDurationMs ??
    (observedSourceDurationMs !== undefined ? Math.max(0, totalDurationMs - observedSourceDurationMs) : totalDurationMs - sourceDurationMs);
  const durationDenominator = sourceDurationMs + runtimeDurationMs;

  if (durationDenominator <= 0) {
    return {
      sourceDurationMs,
      runtimeDurationMs,
      sourceCostUsd: totalCostUsd * 0.5,
      runtimeCostUsd: totalCostUsd * 0.5,
    };
  }

  return {
    sourceDurationMs,
    runtimeDurationMs,
    sourceCostUsd: totalCostUsd * (sourceDurationMs / durationDenominator),
    runtimeCostUsd: totalCostUsd * (runtimeDurationMs / durationDenominator),
  };
}

export function computeSourceMetrics(
  artifact: SourceVerificationArtifact,
  monitor: RunMonitor,
  durationMs: number,
  costUsd: number,
): SourceMetrics {
  const all = [...artifact.candidates, ...(artifact.auditFindings ?? [])];
  const candidateCount = all.length;

  const events = monitor.getEvents();
  const sourceStarts = events.filter((e) => e.kind === 'candidate_start' && e.stage === 'source');
  const sourceEnds = events.filter((e) => e.kind === 'candidate_end' && e.stage === 'source');
  const parseSuccessCount = sourceEnds.filter((e) => e.detail?.error !== 'parse_failure').length;
  const parseSuccessRate = sourceStarts.length > 0 ? parseSuccessCount / sourceStarts.length : 1;

  // Format stability: monitored source candidates with zero gate_repair events.
  const processedCandidateCount = sourceStarts.length > 0 ? sourceStarts.length : artifact.candidates.length;
  const sourceGateRepairs = events.filter(
    (e) => e.kind === 'gate_repair' && e.stage === 'source' && e.candidateId,
  );
  const candidatesWithRepairs = new Set(sourceGateRepairs.map((e) => e.candidateId));
  const stableCandidates = processedCandidateCount - candidatesWithRepairs.size;
  const formatStabilityRate = processedCandidateCount > 0 ? stableCandidates / processedCandidateCount : 1;
  const gateRepairRate = processedCandidateCount > 0 ? candidatesWithRepairs.size / processedCandidateCount : 0;
  const gateRepairsByClass = countGateRepairsByClass(events, 'source');

  // Proof obligation downgrades
  const downgrades = events.filter(
    (e) => e.kind === 'validator_downgrade' && e.stage === 'source' && e.detail?.from,
  );
  const proofObligationDowngradeCount = downgrades.length;

  // Status distribution
  const statusDistribution = { supported: 0, weakened: 0, refuted: 0, needs_runtime: 0 };
  for (const c of all) {
    if (c.status in statusDistribution) {
      statusDistribution[c.status as keyof typeof statusDistribution]++;
    }
  }

  // Defense critic overrides
  const defenseCriticOverrideCount = all.filter((c) => c.preCriticStatus !== undefined).length;

  return {
    candidateCount,
    parseSuccessRate,
    formatStabilityRate,
    gateRepairRate,
    gateRepairsByClass,
    proofObligationDowngradeCount,
    statusDistribution,
    defenseCriticOverrideCount,
    costUsd,
    durationMs,
  };
}

// ---------------------------------------------------------------------------
// Runtime metrics computation
// ---------------------------------------------------------------------------

export function computeRuntimeMetrics(
  artifact: RuntimeVerificationArtifact,
  monitor: RunMonitor,
  durationMs: number,
  costUsd: number,
): RuntimeMetrics {
  const candidates = artifact.candidates;
  const candidateCount = candidates.length;

  const events = monitor.getEvents();
  const runtimeStarts = events.filter((e) => e.kind === 'candidate_start' && e.stage === 'runtime');
  const runtimeEnds = events.filter((e) => e.kind === 'candidate_end' && e.stage === 'runtime');
  const parseSuccessCount = runtimeEnds.filter((e) => e.detail?.error !== 'parse_failure').length;
  const parseSuccessRate = runtimeStarts.length > 0 ? parseSuccessCount / runtimeStarts.length : 1;

  const processedCandidateCount = runtimeStarts.length > 0 ? runtimeStarts.length : candidateCount;
  const runtimeGateRepairs = events.filter(
    (e) => e.kind === 'gate_repair' && e.stage === 'runtime' && e.candidateId,
  );
  const candidatesWithRepairs = new Set(runtimeGateRepairs.map((e) => e.candidateId));
  const stableCandidates = processedCandidateCount - candidatesWithRepairs.size;
  const formatStabilityRate = processedCandidateCount > 0 ? stableCandidates / processedCandidateCount : 1;
  const gateRepairRate = processedCandidateCount > 0 ? candidatesWithRepairs.size / processedCandidateCount : 0;
  const gateRepairsByClass = countGateRepairsByClass(events, 'runtime');

  const validatedCount = candidates.filter((c) => c.validatedResult.status !== 'blocked').length;
  const blockedCount = candidates.filter((c) => c.validatedResult.status === 'blocked').length;
  const validatorDowngradeCount = candidates.filter((c) => c.wasDowngraded).length;
  const fabricatedEvidenceDowngradeCount = candidates.filter(
    (c) => c.validationNotes.some((n) => n.rule.includes('fabricat')),
  ).length;
  const pvrReadyCount = candidates.filter((c) => c.validatedResult.pvrReady).length;

  const statusDistribution = {
    confirmed: 0,
    partially_confirmed: 0,
    not_reproducible: 0,
    blocked: 0,
    refuted: 0,
  };
  for (const c of candidates) {
    const s = c.validatedResult.status;
    if (s in statusDistribution) {
      statusDistribution[s as keyof typeof statusDistribution]++;
    }
  }

  return {
    candidateCount,
    parseSuccessRate,
    formatStabilityRate,
    gateRepairRate,
    gateRepairsByClass,
    validatedCount,
    blockedCount,
    fabricatedEvidenceDowngradeCount,
    validatorDowngradeCount,
    pvrReadyCount,
    statusDistribution,
    dockerSetupSuccess: artifact.dockerSetupSuccess,
    costUsd,
    durationMs,
  };
}

// ---------------------------------------------------------------------------
// Delta computation
// ---------------------------------------------------------------------------

function computeBaselineDelta(
  current: ParityScorecard,
  baseline: ParityScorecard,
): z.infer<typeof BaselineDeltaSchema> {
  const delta: z.infer<typeof BaselineDeltaSchema> = {};

  const cs = current.source;
  const bs = baseline.source;
  if (cs && bs) {
    delta.formatStabilityDelta = cs.formatStabilityRate - bs.formatStabilityRate;
    delta.parseSuccessRateDelta = cs.parseSuccessRate - bs.parseSuccessRate;
    delta.gateRepairRateDelta = cs.gateRepairRate - bs.gateRepairRate;
    delta.proofObligationDowngradeDelta = cs.proofObligationDowngradeCount - bs.proofObligationDowngradeCount;
  }

  const cr = current.runtime;
  const br = baseline.runtime;
  if (cr && br) {
    delta.validatorDowngradeDelta = cr.validatorDowngradeCount - br.validatorDowngradeCount;
  }

  delta.costDelta = current.totalCostUsd - baseline.totalCostUsd;
  delta.durationDelta = current.totalDurationMs - baseline.totalDurationMs;

  return delta;
}

function computeFrontierDelta(
  current: ParityScorecard,
  frontier: ParityScorecard,
): z.infer<typeof FrontierDeltaSchema> {
  const delta: z.infer<typeof FrontierDeltaSchema> = {};

  if (current.source && frontier.source) {
    delta.formatStabilityDelta = current.source.formatStabilityRate - frontier.source.formatStabilityRate;
    delta.parseSuccessRateDelta = current.source.parseSuccessRate - frontier.source.parseSuccessRate;
  }

  if (current.runtime && frontier.runtime) {
    delta.validatorDowngradeDelta = current.runtime.validatorDowngradeCount - frontier.runtime.validatorDowngradeCount;
  }

  delta.costDelta = current.totalCostUsd - frontier.totalCostUsd;

  return delta;
}

// ---------------------------------------------------------------------------
// Recommendation engine
// ---------------------------------------------------------------------------

export function deriveRecommendation(
  scorecard: ParityScorecard,
  baseline?: ParityScorecard | null,
): { recommendation: 'promote' | 'hold' | 'reject'; reason: string } {
  const sourceCandidates = scorecard.source?.candidateCount ?? 0;
  const runtimeCandidatesTotal = scorecard.runtime?.candidateCount ?? 0;

  // A run that processed nothing has no evidence to promote on: the missing
  // rates below default to 1, which would otherwise read as a clean run.
  // Rejection thresholds still apply — this only blocks promotion.
  const noEvidence = sourceCandidates + runtimeCandidatesTotal === 0;
  const noEvidenceHold = {
    recommendation: 'hold' as const,
    reason: 'No candidates were processed — nothing to promote',
  };

  const sourceFs = scorecard.source?.formatStabilityRate ?? 1;
  const sourcePs = scorecard.source?.parseSuccessRate ?? 1;
  const runtimeFs = scorecard.runtime?.formatStabilityRate ?? 1;
  const runtimePs = scorecard.runtime?.parseSuccessRate ?? 1;

  const effectiveFs = Math.min(sourceFs, runtimeFs);
  const effectivePs = Math.min(sourcePs, runtimePs);

  const runtimeCandidates = scorecard.runtime?.candidateCount ?? 0;
  const fabricated = scorecard.runtime?.fabricatedEvidenceDowngradeCount ?? 0;
  const fabricationRate = runtimeCandidates > 0 ? fabricated / runtimeCandidates : 0;

  // Reject thresholds
  if (effectiveFs < 0.5) {
    return { recommendation: 'reject', reason: `Format stability ${(effectiveFs * 100).toFixed(0)}% below 50% threshold` };
  }
  if (effectivePs < 0.6) {
    return { recommendation: 'reject', reason: `Parse success rate ${(effectivePs * 100).toFixed(0)}% below 60% threshold` };
  }
  if (fabricationRate > 0.3) {
    return { recommendation: 'reject', reason: `Evidence fabrication rate ${(fabricationRate * 100).toFixed(0)}% exceeds 30% threshold` };
  }

  // Hold thresholds (baseline comparison)
  if (baseline) {
    const delta = scorecard.baselineDelta;
    if (delta) {
      if (delta.formatStabilityDelta !== undefined && delta.formatStabilityDelta < -0.1) {
        return { recommendation: 'hold', reason: `Format stability regressed ${(delta.formatStabilityDelta * 100).toFixed(0)}pp vs baseline` };
      }
      if (delta.parseSuccessRateDelta !== undefined && delta.parseSuccessRateDelta < -0.1) {
        return { recommendation: 'hold', reason: `Parse success rate regressed ${(delta.parseSuccessRateDelta * 100).toFixed(0)}pp vs baseline` };
      }
    }
  }

  if (scorecard.anomalyCount > 3) {
    return { recommendation: 'hold', reason: `${scorecard.anomalyCount} anomalies detected (threshold: 3)` };
  }

  // No baseline: qualify for promote
  if (!baseline) {
    if (noEvidence) {
      return noEvidenceHold;
    }
    if (effectiveFs >= 0.7 && effectivePs >= 0.8) {
      return { recommendation: 'promote', reason: 'Meets promotion thresholds without baseline' };
    }
    return { recommendation: 'hold', reason: `No baseline and metrics below auto-promote thresholds (fs=${(effectiveFs * 100).toFixed(0)}%, ps=${(effectivePs * 100).toFixed(0)}%)` };
  }

  if (noEvidence) {
    return noEvidenceHold;
  }
  return { recommendation: 'promote', reason: 'Meets all thresholds and no regressions vs baseline' };
}

// ---------------------------------------------------------------------------
// Main computation
// ---------------------------------------------------------------------------

export interface ComputeScorecardOptions {
  runId: string;
  profileId: string | null;
  configHash: string;
  targetId: string;
  manifest: VerificationManifest;
  monitor: RunMonitor;
  sourceArtifact?: SourceVerificationArtifact;
  runtimeArtifact?: RuntimeVerificationArtifact;
  baseline?: ParityScorecard | null;
  frontierReference?: ParityScorecard | null;
}

export function computeScorecard(opts: ComputeScorecardOptions): ParityScorecard {
  const durationMs = opts.manifest.durationMs ?? 0;
  const costUsd = opts.manifest.telemetrySummary?.totalCostUsd ?? 0;
  const split = splitDurationAndCost(
    opts.manifest,
    opts.monitor,
    Boolean(opts.sourceArtifact),
    Boolean(opts.runtimeArtifact),
  );

  const sourceMetrics = opts.sourceArtifact
    ? computeSourceMetrics(opts.sourceArtifact, opts.monitor, split.sourceDurationMs, split.sourceCostUsd)
    : undefined;

  const runtimeMetrics = opts.runtimeArtifact
    ? computeRuntimeMetrics(opts.runtimeArtifact, opts.monitor, split.runtimeDurationMs, split.runtimeCostUsd)
    : undefined;

  const anomalies = opts.monitor.getAnomalies();

  const partial: Omit<ParityScorecard, 'recommendation' | 'recommendationReason'> = {
    schemaVersion: 1,
    runId: opts.runId,
    profileId: opts.profileId,
    configHash: opts.configHash,
    targetId: opts.targetId,
    timestamp: new Date().toISOString(),
    source: sourceMetrics,
    runtime: runtimeMetrics,
    totalCostUsd: costUsd,
    totalDurationMs: durationMs,
    lanes: opts.manifest.lanes,
    baselineDelta: null,
    frontierDelta: null,
    anomalyCount: anomalies.length,
    anomalySummary: anomalies.map((a) => `[${a.severity}] ${a.kind}: ${a.detail}`),
  };

  // Compute deltas after building partial scorecard
  const scorecardForDelta = partial as ParityScorecard;
  if (opts.baseline) {
    (partial as ParityScorecard).baselineDelta = computeBaselineDelta(scorecardForDelta, opts.baseline);
  }
  if (opts.frontierReference) {
    (partial as ParityScorecard).frontierDelta = computeFrontierDelta(scorecardForDelta, opts.frontierReference);
  }

  const { recommendation, reason } = deriveRecommendation(
    scorecardForDelta,
    opts.baseline,
  );

  return {
    ...partial,
    recommendation,
    recommendationReason: reason,
  };
}

// ---------------------------------------------------------------------------
// Markdown rendering
// ---------------------------------------------------------------------------

export function renderScorecardMarkdown(sc: ParityScorecard): string {
  const lines: string[] = [];
  lines.push(`# Parity Scorecard — ${sc.targetId}`);
  lines.push('');
  lines.push(`| Field | Value |`);
  lines.push(`|-------|-------|`);
  lines.push(`| Run ID | ${sc.runId} |`);
  lines.push(`| Profile | ${sc.profileId ?? '(ad-hoc)'} |`);
  lines.push(`| Config Hash | ${sc.configHash} |`);
  lines.push(`| Timestamp | ${sc.timestamp} |`);
  lines.push(`| Recommendation | **${sc.recommendation.toUpperCase()}** |`);
  lines.push(`| Reason | ${sc.recommendationReason} |`);
  lines.push(`| Total Cost | $${sc.totalCostUsd.toFixed(4)} |`);
  lines.push(`| Total Duration | ${Math.round(sc.totalDurationMs / 1000)}s |`);
  lines.push(`| Anomalies | ${sc.anomalyCount} |`);
  lines.push('');

  if (sc.source) {
    lines.push('## Source Verification');
    lines.push('');
    lines.push(`| Metric | Value |`);
    lines.push(`|--------|-------|`);
    lines.push(`| Candidates | ${sc.source.candidateCount} |`);
    lines.push(`| Parse Success | ${(sc.source.parseSuccessRate * 100).toFixed(0)}% |`);
    lines.push(`| Format Stability | ${(sc.source.formatStabilityRate * 100).toFixed(0)}% |`);
    lines.push(`| Gate Repair Rate | ${(sc.source.gateRepairRate * 100).toFixed(0)}% |`);
    lines.push(`| Proof Downgrades | ${sc.source.proofObligationDowngradeCount} |`);
    lines.push(`| Critic Overrides | ${sc.source.defenseCriticOverrideCount} |`);
    lines.push(`| supported | ${sc.source.statusDistribution.supported} |`);
    lines.push(`| weakened | ${sc.source.statusDistribution.weakened} |`);
    lines.push(`| refuted | ${sc.source.statusDistribution.refuted} |`);
    lines.push(`| needs_runtime | ${sc.source.statusDistribution.needs_runtime} |`);
    lines.push('');
  }

  if (sc.runtime) {
    lines.push('## Runtime Verification');
    lines.push('');
    lines.push(`| Metric | Value |`);
    lines.push(`|--------|-------|`);
    lines.push(`| Candidates | ${sc.runtime.candidateCount} |`);
    lines.push(`| Parse Success | ${(sc.runtime.parseSuccessRate * 100).toFixed(0)}% |`);
    lines.push(`| Format Stability | ${(sc.runtime.formatStabilityRate * 100).toFixed(0)}% |`);
    lines.push(`| Gate Repair Rate | ${(sc.runtime.gateRepairRate * 100).toFixed(0)}% |`);
    lines.push(`| Docker Setup | ${sc.runtime.dockerSetupSuccess ? 'OK' : 'FAILED'} |`);
    lines.push(`| Validated | ${sc.runtime.validatedCount} |`);
    lines.push(`| Blocked | ${sc.runtime.blockedCount} |`);
    lines.push(`| PVR Ready | ${sc.runtime.pvrReadyCount} |`);
    lines.push(`| Validator Downgrades | ${sc.runtime.validatorDowngradeCount} |`);
    lines.push(`| Fabrication Downgrades | ${sc.runtime.fabricatedEvidenceDowngradeCount} |`);
    lines.push(`| confirmed | ${sc.runtime.statusDistribution.confirmed} |`);
    lines.push(`| partially_confirmed | ${sc.runtime.statusDistribution.partially_confirmed} |`);
    lines.push(`| not_reproducible | ${sc.runtime.statusDistribution.not_reproducible} |`);
    lines.push(`| blocked | ${sc.runtime.statusDistribution.blocked} |`);
    lines.push(`| refuted | ${sc.runtime.statusDistribution.refuted} |`);
    lines.push('');
  }

  if (sc.baselineDelta) {
    lines.push('## Baseline Delta');
    lines.push('');
    lines.push(`| Metric | Delta |`);
    lines.push(`|--------|-------|`);
    for (const [key, value] of Object.entries(sc.baselineDelta)) {
      if (value !== undefined) {
        const formatted = key.includes('Delta') && !key.includes('cost') && !key.includes('duration')
          ? `${value > 0 ? '+' : ''}${(value * 100).toFixed(1)}pp`
          : `${value > 0 ? '+' : ''}${typeof value === 'number' ? value.toFixed(2) : value}`;
        lines.push(`| ${key} | ${formatted} |`);
      }
    }
    lines.push('');
  }

  if (sc.anomalyCount > 0) {
    lines.push('## Anomalies');
    lines.push('');
    for (const a of sc.anomalySummary) {
      lines.push(`- ${a}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

export async function writeScorecard(
  outputDir: string,
  scorecard: ParityScorecard,
): Promise<{ jsonPath: string; mdPath: string }> {
  const jsonPath = resolve(outputDir, 'scorecard.json');
  const mdPath = resolve(outputDir, 'scorecard.md');
  await writeFile(jsonPath, JSON.stringify(scorecard, null, 2), 'utf8');
  await writeFile(mdPath, renderScorecardMarkdown(scorecard), 'utf8');
  return { jsonPath, mdPath };
}

export async function readScorecard(path: string): Promise<ParityScorecard> {
  const raw = await readFile(path, 'utf8');
  return ParityScorecardSchema.parse(JSON.parse(raw));
}
