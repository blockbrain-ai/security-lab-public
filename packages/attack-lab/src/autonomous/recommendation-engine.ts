import { z } from 'zod';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { SourceVerificationArtifact, SourceVerificationResult } from './source-verify-schemas.js';
import type { RuntimeVerificationArtifact } from './runtime-verify-schemas.js';
import type { RunMonitor } from './run-monitor.js';
import type { ParityScorecard } from './parity-scorecard.js';

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

export const RecommendationClassSchema = z.enum([
  'missing_runtime_capability',
  'source_precision_gap',
  'defense_reasoning_gap',
  'format_stability_gap',
  'docker_environment_gap',
  'regression_from_baseline',
]);
export type RecommendationClass = z.infer<typeof RecommendationClassSchema>;

export const RecommendationSchema = z.object({
  id: z.string(),
  class: RecommendationClassSchema,
  priority: z.enum(['critical', 'high', 'medium', 'low']),
  title: z.string(),
  detail: z.string(),
  metrics: z.record(z.union([z.string(), z.number(), z.boolean()])),
  affectedCandidates: z.array(z.string()).default([]),
  suggestedAction: z.string(),
});
export type Recommendation = z.infer<typeof RecommendationSchema>;

export const RecommendationSummarySchema = z.object({
  generatedAt: z.string(),
  campaignId: z.string().optional(),
  targetId: z.string(),
  recommendations: z.array(RecommendationSchema),
  metrics: z.object({
    totalCandidates: z.number(),
    sourceVerified: z.number(),
    runtimeVerified: z.number(),
    gateFailures: z.number(),
    downgrades: z.number(),
    pvrReady: z.number(),
    costUsd: z.number(),
  }),
});
export type RecommendationSummary = z.infer<typeof RecommendationSummarySchema>;

// ---------------------------------------------------------------------------
// Detector functions — pure, no model calls
// ---------------------------------------------------------------------------

export function detectMissingRuntimeCapability(
  sourceArtifact?: SourceVerificationArtifact,
  runtimeArtifact?: RuntimeVerificationArtifact,
): Recommendation[] {
  if (!sourceArtifact) return [];

  const allSource = [
    ...sourceArtifact.candidates,
    ...(sourceArtifact.auditFindings ?? []),
  ];
  const runtimeCandidateIds = new Set(
    (runtimeArtifact?.candidates ?? []).map(c => c.validatedResult.candidateId),
  );

  const recs: Recommendation[] = [];

  // Source-supported but no runtime result at all
  const supportedNoRuntime = allSource.filter(c =>
    c.status === 'supported' && !runtimeCandidateIds.has(c.candidateId),
  );
  if (supportedNoRuntime.length > 0) {
    recs.push({
      id: 'mrc-no-runtime-for-supported',
      class: 'missing_runtime_capability',
      priority: supportedNoRuntime.some(c => c.reviewPolicy?.riskTier === 'critical') ? 'critical' : 'high',
      title: `${supportedNoRuntime.length} source-supported finding(s) lack runtime verification`,
      detail: 'Source verification marked these as supported, but no runtime verification was attempted.',
      metrics: { count: supportedNoRuntime.length },
      affectedCandidates: supportedNoRuntime.map(c => c.candidateId),
      suggestedAction: 'Run full mode (--verification-mode full) to add runtime verification for these findings.',
    });
  }

  // Source requires runtime but runtime blocked/not_reproducible
  if (runtimeArtifact) {
    const blockedOrFailed = runtimeArtifact.candidates.filter(c => {
      const vr = c.validatedResult;
      const sourceMatch = allSource.find(s => s.candidateId === vr.candidateId);
      if (!sourceMatch) return false;
      if (sourceMatch.status !== 'supported' && sourceMatch.status !== 'needs_runtime') return false;
      return vr.status === 'blocked' || vr.status === 'not_reproducible';
    });

    if (blockedOrFailed.length > 0) {
      const critical = blockedOrFailed.filter(c => {
        const src = allSource.find(s => s.candidateId === c.validatedResult.candidateId);
        return src?.reviewPolicy?.riskTier === 'critical';
      });
      recs.push({
        id: 'mrc-runtime-blocked',
        class: 'missing_runtime_capability',
        priority: critical.length > 0 ? 'critical' : 'high',
        title: `${blockedOrFailed.length} finding(s) blocked or not reproducible at runtime`,
        detail: 'Source supported these but runtime could not confirm them.',
        metrics: {
          blocked: blockedOrFailed.filter(c => c.validatedResult.status === 'blocked').length,
          notReproducible: blockedOrFailed.filter(c => c.validatedResult.status === 'not_reproducible').length,
        },
        affectedCandidates: blockedOrFailed.map(c => c.validatedResult.candidateId),
        suggestedAction: 'Check Docker setup logs. Ensure the target service is correctly configured and reachable.',
      });
    }
  }

  // Findings where reviewPolicy.requireRuntime but no runtime verification exists
  if (!runtimeArtifact) {
    const requireRuntime = allSource.filter(c => c.reviewPolicy?.requireRuntime);
    if (requireRuntime.length > 0) {
      recs.push({
        id: 'mrc-policy-requires-runtime',
        class: 'missing_runtime_capability',
        priority: requireRuntime.some(c => c.reviewPolicy?.hardFailOnMiss) ? 'critical' : 'high',
        title: `${requireRuntime.length} finding(s) require runtime verification per review policy`,
        detail: 'Review policy flags these for mandatory runtime but only source verification was run.',
        metrics: { count: requireRuntime.length },
        affectedCandidates: requireRuntime.map(c => c.candidateId),
        suggestedAction: 'Re-run with --verification-mode full to satisfy review policy requirements.',
      });
    }
  }

  return recs;
}

export function detectSourcePrecisionGap(
  sourceArtifact?: SourceVerificationArtifact,
): Recommendation[] {
  if (!sourceArtifact) return [];

  const allSource = [
    ...sourceArtifact.candidates,
    ...(sourceArtifact.auditFindings ?? []),
  ];

  const weakGrounding: SourceVerificationResult[] = [];

  for (const c of allSource) {
    if (c.status !== 'supported') continue;
    const hasLineRefs = c.sourceRefs.some(r => r.line !== undefined);
    if (!hasLineRefs || c.confidence < 0.5 || c.sourceRefs.length < 1) {
      weakGrounding.push(c);
    }
  }

  if (weakGrounding.length === 0) return [];

  return [{
    id: 'spg-weak-grounding',
    class: 'source_precision_gap',
    priority: 'medium',
    title: `${weakGrounding.length} supported finding(s) with weak source grounding`,
    detail: 'Supported findings that lack line-specific references, have low confidence, or insufficient sourceRefs.',
    metrics: {
      count: weakGrounding.length,
      avgConfidence: weakGrounding.reduce((s, c) => s + c.confidence, 0) / weakGrounding.length,
    },
    affectedCandidates: weakGrounding.map(c => c.candidateId),
    suggestedAction: 'Review these findings manually. Low-grounding supported findings may be false positives.',
  }];
}

export function detectDefenseReasoningGap(
  sourceArtifact?: SourceVerificationArtifact,
): Recommendation[] {
  if (!sourceArtifact) return [];

  const allSource = [
    ...sourceArtifact.candidates,
    ...(sourceArtifact.auditFindings ?? []),
  ];

  const downgraded = allSource.filter(c =>
    c.defenseMechanismsObserved.length > 0 &&
    c.preValidationStatus !== undefined &&
    c.status === 'needs_runtime',
  );

  if (downgraded.length === 0) return [];

  return [{
    id: 'drg-defended-downgraded',
    class: 'defense_reasoning_gap',
    priority: 'high',
    title: `${downgraded.length} defended finding(s) downgraded to needs_runtime`,
    detail: 'Findings with observed defenses were downgraded because proof obligations were not met.',
    metrics: { count: downgraded.length },
    affectedCandidates: downgraded.map(c => c.candidateId),
    suggestedAction: 'Runtime verification needed to determine if defenses are actually effective.',
  }];
}

export function detectFormatStabilityGap(
  monitor?: RunMonitor,
): Recommendation[] {
  if (!monitor) return [];

  const repairsByClass = monitor.getGateRepairsByClass();
  const recs: Recommendation[] = [];

  let formatJsonCount = 0;
  let schemaMismatchCount = 0;
  let fabricatedCount = 0;

  for (const [className, stats] of Object.entries(repairsByClass)) {
    if (
      className === 'format_no_json' ||
      className === 'format_markdown_wrapped' ||
      className === 'format_invalid_json' ||
      className === 'format_truncated'
    ) {
      formatJsonCount += stats.total;
    } else if (
      className === 'format_schema_mismatch' ||
      className === 'schema_mismatch' ||
      className === 'partial_schema_mismatch'
    ) {
      schemaMismatchCount += stats.total;
    } else if (className === 'evidence_fabricated') {
      fabricatedCount += stats.total;
    }
  }

  if (formatJsonCount >= 3) {
    recs.push({
      id: 'fsg-format-json',
      class: 'format_stability_gap',
      priority: 'medium',
      title: `${formatJsonCount} JSON format repair(s) needed`,
      detail: 'Model produced non-JSON or markdown-wrapped output requiring gate repair.',
      metrics: { formatJsonRepairs: formatJsonCount },
      affectedCandidates: [],
      suggestedAction: 'Consider switching to a model with better structured JSON output, or tighten system prompt instructions.',
    });
  }

  if (schemaMismatchCount >= 2) {
    recs.push({
      id: 'fsg-schema-mismatch',
      class: 'format_stability_gap',
      priority: 'medium',
      title: `${schemaMismatchCount} schema mismatch repair(s) needed`,
      detail: 'Model output parsed as JSON but did not match the expected Zod schema.',
      metrics: { schemaMismatchRepairs: schemaMismatchCount },
      affectedCandidates: [],
      suggestedAction: 'Review model output format compliance. May need prompt tuning or a different model.',
    });
  }

  if (fabricatedCount > 0) {
    recs.push({
      id: 'fsg-fabrication',
      class: 'format_stability_gap',
      priority: 'high',
      title: `${fabricatedCount} evidence fabrication detection(s)`,
      detail: 'Model output was flagged for fabricated evidence by the mechanical validator.',
      metrics: { fabricationCount: fabricatedCount },
      affectedCandidates: [],
      suggestedAction: 'Investigate which candidates had fabricated evidence. Model may need stronger grounding constraints.',
    });
  }

  return recs;
}

export function detectDockerEnvironmentGap(
  runtimeArtifact?: RuntimeVerificationArtifact,
): Recommendation[] {
  if (!runtimeArtifact) return [];

  const recs: Recommendation[] = [];

  if (!runtimeArtifact.dockerSetupSuccess) {
    recs.push({
      id: 'deg-docker-setup-failed',
      class: 'docker_environment_gap',
      priority: 'high',
      title: 'Docker setup failed',
      detail: runtimeArtifact.dockerSetupLog ?? 'Docker setup did not succeed. All candidates blocked.',
      metrics: {
        blockedCandidates: runtimeArtifact.candidates.filter(c => c.validatedResult.status === 'blocked').length,
      },
      affectedCandidates: runtimeArtifact.candidates.map(c => c.validatedResult.candidateId),
      suggestedAction: 'Fix Docker environment. Check compose files, .env configuration, and Docker Desktop status.',
    });
    return recs;
  }

  const blocked = runtimeArtifact.candidates.filter(c => c.validatedResult.status === 'blocked');
  if (blocked.length === runtimeArtifact.candidates.length && blocked.length > 0) {
    recs.push({
      id: 'deg-all-blocked',
      class: 'docker_environment_gap',
      priority: 'high',
      title: 'All runtime candidates blocked despite Docker setup succeeding',
      detail: 'Docker appeared to start but no candidates could be verified.',
      metrics: { blockedCount: blocked.length },
      affectedCandidates: blocked.map(c => c.validatedResult.candidateId),
      suggestedAction: 'Check if the service is actually reachable. Verify ports, health checks, and startup timing.',
    });
  }

  return recs;
}

export function detectRegressionFromBaseline(
  scorecard?: ParityScorecard,
  baseline?: ParityScorecard | null,
): Recommendation[] {
  if (!scorecard || !baseline) return [];

  const recs: Recommendation[] = [];
  const delta = scorecard.baselineDelta;
  if (!delta) return [];

  const regressions: string[] = [];

  if (delta.formatStabilityDelta !== undefined && delta.formatStabilityDelta < -0.1) {
    regressions.push(`format stability dropped ${(delta.formatStabilityDelta * 100).toFixed(0)}%`);
  }
  if (delta.parseSuccessRateDelta !== undefined && delta.parseSuccessRateDelta < -0.1) {
    regressions.push(`parse success dropped ${(delta.parseSuccessRateDelta * 100).toFixed(0)}%`);
  }
  if (delta.validatorDowngradeDelta !== undefined && delta.validatorDowngradeDelta > 2) {
    regressions.push(`validator downgrades increased by ${delta.validatorDowngradeDelta}`);
  }
  if (delta.proofObligationDowngradeDelta !== undefined && delta.proofObligationDowngradeDelta > 2) {
    regressions.push(`proof obligation downgrades increased by ${delta.proofObligationDowngradeDelta}`);
  }

  if (regressions.length > 0) {
    recs.push({
      id: 'rfb-regression',
      class: 'regression_from_baseline',
      priority: 'critical',
      title: `${regressions.length} regression(s) from baseline detected`,
      detail: regressions.join('; '),
      metrics: {
        formatStabilityDelta: delta.formatStabilityDelta ?? 0,
        parseSuccessRateDelta: delta.parseSuccessRateDelta ?? 0,
      },
      affectedCandidates: [],
      suggestedAction: 'Compare run artifacts against the baseline. Consider reverting model/profile changes.',
    });
  }

  return recs;
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

export interface GenerateRecommendationsOpts {
  targetId: string;
  campaignId?: string;
  monitor?: RunMonitor;
  sourceArtifact?: SourceVerificationArtifact;
  runtimeArtifact?: RuntimeVerificationArtifact;
  scorecard?: ParityScorecard;
  baseline?: ParityScorecard | null;
}

export function generateRecommendations(
  opts: GenerateRecommendationsOpts,
): RecommendationSummary {
  const allRecs: Recommendation[] = [
    ...detectMissingRuntimeCapability(opts.sourceArtifact, opts.runtimeArtifact),
    ...detectSourcePrecisionGap(opts.sourceArtifact),
    ...detectDefenseReasoningGap(opts.sourceArtifact),
    ...detectFormatStabilityGap(opts.monitor),
    ...detectDockerEnvironmentGap(opts.runtimeArtifact),
    ...detectRegressionFromBaseline(opts.scorecard, opts.baseline),
  ];

  const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  allRecs.sort((a, b) => priorityOrder[a.priority] - priorityOrder[b.priority]);

  const sourceCandidates = opts.sourceArtifact
    ? opts.sourceArtifact.candidates.length + (opts.sourceArtifact.auditFindings?.length ?? 0)
    : 0;
  const runtimeCandidates = opts.runtimeArtifact?.candidates.length ?? 0;

  const gateRepairs = opts.monitor
    ? Object.values(opts.monitor.getGateRepairsByClass()).reduce((s, v) => s + v.total, 0)
    : 0;

  const downgrades = opts.monitor?.getDowngradeCount() ?? 0;

  const pvrReady = opts.runtimeArtifact
    ? opts.runtimeArtifact.candidates.filter(c => c.validatedResult.pvrReady).length
    : 0;

  const costUsd = (opts.scorecard?.totalCostUsd ?? 0);

  return {
    generatedAt: new Date().toISOString(),
    campaignId: opts.campaignId,
    targetId: opts.targetId,
    recommendations: allRecs,
    metrics: {
      totalCandidates: Math.max(sourceCandidates, runtimeCandidates),
      sourceVerified: sourceCandidates,
      runtimeVerified: runtimeCandidates,
      gateFailures: gateRepairs,
      downgrades,
      pvrReady,
      costUsd,
    },
  };
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

export function formatRecommendationsMd(summary: RecommendationSummary): string {
  const lines: string[] = [];
  lines.push(`# Verification Recommendations — ${summary.targetId}`);
  lines.push('');
  lines.push(`Generated: ${summary.generatedAt}`);
  if (summary.campaignId) lines.push(`Campaign: ${summary.campaignId}`);
  lines.push('');

  lines.push('## Metrics');
  lines.push('');
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Total candidates | ${summary.metrics.totalCandidates} |`);
  lines.push(`| Source verified | ${summary.metrics.sourceVerified} |`);
  lines.push(`| Runtime verified | ${summary.metrics.runtimeVerified} |`);
  lines.push(`| Gate failures | ${summary.metrics.gateFailures} |`);
  lines.push(`| Downgrades | ${summary.metrics.downgrades} |`);
  lines.push(`| PVR ready | ${summary.metrics.pvrReady} |`);
  lines.push(`| Cost | $${summary.metrics.costUsd.toFixed(4)} |`);
  lines.push('');

  if (summary.recommendations.length === 0) {
    lines.push('No recommendations generated.');
    return lines.join('\n');
  }

  lines.push(`## Recommendations (${summary.recommendations.length})`);
  lines.push('');

  const grouped: Record<string, Recommendation[]> = {};
  for (const rec of summary.recommendations) {
    (grouped[rec.priority] ??= []).push(rec);
  }

  for (const priority of ['critical', 'high', 'medium', 'low'] as const) {
    const recs = grouped[priority];
    if (!recs || recs.length === 0) continue;

    lines.push(`### ${priority.toUpperCase()} (${recs.length})`);
    lines.push('');

    for (const rec of recs) {
      lines.push(`#### ${rec.title}`);
      lines.push('');
      lines.push(`- **Class:** ${rec.class}`);
      lines.push(`- **Detail:** ${rec.detail}`);
      if (rec.affectedCandidates.length > 0) {
        lines.push(`- **Affected:** ${rec.affectedCandidates.join(', ')}`);
      }
      lines.push(`- **Action:** ${rec.suggestedAction}`);
      lines.push('');
    }
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

export async function writeRecommendations(
  outputDir: string,
  summary: RecommendationSummary,
): Promise<{ jsonPath: string; mdPath: string }> {
  const jsonPath = resolve(outputDir, 'verification-recommendations.json');
  const mdPath = resolve(outputDir, 'verification-recommendations.md');
  await writeFile(jsonPath, JSON.stringify(summary, null, 2), 'utf8');
  await writeFile(mdPath, formatRecommendationsMd(summary), 'utf8');
  return { jsonPath, mdPath };
}
