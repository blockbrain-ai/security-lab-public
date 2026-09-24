import { z } from 'zod';
import { createHash, randomBytes } from 'node:crypto';
import { execSync, type ExecSyncOptionsWithStringEncoding } from 'node:child_process';
import { writeFile, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

export const GitStateSchema = z.object({
  commitHash: z.string(),
  branch: z.string(),
  isDirty: z.boolean(),
});

export type GitState = z.infer<typeof GitStateSchema>;

export const LaneConfigSchema = z.object({
  provider: z.string(),
  model: z.string(),
  baseUrl: z.string().optional(),
});

export type LaneConfig = z.infer<typeof LaneConfigSchema>;

export const TelemetrySummarySchema = z.object({
  totalCostUsd: z.number(),
  totalInputTokens: z.number(),
  totalOutputTokens: z.number(),
  invocationCount: z.number(),
});

export type TelemetrySummary = z.infer<typeof TelemetrySummarySchema>;

export const VerificationManifestSchema = z.object({
  schemaVersion: z.literal(1),
  runId: z.string(),
  profileId: z.string().nullable().optional(),
  campaignId: z.string().optional(),
  targetId: z.string(),
  mode: z.enum(['source', 'runtime', 'full']),
  git: GitStateSchema,
  lanes: z.object({
    source: LaneConfigSchema.optional(),
    runtime: LaneConfigSchema.optional(),
    sourceCritic: LaneConfigSchema.optional(),
    runtimeSetup: LaneConfigSchema.optional(),
    runtimeProbe: LaneConfigSchema.optional(),
  }),
  cliOptions: z.record(z.unknown()),
  artifactPaths: z.record(z.string()),
  configHash: z.string(),
  startedAt: z.string(),
  finalizedAt: z.string().optional(),
  durationMs: z.number().optional(),
  exitStatus: z.enum(['success', 'failure', 'partial']).optional(),
  telemetrySummary: TelemetrySummarySchema.optional(),
});

export type VerificationManifest = z.infer<typeof VerificationManifestSchema>;

// ---------------------------------------------------------------------------
// Git state capture
// ---------------------------------------------------------------------------

export function captureGitState(repoRoot: string): GitState {
  const execOptions: ExecSyncOptionsWithStringEncoding = {
    cwd: repoRoot,
    timeout: 5000,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  };

  try {
    const commitHash = execSync('git rev-parse HEAD', execOptions).trim();
    const branch = execSync('git rev-parse --abbrev-ref HEAD', execOptions).trim();
    const porcelain = execSync('git status --porcelain', execOptions).trim();
    return { commitHash, branch, isDirty: porcelain.length > 0 };
  } catch {
    return { commitHash: 'unknown', branch: 'unknown', isDirty: true };
  }
}

// ---------------------------------------------------------------------------
// Config hashing
// ---------------------------------------------------------------------------

export interface ConfigHashInput {
  lanes: VerificationManifest['lanes'];
  mode: string;
  candidateLimit?: number;
  skipAudit?: boolean;
  profileId?: string | null;
}

function canonicalizeForHash(value: unknown): unknown {
  if (value === undefined || value === null) return undefined;
  if (Array.isArray(value)) {
    return value
      .map((item) => canonicalizeForHash(item))
      .filter((item) => item !== undefined);
  }
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const normalized: Record<string, unknown> = {};
    for (const key of Object.keys(record).sort()) {
      const normalizedValue = canonicalizeForHash(record[key]);
      if (normalizedValue !== undefined) {
        normalized[key] = normalizedValue;
      }
    }
    return normalized;
  }
  return value;
}

export function computeConfigHash(input: ConfigHashInput): string {
  const normalized = canonicalizeForHash(input);
  return createHash('sha256')
    .update(JSON.stringify(normalized))
    .digest('hex')
    .slice(0, 16);
}

// ---------------------------------------------------------------------------
// Manifest lifecycle
// ---------------------------------------------------------------------------

export interface CreateManifestOptions {
  campaignId?: string;
  targetId: string;
  mode: 'source' | 'runtime' | 'full';
  repoRoot: string;
  lanes: VerificationManifest['lanes'];
  cliOptions: Record<string, unknown>;
  profileId?: string | null;
  candidateLimit?: number;
  skipAudit?: boolean;
}

export function createManifest(opts: CreateManifestOptions): VerificationManifest {
  const runId = `verify-${Date.now()}-${randomBytes(4).toString('hex')}`;
  const git = captureGitState(opts.repoRoot);
  const configHash = computeConfigHash({
    lanes: opts.lanes,
    mode: opts.mode,
    candidateLimit: opts.candidateLimit,
    skipAudit: opts.skipAudit,
    profileId: opts.profileId,
  });

  return {
    schemaVersion: 1,
    runId,
    profileId: opts.profileId ?? null,
    campaignId: opts.campaignId,
    targetId: opts.targetId,
    mode: opts.mode,
    git,
    lanes: opts.lanes,
    cliOptions: opts.cliOptions,
    artifactPaths: {},
    configHash,
    startedAt: new Date().toISOString(),
  };
}

export interface FinalizeManifestOptions {
  exitStatus: 'success' | 'failure' | 'partial';
  artifactPaths?: Record<string, string>;
  telemetrySummary?: TelemetrySummary;
}

export function finalizeManifest(
  manifest: VerificationManifest,
  opts: FinalizeManifestOptions,
): VerificationManifest {
  const now = new Date();
  const startedAt = new Date(manifest.startedAt);
  return {
    ...manifest,
    finalizedAt: now.toISOString(),
    durationMs: now.getTime() - startedAt.getTime(),
    exitStatus: opts.exitStatus,
    artifactPaths: { ...manifest.artifactPaths, ...opts.artifactPaths },
    telemetrySummary: opts.telemetrySummary,
  };
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

export async function writeManifest(
  outputDir: string,
  manifest: VerificationManifest,
): Promise<string> {
  const path = resolve(outputDir, 'manifest.json');
  await writeFile(path, JSON.stringify(manifest, null, 2), 'utf8');
  return path;
}

export async function readManifest(path: string): Promise<VerificationManifest> {
  const raw = await readFile(path, 'utf8');
  return VerificationManifestSchema.parse(JSON.parse(raw));
}
