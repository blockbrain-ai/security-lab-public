import { z } from 'zod';
import { readFile, writeFile, mkdir, rename } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import type { ParityScorecard } from './parity-scorecard.js';

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

export const BenchmarkRunEntrySchema = z.object({
  runId: z.string(),
  label: z.string(),
  profileId: z.string().nullable(),
  configHash: z.string(),
  targetId: z.string(),
  timestamp: z.string(),
  manifestPath: z.string(),
  scorecardPath: z.string(),
});

export type BenchmarkRunEntry = z.infer<typeof BenchmarkRunEntrySchema>;

export const BenchmarkRegistryDataSchema = z.object({
  schemaVersion: z.literal(1),
  targetId: z.string(),
  runs: z.array(BenchmarkRunEntrySchema),
  baselines: z.record(z.string(), z.string()),
});

export type BenchmarkRegistryData = z.infer<typeof BenchmarkRegistryDataSchema>;

// ---------------------------------------------------------------------------
// BenchmarkRegistry
// ---------------------------------------------------------------------------

export class BenchmarkRegistry {
  private readonly targetDir: string;
  private readonly registryPath: string;
  private readonly runsDir: string;
  private readonly baselinesDir: string;

  constructor(
    private readonly targetId: string,
    dataRoot?: string,
  ) {
    const root = dataRoot ?? resolve('data', 'benchmarks');
    this.targetDir = resolve(root, targetId);
    this.registryPath = resolve(this.targetDir, 'registry.json');
    this.runsDir = resolve(this.targetDir, 'runs');
    this.baselinesDir = resolve(this.targetDir, 'baselines');
  }

  async prepare(): Promise<void> {
    await mkdir(this.runsDir, { recursive: true });
    await mkdir(this.baselinesDir, { recursive: true });
  }

  async load(): Promise<BenchmarkRegistryData> {
    if (!existsSync(this.registryPath)) {
      return {
        schemaVersion: 1,
        targetId: this.targetId,
        runs: [],
        baselines: {},
      };
    }
    const raw = await readFile(this.registryPath, 'utf8');
    return BenchmarkRegistryDataSchema.parse(JSON.parse(raw));
  }

  async save(data: BenchmarkRegistryData): Promise<void> {
    const tmpPath = `${this.registryPath}.${randomBytes(4).toString('hex')}.tmp`;
    await writeFile(tmpPath, JSON.stringify(data, null, 2), 'utf8');
    await rename(tmpPath, this.registryPath);
  }

  async recordRun(entry: BenchmarkRunEntry, scorecard: ParityScorecard): Promise<void> {
    const data = await this.load();

    // Avoid duplicate runIds
    if (data.runs.some((r) => r.runId === entry.runId)) return;

    const scorecardPath = resolve(this.runsDir, `${entry.runId}.json`);
    await writeFile(scorecardPath, JSON.stringify(scorecard, null, 2), 'utf8');

    data.runs.push({
      ...entry,
      scorecardPath,
    });
    await this.save(data);
  }

  async promoteBaseline(runId: string): Promise<void> {
    const data = await this.load();
    const entry = data.runs.find((r) => r.runId === runId);
    if (!entry) {
      throw new Error(`Run ${runId} not found in registry for target ${this.targetId}`);
    }

    data.baselines[entry.configHash] = runId;
    await this.save(data);

    // Copy scorecard to baselines/
    const runScorecardPath = resolve(this.runsDir, `${runId}.json`);
    if (existsSync(runScorecardPath)) {
      const baselinePath = resolve(this.baselinesDir, `${entry.configHash}.json`);
      const content = await readFile(runScorecardPath, 'utf8');
      await writeFile(baselinePath, content, 'utf8');
    }
  }

  async getBaseline(configHash: string): Promise<ParityScorecard | null> {
    const baselinePath = resolve(this.baselinesDir, `${configHash}.json`);
    if (!existsSync(baselinePath)) return null;
    const raw = await readFile(baselinePath, 'utf8');
    return JSON.parse(raw) as ParityScorecard;
  }

  async listRuns(): Promise<BenchmarkRunEntry[]> {
    const data = await this.load();
    return data.runs;
  }

  async renderMatrixSummary(): Promise<string> {
    const data = await this.load();
    if (data.runs.length < 2) return '';

    const lines: string[] = [];
    lines.push(`# Benchmark Matrix — ${this.targetId}`);
    lines.push('');
    lines.push('| Run ID | Profile | Source Model | Critic Model | Runtime Model | Parse % | Stability % | PO Downgrades | Val Downgrades | Supported | PVR Ready | Cost | Duration | Rec |');
    lines.push('|--------|---------|-------------|-------------|---------------|---------|-------------|---------------|----------------|-----------|-----------|------|----------|-----|');

    for (const entry of data.runs) {
      const scorecardPath = resolve(this.runsDir, `${entry.runId}.json`);
      if (!existsSync(scorecardPath)) continue;

      const raw = await readFile(scorecardPath, 'utf8');
      const sc = JSON.parse(raw) as ParityScorecard;

      const sourceModel = sc.lanes.source?.model ?? '-';
      const criticModel = sc.lanes.sourceCritic?.model ?? sourceModel;
      const runtimeModel = sc.lanes.runtime?.model ?? '-';
      const parseRate = sc.source ? `${(sc.source.parseSuccessRate * 100).toFixed(0)}%` : '-';
      const stabilityRate = sc.source ? `${(sc.source.formatStabilityRate * 100).toFixed(0)}%` : '-';
      const poDowngrades = sc.source?.proofObligationDowngradeCount ?? '-';
      const valDowngrades = sc.runtime?.validatorDowngradeCount ?? '-';
      const supported = sc.source?.statusDistribution.supported ?? '-';
      const pvrReady = sc.runtime?.pvrReadyCount ?? '-';
      const cost = `$${sc.totalCostUsd.toFixed(4)}`;
      const duration = `${Math.round(sc.totalDurationMs / 1000)}s`;
      const rec = sc.recommendation;

      const shortRunId = entry.runId.length > 20 ? entry.runId.slice(0, 20) + '...' : entry.runId;

      lines.push(`| ${shortRunId} | ${entry.profileId ?? '-'} | ${sourceModel} | ${criticModel} | ${runtimeModel} | ${parseRate} | ${stabilityRate} | ${poDowngrades} | ${valDowngrades} | ${supported} | ${pvrReady} | ${cost} | ${duration} | ${rec} |`);
    }

    lines.push('');
    return lines.join('\n');
  }

  getTargetDir(): string {
    return this.targetDir;
  }
}
