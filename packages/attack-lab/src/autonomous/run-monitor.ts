import { z } from 'zod';
import { appendFile, mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

export const MonitorEventKindSchema = z.enum([
  'stage_enter',
  'stage_exit',
  'candidate_start',
  'candidate_end',
  'gate_repair',
  'validator_downgrade',
  'docker_setup',
  'docker_teardown',
  'run_start',
  'run_end',
]);

export type MonitorEventKind = z.infer<typeof MonitorEventKindSchema>;

export const MonitorEventSchema = z.object({
  at: z.string(),
  kind: MonitorEventKindSchema,
  stage: z.string().optional(),
  candidateId: z.string().optional(),
  durationMs: z.number().optional(),
  detail: z.record(z.unknown()).optional(),
});

export type MonitorEvent = z.infer<typeof MonitorEventSchema>;

export const AnomalySchema = z.object({
  at: z.string(),
  kind: z.string(),
  severity: z.enum(['info', 'warning', 'error']),
  detail: z.string(),
  candidateId: z.string().optional(),
});

export type Anomaly = z.infer<typeof AnomalySchema>;

// ---------------------------------------------------------------------------
// RunMonitor
// ---------------------------------------------------------------------------

export class RunMonitor {
  private readonly snapshotsPath: string;
  private readonly anomaliesPath: string;
  private readonly events: MonitorEvent[] = [];
  private readonly anomalies: Anomaly[] = [];
  private readonly candidateTimers = new Map<string, number>();
  private readonly gateRepairCounts = new Map<string, number>();
  private prepared = false;

  constructor(outputDir: string) {
    const monitorDir = resolve(outputDir, 'monitoring');
    this.snapshotsPath = resolve(monitorDir, 'snapshots.jsonl');
    this.anomaliesPath = resolve(monitorDir, 'anomalies.jsonl');
  }

  async prepare(): Promise<void> {
    if (this.prepared) return;
    const dir = resolve(this.snapshotsPath, '..');
    await mkdir(dir, { recursive: true });
    this.prepared = true;
  }

  // -----------------------------------------------------------------------
  // Event emission
  // -----------------------------------------------------------------------

  async emitStageEnter(stage: string): Promise<void> {
    await this.emit({ kind: 'stage_enter', stage });
  }

  async emitStageExit(stage: string, durationMs: number): Promise<void> {
    await this.emit({ kind: 'stage_exit', stage, durationMs });
  }

  async emitCandidateStart(candidateId: string, stage: string): Promise<void> {
    this.candidateTimers.set(`${stage}:${candidateId}`, Date.now());
    await this.emit({ kind: 'candidate_start', candidateId, stage });
  }

  async emitCandidateEnd(
    candidateId: string,
    stage: string,
    detail?: Record<string, unknown>,
  ): Promise<void> {
    const key = `${stage}:${candidateId}`;
    const startTime = this.candidateTimers.get(key);
    const durationMs = startTime ? Date.now() - startTime : undefined;
    this.candidateTimers.delete(key);

    await this.emit({ kind: 'candidate_end', candidateId, stage, durationMs, detail });

    if (durationMs !== undefined && durationMs > 900_000) {
      await this.recordAnomaly({
        at: new Date().toISOString(),
        kind: 'stall_candidate',
        severity: 'warning',
        detail: `Candidate ${candidateId} took ${Math.round(durationMs / 1000)}s in ${stage}`,
        candidateId,
      });
    }
  }

  async emitGateRepair(
    candidateId: string,
    failureClass: string,
    succeeded: boolean,
    costUsd: number,
    stage?: string,
  ): Promise<void> {
    const count = (this.gateRepairCounts.get(candidateId) ?? 0) + 1;
    this.gateRepairCounts.set(candidateId, count);

    await this.emit({
      kind: 'gate_repair',
      candidateId,
      ...(stage !== undefined && { stage }),
      detail: { failureClass, succeeded, costUsd },
    });

    if (count > 2) {
      await this.recordAnomaly({
        at: new Date().toISOString(),
        kind: 'excessive_gate_repairs',
        severity: 'warning',
        detail: `Candidate ${candidateId} required ${count} gate repairs`,
        candidateId,
      });
    }
  }

  async emitValidatorDowngrade(
    candidateId: string,
    from: string,
    to: string,
    notes: string[],
    stage?: string,
  ): Promise<void> {
    await this.emit({
      kind: 'validator_downgrade',
      candidateId,
      ...(stage !== undefined && { stage }),
      detail: { from, to, notes },
    });
  }

  async emitDockerSetup(success: boolean, durationMs: number): Promise<void> {
    await this.emit({
      kind: 'docker_setup',
      durationMs,
      detail: { success },
    });

    if (!success) {
      await this.recordAnomaly({
        at: new Date().toISOString(),
        kind: 'docker_setup_failure',
        severity: 'error',
        detail: 'Docker setup failed',
      });
    }
  }

  async emitDockerTeardown(durationMs: number): Promise<void> {
    await this.emit({ kind: 'docker_teardown', durationMs });
  }

  async emitRunStart(): Promise<void> {
    await this.emit({ kind: 'run_start' });
  }

  async emitRunEnd(exitStatus: string): Promise<void> {
    await this.emit({ kind: 'run_end', detail: { exitStatus } });
    await this.checkEndOfRunAnomalies();
  }

  // -----------------------------------------------------------------------
  // Anomaly recording
  // -----------------------------------------------------------------------

  async recordAnomaly(anomaly: Anomaly): Promise<void> {
    this.anomalies.push(anomaly);
    await appendFile(this.anomaliesPath, JSON.stringify(anomaly) + '\n', 'utf8');
  }

  // -----------------------------------------------------------------------
  // Accessors
  // -----------------------------------------------------------------------

  getEvents(): MonitorEvent[] {
    return [...this.events];
  }

  getAnomalies(): Anomaly[] {
    return [...this.anomalies];
  }

  getGateRepairsByClass(): Record<string, { total: number; succeeded: number; costUsd: number }> {
    const result: Record<string, { total: number; succeeded: number; costUsd: number }> = {};
    for (const event of this.events) {
      if (event.kind !== 'gate_repair' || !event.detail) continue;
      const cls = event.detail.failureClass as string;
      if (!result[cls]) result[cls] = { total: 0, succeeded: 0, costUsd: 0 };
      result[cls].total += 1;
      if (event.detail.succeeded) result[cls].succeeded += 1;
      result[cls].costUsd += (event.detail.costUsd as number) ?? 0;
    }
    return result;
  }

  getDowngradeCount(): number {
    return this.events.filter((e) => e.kind === 'validator_downgrade').length;
  }

  getCandidateGateRepairCount(candidateId: string): number {
    return this.gateRepairCounts.get(candidateId) ?? 0;
  }

  // -----------------------------------------------------------------------
  // Internal
  // -----------------------------------------------------------------------

  private async emit(
    partial: Omit<MonitorEvent, 'at'> & { at?: string },
  ): Promise<void> {
    const event: MonitorEvent = {
      at: partial.at ?? new Date().toISOString(),
      kind: partial.kind,
      ...(partial.stage !== undefined && { stage: partial.stage }),
      ...(partial.candidateId !== undefined && { candidateId: partial.candidateId }),
      ...(partial.durationMs !== undefined && { durationMs: partial.durationMs }),
      ...(partial.detail !== undefined && { detail: partial.detail }),
    };
    this.events.push(event);
    await appendFile(this.snapshotsPath, JSON.stringify(event) + '\n', 'utf8');
  }

  private async checkEndOfRunAnomalies(): Promise<void> {
    const candidateStarts = this.events.filter((e) => e.kind === 'candidate_start');
    const candidateEnds = this.events.filter((e) => e.kind === 'candidate_end');
    if (candidateStarts.length === 0) return;

    const gateRepairEvents = this.events.filter((e) => e.kind === 'gate_repair');
    const candidatesWithGateRepairs = new Set(gateRepairEvents.map((e) => e.candidateId));
    const failureRate = candidatesWithGateRepairs.size / candidateStarts.length;

    if (failureRate > 0.5) {
      await this.recordAnomaly({
        at: new Date().toISOString(),
        kind: 'high_parse_failure_rate',
        severity: 'error',
        detail: `${Math.round(failureRate * 100)}% of candidates required gate repairs (${candidatesWithGateRepairs.size}/${candidateStarts.length})`,
      });
    }

    const dockerSetup = this.events.find((e) => e.kind === 'docker_setup');
    if (dockerSetup?.detail?.success === false && candidateEnds.length > 0) {
      const allBlocked = candidateEnds.every(
        (e) => e.detail?.status === 'blocked',
      );
      if (allBlocked) {
        await this.recordAnomaly({
          at: new Date().toISOString(),
          kind: 'all_blocked',
          severity: 'error',
          detail: 'Docker setup failed and all candidates are blocked',
        });
      }
    }
  }
}
