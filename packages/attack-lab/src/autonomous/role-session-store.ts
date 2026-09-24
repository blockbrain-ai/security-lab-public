/**
 * Role session store — persists canonical role transcripts under
 * the campaign directory so planner/judge reasoning survives resume
 * and is auditable independently of provider-native sessions.
 */

import { appendFile, readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RoleTranscriptEntry {
  at: string;
  role: string;
  iteration: number;
  promptHash: string;
  responseHash: string;
  provider: string;
  model: string;
  nativeSessionId?: string;
  /** Brief summary of what was asked/decided. */
  summary: string;
  /** Evidence IDs referenced in this entry. */
  evidenceRefs: string[];
  /** Token usage. */
  inputTokens: number;
  outputTokens: number;
  costUsd: number;
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

export class RoleSessionStore {
  private readonly sessionDir: string;

  constructor(campaignDir: string) {
    this.sessionDir = resolve(campaignDir, 'sessions');
  }

  async prepare(): Promise<void> {
    await mkdir(this.sessionDir, { recursive: true });
  }

  async appendPlannerEntry(entry: RoleTranscriptEntry): Promise<void> {
    await this.append('planner.jsonl', entry);
  }

  async appendCounterPlannerEntry(entry: RoleTranscriptEntry): Promise<void> {
    await this.append('counter-planner.jsonl', entry);
  }

  async appendJudgeEntry(hypothesisId: string, entry: RoleTranscriptEntry): Promise<void> {
    const dir = resolve(this.sessionDir, 'judges', hypothesisId);
    await mkdir(dir, { recursive: true });
    const filename = `${entry.provider}-${entry.model}.jsonl`.replace(/\//g, '-');
    await appendFile(resolve(dir, filename), JSON.stringify(entry) + '\n', 'utf8');
  }

  async appendSynthesizerEntry(findingId: string, entry: RoleTranscriptEntry): Promise<void> {
    const dir = resolve(this.sessionDir, 'synthesizer');
    await mkdir(dir, { recursive: true });
    await appendFile(resolve(dir, `${findingId}.jsonl`), JSON.stringify(entry) + '\n', 'utf8');
  }

  async appendReporterEntry(entry: RoleTranscriptEntry): Promise<void> {
    await this.append('reporter.jsonl', entry);
  }

  async getPlannerHistory(maxEntries: number = 20): Promise<RoleTranscriptEntry[]> {
    return this.readEntries('planner.jsonl', maxEntries);
  }

  async getCounterPlannerHistory(maxEntries: number = 20): Promise<RoleTranscriptEntry[]> {
    return this.readEntries('counter-planner.jsonl', maxEntries);
  }

  async getJudgeHistory(hypothesisId: string, maxEntries: number = 10): Promise<RoleTranscriptEntry[]> {
    const dir = resolve(this.sessionDir, 'judges', hypothesisId);
    const entries: RoleTranscriptEntry[] = [];
    try {
      const { readdir } = await import('node:fs/promises');
      const files = await readdir(dir);
      for (const file of files) {
        entries.push(...await this.readEntriesFromPath(resolve(dir, file), maxEntries));
      }
    } catch {
      // No history yet
    }
    return entries.slice(-maxEntries);
  }

  async getSynthesizerHistory(maxEntries: number = 10): Promise<RoleTranscriptEntry[]> {
    const dir = resolve(this.sessionDir, 'synthesizer');
    const entries: RoleTranscriptEntry[] = [];
    try {
      const { readdir } = await import('node:fs/promises');
      const files = await readdir(dir);
      for (const file of files) {
        entries.push(...await this.readEntriesFromPath(resolve(dir, file), maxEntries));
      }
    } catch {
      // No history yet
    }
    return entries.slice(-maxEntries);
  }

  async getReporterHistory(maxEntries: number = 20): Promise<RoleTranscriptEntry[]> {
    return this.readEntries('reporter.jsonl', maxEntries);
  }

  // ---------------------------------------------------------------------------
  // Brief-mode manifests
  //
  // Heavy reasoning stages (judge, synth, planner-round-N) use persistent
  // worker sessions. Instead of packing the whole decision context into
  // the prompt, we write it to disk here and hand the worker a short
  // pointer-style prompt. The worker opens the brief and the evidence
  // pointers from disk inside its session. See the plan for semantics.
  // ---------------------------------------------------------------------------

  /**
   * Write a per-role, per-scope brief + evidence artifacts to disk and
   * return the paths the caller should stuff into `InvokeOptions.briefMode`.
   *
   * `role` becomes a subdirectory under `briefs/`, `scopeId` becomes the
   * file stem. `evidence` entries are written alongside the brief and their
   * absolute paths are returned so the caller can pass them as
   * `evidencePointers` — the worker opens them from inside its session.
   */
  async writeBriefManifest(args: {
    role: string;
    scopeId: string;
    iteration: number;
    whatToDecide: string;
    outputSchemaReminder: string;
    evidence: Array<{ name: string; content: string }>;
    /** Absolute paths the worker should inspect first (source files, etc). */
    inspectFirst?: string[];
  }): Promise<{ briefPath: string; evidencePaths: string[] }> {
    const safeRole = args.role.replace(/[^a-z0-9_-]/gi, '-');
    const safeScope = args.scopeId.replace(/[^a-z0-9_-]/gi, '-');
    const baseDir = resolve(this.sessionDir, '..', 'briefs', safeRole);
    await mkdir(baseDir, { recursive: true });

    const evidencePaths: string[] = [];
    for (const item of args.evidence) {
      const safeName = item.name.replace(/[^a-z0-9_.-]/gi, '-');
      const evPath = resolve(baseDir, `${safeScope}__${safeName}`);
      await writeFile(evPath, item.content, 'utf8');
      evidencePaths.push(evPath);
    }

    const briefPath = resolve(baseDir, `${safeScope}.brief.md`);
    const lines: string[] = [
      `# Brief — role: ${args.role}, scope: ${args.scopeId}, iteration: ${args.iteration}`,
      '',
      '## What to decide',
      args.whatToDecide.trim(),
      '',
      '## Required output',
      args.outputSchemaReminder.trim(),
      '',
      '## Evidence pointers',
    ];
    for (const p of evidencePaths) lines.push(`- ${p}`);
    if (args.inspectFirst && args.inspectFirst.length > 0) {
      lines.push('', '## Inspect first');
      for (const p of args.inspectFirst) lines.push(`- ${p}`);
    }
    lines.push(
      '',
      '## Protocol',
      '1. Read this brief and every evidence pointer above.',
      '2. Read any "inspect first" files before reasoning.',
      '3. Use your session memory — do NOT expect the caller to reassemble context.',
      '4. Return JSON only, matching the schema above. No prose outside the JSON block.',
      '',
    );

    await writeFile(briefPath, lines.join('\n'), 'utf8');

    return { briefPath, evidencePaths };
  }

  // ---------------------------------------------------------------------------
  // Internal
  // ---------------------------------------------------------------------------

  private async append(filename: string, entry: RoleTranscriptEntry): Promise<void> {
    const path = resolve(this.sessionDir, filename);
    await mkdir(dirname(path), { recursive: true });
    await appendFile(path, JSON.stringify(entry) + '\n', 'utf8');
  }

  private async readEntries(filename: string, maxEntries: number): Promise<RoleTranscriptEntry[]> {
    return this.readEntriesFromPath(resolve(this.sessionDir, filename), maxEntries);
  }

  private async readEntriesFromPath(path: string, maxEntries: number): Promise<RoleTranscriptEntry[]> {
    try {
      const content = await readFile(path, 'utf8');
      const lines = content.trim().split('\n').filter(Boolean);
      return lines.slice(-maxEntries).map((line) => JSON.parse(line));
    } catch {
      return [];
    }
  }
}
