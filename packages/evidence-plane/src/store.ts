import { appendFile, mkdir, open, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { EVIDENCE_SCHEMA_VERSION, type EvidenceManifest, type EventEnvelope, type RunSummary } from './contracts.js';
import { HashChain, type HashedEvent, type HashChainVerification } from './hash-chain.js';
import { renderInvestigationReport, type InvestigationReportData } from './investigation-report.js';
import { renderMarkdownReport } from './report.js';

export interface StoredRunPaths {
  runDir: string;
  eventsPath: string;
  summaryPath: string;
  reportPath: string;
  manifestPath: string;
}

/**
 * A repair applied while loading `events.jsonl`. Recoveries are never
 * swallowed: they are logged to stderr and returned to the caller (and, in
 * read-only verification mode, surfaced as verification errors).
 */
export interface EvidenceRecoveryDiagnostic {
  kind: 'torn_tail_dropped' | 'unparseable_final_line_dropped';
  path: string;
  /** Bytes removed from the live stream. */
  droppedBytes: number;
  /** The dropped fragment, truncated for logging. */
  droppedFragment: string;
  /** Events that survived the repair and were retained in the chain. */
  retainedEventCount: number;
}

/** Manifest-recorded chain position, checked by {@link EvidenceStore.verifyChain}. */
export interface ChainCheckpoint {
  eventCount?: number;
  headHash?: string;
}

export interface EvidenceChainVerification extends HashChainVerification {
  /** Repairs detected (and, unless read-only, applied) while loading. */
  recoveries: EvidenceRecoveryDiagnostic[];
}

export interface VerifyChainOptions {
  /**
   * When `false`, a torn tail is reported as a verification error instead of
   * being repaired in place — used by the read-only report CLI so verification
   * never mutates evidence. Defaults to `true`.
   */
  repairTornTail?: boolean;
  /**
   * Manifest-recorded position to check the stream against. The checkpoint
   * must be a prefix of the current chain: fewer events than recorded means
   * the stream was truncated, and a mismatched head hash at the recorded
   * index means it was rewritten.
   */
  checkpoint?: ChainCheckpoint;
}

/** Raised when a complete (newline-terminated) event line cannot be parsed. */
export class EvidenceStreamCorruptionError extends Error {
  constructor(
    readonly path: string,
    readonly lineNumber: number,
    cause: unknown,
  ) {
    super(
      `events.jsonl is corrupted at line ${lineNumber + 1} of ${path}: ` +
        `${cause instanceof Error ? cause.message : String(cause)}. ` +
        'Refusing to append to a corrupted evidence stream.',
    );
    this.name = 'EvidenceStreamCorruptionError';
  }
}

export class EvidenceStore {
  readonly paths: StoredRunPaths;
  private hashChain = new HashChain();
  private prepared = false;
  private writeQueue: Promise<unknown> = Promise.resolve();
  private readonly recoveries: EvidenceRecoveryDiagnostic[] = [];

  constructor(runId: string, rootDir = resolve('data', 'runs')) {
    const runDir = resolve(rootDir, runId);
    this.paths = {
      runDir,
      eventsPath: join(runDir, 'events.jsonl'),
      summaryPath: join(runDir, 'summary.json'),
      reportPath: join(runDir, 'report.md'),
      manifestPath: join(runDir, 'manifest.json'),
    };
  }

  /** Bind a store to an existing run directory (read/write in place). */
  static forRunDir(runDir: string): EvidenceStore {
    const absolute = resolve(runDir);
    return new EvidenceStore(basename(absolute), dirname(absolute));
  }

  /** Repairs applied to the event stream so far (torn tails, dropped lines). */
  getRecoveryDiagnostics(): readonly EvidenceRecoveryDiagnostic[] {
    return [...this.recoveries];
  }

  async prepare(): Promise<void> {
    if (this.prepared) {
      return;
    }
    await mkdir(this.paths.runDir, { recursive: true });
    await this.loadExistingEvents();
    this.prepared = true;
  }

  async appendEvent(stage: string, payload: Record<string, unknown>): Promise<void> {
    await this.enqueue(async () => {
      await this.prepare();
      // Persist first, commit second: computing the successor without
      // mutating the chain means a failed write (ENOSPC/EACCES) leaves the
      // in-memory head untouched, so the next append is still a valid
      // successor of the last durable event instead of a poisoned fork.
      const event = this.hashChain.next(stage, payload);
      const envelope: EventEnvelope = {
        ...event,
        schemaVersion: EVIDENCE_SCHEMA_VERSION,
      };
      // Line-boundary guard: if anything left a partial trailing line behind,
      // start our record on a fresh line so records can never concatenate into
      // an unparseable fragment.
      const guard = (await this.needsNewlineGuard()) ? '\n' : '';
      await appendFile(this.paths.eventsPath, `${guard}${JSON.stringify(envelope)}\n`, 'utf8');
      this.hashChain.commit(event);
    });
  }

  /**
   * Wait for every queued write to settle. Rejected operations are isolated by
   * the queue, so draining never rejects — it is a shutdown barrier.
   */
  async drain(): Promise<void> {
    await this.writeQueue;
  }

  /**
   * Verify the rolling hash chain of this run. Covers positional integrity
   * (index must equal position), previous-hash linkage and per-event hashes,
   * and optionally checks the stream against a manifest checkpoint.
   */
  async verifyChain(options: VerifyChainOptions = {}): Promise<EvidenceChainVerification> {
    if (this.prepared) {
      return this.buildVerification(this.hashChain, [...this.recoveries], options);
    }

    const loaded = await readEventStream(this.paths.eventsPath);
    const retainedEventCount = loaded.chain.getEventCount();
    const recoveries = loaded.recoveries.map((recovery) => ({ ...recovery, retainedEventCount }));

    if (recoveries.length > 0 && options.repairTornTail !== false) {
      if (loaded.repairedContent !== undefined) {
        await this.writeFileAtomic(this.paths.eventsPath, loaded.repairedContent);
      }
      for (const recovery of recoveries) {
        warnRecovery(recovery);
      }
    }

    return this.buildVerification(loaded.chain, recoveries, options);
  }

  async writeSummary(summary: RunSummary): Promise<void> {
    await this.enqueue(async () => {
      await this.prepare();
      await this.writeJsonArtifact('summary.json', summary);
      await this.writeTextArtifact('report.md', renderMarkdownReport(summary));
      await this.writeManifestNow(summary.runId);
    });
  }

  async writeInvestigationSummary(summary: InvestigationReportData): Promise<void> {
    await this.enqueue(async () => {
      await this.prepare();
      await this.writeJsonArtifact('summary.json', summary);
      await this.writeTextArtifact('report.md', renderInvestigationReport(summary));
      await this.writeManifestNow(summary.campaignId);
    });
  }

  async writeJsonArtifact(relativePath: string, data: unknown): Promise<string> {
    const path = this.resolveArtifactPath(relativePath);
    await this.writeFileAtomic(path, JSON.stringify(data, null, 2));
    return path;
  }

  async writeTextArtifact(relativePath: string, content: string): Promise<string> {
    const path = this.resolveArtifactPath(relativePath);
    await this.writeFileAtomic(path, content);
    return path;
  }

  async writeManifest(runId: string): Promise<void> {
    await this.enqueue(async () => {
      await this.prepare();
      await this.writeManifestNow(runId);
    });
  }

  static async readSummary(runDir: string): Promise<RunSummary> {
    const raw = await readFile(resolve(runDir, 'summary.json'), 'utf8');
    return JSON.parse(raw) as RunSummary;
  }

  /**
   * Read a manifest, tolerating manifests written before `eventCount` /
   * `headHash` existed (and older ones without a `files` map).
   */
  static async readManifest(runDir: string): Promise<EvidenceManifest> {
    const raw = await readFile(resolve(runDir, 'manifest.json'), 'utf8');
    const parsed = JSON.parse(raw) as Partial<EvidenceManifest>;
    return {
      runId: typeof parsed.runId === 'string' ? parsed.runId : '',
      generatedAt: typeof parsed.generatedAt === 'string' ? parsed.generatedAt : '',
      files: parsed.files && typeof parsed.files === 'object' ? parsed.files : {},
      ...(typeof parsed.eventCount === 'number' ? { eventCount: parsed.eventCount } : {}),
      ...(typeof parsed.headHash === 'string' ? { headHash: parsed.headHash } : {}),
    };
  }

  private buildVerification(
    chain: HashChain,
    recoveries: EvidenceRecoveryDiagnostic[],
    options: VerifyChainOptions,
  ): EvidenceChainVerification {
    const verification = chain.verify();
    const errors = [...verification.errors];

    if (options.repairTornTail === false) {
      for (const recovery of recoveries) {
        errors.push(`Event stream is truncated: ${describeRecovery(recovery)}`);
      }
    }

    const checkpoint = options.checkpoint;
    if (checkpoint?.eventCount != null) {
      if (verification.eventCount < checkpoint.eventCount) {
        errors.push(
          `Manifest checkpoint expects ${checkpoint.eventCount} event(s) but the stream has ` +
            `${verification.eventCount} — truncation detected`,
        );
      } else if (checkpoint.headHash) {
        const recordedHead = chain.getEvents()[checkpoint.eventCount - 1];
        if (recordedHead && recordedHead.hash !== checkpoint.headHash) {
          errors.push(
            `Manifest checkpoint head mismatch at index ${checkpoint.eventCount - 1} ` +
              `(expected ${checkpoint.headHash.slice(0, 12)}, got ${recordedHead.hash.slice(0, 12)})`,
          );
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      eventCount: verification.eventCount,
      headHash: verification.headHash,
      recoveries,
    };
  }

  /**
   * Write the manifest last, inside the write queue, so the recorded file
   * hashes and chain position describe the run as of the moment of writing.
   */
  private async writeManifestNow(runId: string): Promise<void> {
    const files = await collectRunFiles(this.paths.runDir, this.paths.manifestPath);
    const manifest: EvidenceManifest = {
      runId,
      generatedAt: new Date().toISOString(),
      files,
      eventCount: this.hashChain.getEventCount(),
      headHash: this.hashChain.getHeadHash(),
    };
    await this.writeFileAtomic(this.paths.manifestPath, JSON.stringify(manifest, null, 2));
  }

  /**
   * Resolve an artifact path and refuse anything that escapes the run
   * directory (`../../x.json`, absolute paths).
   */
  private resolveArtifactPath(relativePath: string): string {
    const absolute = resolve(this.paths.runDir, relativePath);
    const inside = relative(this.paths.runDir, absolute);
    if (inside === '' || inside.startsWith('..') || isAbsolute(inside)) {
      throw new Error(
        `Artifact path escapes the run directory: ${relativePath} (resolved to ${absolute})`,
      );
    }
    return absolute;
  }

  /** Temp file + rename so a crash cannot destroy the previous good artifact. */
  private async writeFileAtomic(path: string, content: string): Promise<void> {
    const directory = dirname(path);
    await mkdir(directory, { recursive: true });
    const tempPath = join(directory, `.${basename(path)}.${randomUUID()}.tmp`);
    try {
      await writeFile(tempPath, content, 'utf8');
      await rename(tempPath, path);
    } catch (error) {
      await rm(tempPath, { force: true }).catch(() => undefined);
      throw error;
    }
  }

  private async loadExistingEvents(): Promise<void> {
    const loaded = await readEventStream(this.paths.eventsPath);
    const retainedEventCount = loaded.chain.getEventCount();

    for (const recovery of loaded.recoveries) {
      const diagnostic = { ...recovery, retainedEventCount };
      this.recoveries.push(diagnostic);
      warnRecovery(diagnostic);
    }

    // Repair explicitly on disk before any append can happen, so the resumed
    // stream never forks and never restarts at index 0 while it holds events.
    if (loaded.repairedContent !== undefined) {
      await this.writeFileAtomic(this.paths.eventsPath, loaded.repairedContent);
    }

    if (loaded.chain.getEventCount() > 0) {
      this.hashChain = loaded.chain;
    }
  }

  /**
   * True when the on-disk stream does not end at a line boundary, i.e. the
   * next record must be preceded by a newline rather than concatenated onto a
   * partial line left behind by an aborted writer.
   */
  private async needsNewlineGuard(): Promise<boolean> {
    let handle: FileHandle;
    try {
      handle = await open(this.paths.eventsPath, 'r');
    } catch (error) {
      if (isErrnoException(error) && error.code === 'ENOENT') {
        return false;
      }
      throw error;
    }

    try {
      const { size } = await handle.stat();
      if (size === 0) {
        return false;
      }
      const buffer = Buffer.alloc(1);
      const { bytesRead } = await handle.read(buffer, 0, 1, size - 1);
      return bytesRead === 1 && buffer[0] !== 0x0a;
    } finally {
      await handle.close();
    }
  }

  private async enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.writeQueue.then(operation, operation);
    this.writeQueue = result.then(() => undefined, () => undefined);
    return result;
  }
}

interface LoadedEventStream {
  chain: HashChain;
  recoveries: EvidenceRecoveryDiagnostic[];
  /** Repaired content when a torn tail was dropped; undefined when clean. */
  repairedContent?: string;
}

/**
 * Read and parse `events.jsonl` line by line.
 *
 * A missing file means "no events yet". A trailing partial line (no
 * terminating newline) or an unparseable final line is a torn write from a
 * crash: it is dropped and reported. An unparseable line anywhere else is real
 * corruption and fails closed — the stream must not be appended to.
 */
async function readEventStream(path: string): Promise<LoadedEventStream> {
  let raw: string;
  try {
    raw = await readFile(path, 'utf8');
  } catch (error) {
    if (isErrnoException(error) && error.code === 'ENOENT') {
      return { chain: new HashChain(), recoveries: [] };
    }
    throw error;
  }

  const recoveries: EvidenceRecoveryDiagnostic[] = [];
  const complete = raw.endsWith('\n') ? raw : raw.slice(0, raw.lastIndexOf('\n') + 1);

  if (complete !== raw) {
    const fragment = raw.slice(complete.length);
    recoveries.push({
      kind: 'torn_tail_dropped',
      path,
      droppedBytes: Buffer.byteLength(fragment, 'utf8'),
      droppedFragment: describeFragment(fragment),
      retainedEventCount: 0,
    });
  }

  const lines = complete.split('\n');
  if (lines.length > 0 && lines[lines.length - 1] === '') {
    lines.pop();
  }

  const events: HashedEvent[] = [];
  const retainedLines: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (line.trim() === '') {
      retainedLines.push(line);
      continue;
    }

    let event: HashedEvent;
    try {
      event = JSON.parse(line) as HashedEvent;
    } catch (error) {
      if (i === lines.length - 1) {
        // Final complete-looking line that still will not parse: treat it the
        // same as a torn tail rather than silently restarting the chain.
        recoveries.push({
          kind: 'unparseable_final_line_dropped',
          path,
          droppedBytes: Buffer.byteLength(line, 'utf8'),
          droppedFragment: describeFragment(line),
          retainedEventCount: events.length,
        });
        break;
      }
      throw new EvidenceStreamCorruptionError(path, i, error);
    }

    events.push(event);
    retainedLines.push(line);
  }

  return {
    chain: HashChain.fromEvents(events),
    recoveries,
    ...(recoveries.length > 0
      ? { repairedContent: retainedLines.length > 0 ? `${retainedLines.join('\n')}\n` : '' }
      : {}),
  };
}

function describeFragment(fragment: string): string {
  return fragment.length > 200 ? `${fragment.slice(0, 200)}…` : fragment;
}

function describeRecovery(recovery: EvidenceRecoveryDiagnostic): string {
  return recovery.kind === 'torn_tail_dropped'
    ? `dropped a torn ${recovery.droppedBytes}-byte tail with no terminating newline`
    : `dropped an unparseable final line (${recovery.droppedBytes} bytes)`;
}

function warnRecovery(recovery: EvidenceRecoveryDiagnostic): void {
  process.stderr.write(
    `[evidence-plane] ${recovery.path}: ${describeRecovery(recovery)}; ` +
      `resumed after ${recovery.retainedEventCount} durable event(s) ` +
      `[dropped: ${JSON.stringify(recovery.droppedFragment)}]\n`,
  );
}

function isErrnoException(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && 'code' in error;
}

async function sha256OfFile(path: string): Promise<string> {
  const contents = await readFile(path);
  return createHash('sha256').update(contents).digest('hex');
}

async function collectRunFiles(runDir: string, manifestPath: string): Promise<Record<string, string>> {
  const files: Record<string, string> = {};

  async function walk(dir: string): Promise<void> {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(fullPath);
        continue;
      }
      if (fullPath === manifestPath) {
        continue;
      }
      const relPath = relative(runDir, fullPath);
      files[relPath] = await sha256OfFile(fullPath);
    }
  }

  await walk(runDir);
  return files;
}
