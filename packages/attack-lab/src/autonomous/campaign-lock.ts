/**
 * Single-writer campaign lock — prevents concurrent processes from
 * corrupting a campaign's evidence stream by acquiring an exclusive
 * lock file before any state/memory/event write.
 *
 * Acquisition is atomic: the contents are written to a temporary file
 * and hard-linked into place, so no reader can ever observe a
 * partially written lock (and therefore cannot steal one).
 *
 * Staleness: a lock held by a *live* process on this host is never
 * stale, regardless of age. A lock whose local PID is dead is reclaimed
 * immediately; a lock from another host is reclaimed once it is older
 * than `staleLockMs`.
 *
 * Signals: SIGTERM/SIGINT run the registered shutdown hook (which is
 * expected to drain in-flight work), then release the lock, then
 * terminate the process with 143/130. A second signal exits immediately.
 * Contention diagnostics are written beside the lock file, never into
 * the evidence stream the lock exists to protect.
 */

import { appendFileSync } from 'node:fs';
import { appendFile, link, mkdir, readFile, stat, unlink, writeFile } from 'node:fs/promises';
import { unlinkSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { hostname } from 'node:os';
import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface LockContents {
  pid: number;
  hostname: string;
  acquiredAt: string;
  campaignId: string;
}

export interface CampaignLockOptions {
  /** Campaign directory (the per-campaign root, e.g. data/campaigns/<id>). */
  campaignDir: string;
  /** Campaign identifier. */
  campaignId: string;
  /** Age in ms after which a *foreign-host* lock is considered stale (default 30 min). */
  staleLockMs?: number;
  /** Callback to emit structured events (lifecycle events only — never contention). */
  emitEvent?: (stage: string, payload: Record<string, unknown>) => Promise<void>;
  /**
   * Shutdown hook invoked on SIGTERM/SIGINT before the lock is released.
   * It should abort in-flight work and drain pending writes. If it throws or
   * exceeds its budget, the lock is still released and the process still exits.
   */
  onSignal?: (signal: NodeJS.Signals) => Promise<void> | void;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class WriterLockContentionError extends Error {
  constructor(
    public readonly existingLock: LockContents,
    public readonly currentPid: number,
    detail?: string,
  ) {
    super(
      `Campaign ${existingLock.campaignId} is locked by PID ${existingLock.pid} ` +
      `on ${existingLock.hostname} since ${existingLock.acquiredAt}${detail ? ` (${detail})` : ''}`,
    );
    this.name = 'WriterLockContentionError';
  }
}

// ---------------------------------------------------------------------------
// CampaignLock
// ---------------------------------------------------------------------------

const LOCK_FILENAME = '.writer.lock';
const DIAGNOSTICS_FILENAME = 'lock-diagnostics.jsonl';

/**
 * A lock file that cannot be parsed is only reclaimed once it is older than
 * this grace period, so a create-in-progress is never mistaken for garbage.
 */
const INVALID_LOCK_GRACE_MS = 30_000;

/** Upper bound on the shutdown hook before the lock is released regardless. */
const SHUTDOWN_TIMEOUT_MS = 30_000;

export class CampaignLock {
  private readonly lockPath: string;
  private readonly diagnosticsPath: string;
  private readonly campaignId: string;
  private readonly staleLockMs: number;
  private readonly emitEvent: (stage: string, payload: Record<string, unknown>) => Promise<void>;
  private readonly onSignal?: (signal: NodeJS.Signals) => Promise<void> | void;
  private acquired = false;
  private shuttingDown = false;
  private signalHandlersInstalled = false;
  private readonly boundRelease: () => void;
  private readonly boundSignal: (signal: NodeJS.Signals) => void;

  constructor(options: CampaignLockOptions) {
    this.lockPath = resolve(options.campaignDir, LOCK_FILENAME);
    this.diagnosticsPath = resolve(options.campaignDir, DIAGNOSTICS_FILENAME);
    this.campaignId = options.campaignId;
    this.staleLockMs = options.staleLockMs ?? 30 * 60 * 1000;
    this.emitEvent = options.emitEvent ?? (async () => {});
    this.onSignal = options.onSignal;
    this.boundRelease = () => { this.releaseSync(); };
    this.boundSignal = (signal: NodeJS.Signals) => { void this.handleSignal(signal); };
  }

  /**
   * Acquire the lock. Throws WriterLockContentionError if another live
   * process holds it. Reclaims stale locks automatically.
   */
  async acquire(): Promise<void> {
    // The campaign directory may not exist yet on a first run.
    await mkdir(dirname(this.lockPath), { recursive: true });

    const contents = this.buildLockContents();
    if (await this.tryCreateExclusive(contents)) {
      this.markAcquired();
      return;
    }

    const existing = await this.readExistingLock();
    if (!existing) {
      // Unreadable or invalid contents. Reclaim only when it is old enough to
      // be certainly abandoned; otherwise treat it as held.
      const ageMs = await this.lockAgeMs();
      if (ageMs !== null && ageMs > INVALID_LOCK_GRACE_MS) {
        await this.removeLock();
        return this.acquire();
      }
      await this.reportContention(null);
      throw new WriterLockContentionError(
        {
          pid: -1,
          hostname: 'unknown',
          acquiredAt: new Date().toISOString(),
          campaignId: this.campaignId,
        },
        process.pid,
        'existing lock file is unreadable or invalid',
      );
    }

    if (this.isStale(existing)) {
      await this.reclaim(existing);
      return;
    }

    await this.reportContention(existing);
    throw new WriterLockContentionError(existing, process.pid);
  }

  /**
   * Release the lock. Idempotent — safe to call multiple times.
   */
  async release(): Promise<void> {
    if (!this.acquired) {
      return;
    }
    this.acquired = false;
    this.removeSignalHandlers();
    await this.removeLock();
  }

  /**
   * Synchronous release for use in `process.on('exit')`.
   * Returns true when the lock file is gone afterwards.
   */
  releaseSync(): boolean {
    if (!this.acquired) {
      return true;
    }
    this.acquired = false;
    this.removeSignalHandlers();
    try {
      unlinkSync(this.lockPath);
      return true;
    } catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return true;
      }
      // A lock that cannot be released must never fail silently.
      const detail = error instanceof Error ? error.message : String(error);
      this.recordDiagnosticSync('writer_lock_release_failed', { error: detail });
      return false;
    }
  }

  /**
   * Check whether an existing lock is stale.
   *
   * A lock held by a live process on this host is never stale — age alone
   * must not let a second writer take over a running campaign.
   */
  isStale(lock: LockContents): boolean {
    const sameHost = lock.hostname === hostname();

    if (sameHost) {
      // Live local holder ⇒ not stale; dead local PID ⇒ immediately reclaimable.
      return !isPidAlive(lock.pid);
    }

    const age = Date.now() - new Date(lock.acquiredAt).getTime();
    if (!Number.isFinite(age)) {
      return true;
    }
    return age > this.staleLockMs;
  }

  /** Whether this instance currently holds the lock. */
  isAcquired(): boolean {
    return this.acquired;
  }

  /** Whether a shutdown signal has been received and is being handled. */
  isShuttingDown(): boolean {
    return this.shuttingDown;
  }

  getLockPath(): string {
    return this.lockPath;
  }

  /** Path of the out-of-band diagnostics file (contention, release failures). */
  getDiagnosticsPath(): string {
    return this.diagnosticsPath;
  }

  // -------------------------------------------------------------------------
  // Private
  // -------------------------------------------------------------------------

  private markAcquired(): void {
    this.acquired = true;
    this.installSignalHandlers();
  }

  /**
   * Atomic exclusive create: write to a temp file, then hard-link it into
   * place. `link` fails with EEXIST if the lock is held, and a reader can
   * never see a partially written lock file.
   */
  private async tryCreateExclusive(contents: LockContents): Promise<boolean> {
    const tempPath = `${this.lockPath}.tmp-${process.pid}-${randomBytes(4).toString('hex')}`;
    await writeFile(tempPath, JSON.stringify(contents, null, 2), 'utf8');
    try {
      await link(tempPath, this.lockPath);
      return true;
    } catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
        return false;
      }
      throw error;
    } finally {
      await unlink(tempPath).catch(() => {});
    }
  }

  private async reclaim(oldLock: LockContents): Promise<void> {
    await this.removeLock();
    const contents = this.buildLockContents();

    if (!(await this.tryCreateExclusive(contents))) {
      // Another process beat us to reclaim.
      const existing = await this.readExistingLock();
      if (existing) {
        throw new WriterLockContentionError(existing, process.pid);
      }
      throw new WriterLockContentionError(oldLock, process.pid, 'reclaim race lost');
    }

    this.markAcquired();

    await this.emitEvent('writer_lock_reclaimed', {
      campaignId: this.campaignId,
      oldLock,
      newLock: contents,
    });
  }

  private buildLockContents(): LockContents {
    return {
      pid: process.pid,
      hostname: hostname(),
      acquiredAt: new Date().toISOString(),
      campaignId: this.campaignId,
    };
  }

  private async readExistingLock(): Promise<LockContents | null> {
    try {
      const raw = await readFile(this.lockPath, 'utf8');
      return parseLockContents(raw);
    } catch {
      return null;
    }
  }

  private async lockAgeMs(): Promise<number | null> {
    try {
      const info = await stat(this.lockPath);
      return Date.now() - info.mtimeMs;
    } catch {
      return null;
    }
  }

  private async removeLock(): Promise<void> {
    try {
      await unlink(this.lockPath);
    } catch {
      // Ignore — already removed
    }
  }

  /**
   * Contention is reported out-of-band (diagnostics file + stderr), never
   * through the evidence stream: the losing writer does not own that stream
   * and appending to it would fork the winner's hash chain.
   */
  private async reportContention(existing: LockContents | null): Promise<void> {
    const payload = {
      event: 'writer_lock_contention',
      at: new Date().toISOString(),
      campaignId: this.campaignId,
      existingLock: existing,
      currentPid: process.pid,
      currentHostname: hostname(),
    };
    try {
      await appendFile(this.diagnosticsPath, `${JSON.stringify(payload)}\n`, 'utf8');
    } catch {
      // Best effort — diagnostics must never mask the contention error.
    }
    try {
      process.stderr.write(
        `[security-lab] campaign ${this.campaignId} is locked by ` +
        `PID ${existing?.pid ?? 'unknown'} on ${existing?.hostname ?? 'unknown'} ` +
        `since ${existing?.acquiredAt ?? 'unknown'}\n`,
      );
    } catch {
      // Ignore — stderr may be closed.
    }
  }

  private recordDiagnosticSync(event: string, payload: Record<string, unknown>): void {
    try {
      appendFileSync(
        this.diagnosticsPath,
        `${JSON.stringify({ event, at: new Date().toISOString(), campaignId: this.campaignId, ...payload })}\n`,
        'utf8',
      );
    } catch {
      // Best effort.
    }
  }

  private installSignalHandlers(): void {
    if (this.signalHandlersInstalled) {
      return;
    }
    this.signalHandlersInstalled = true;
    process.on('exit', this.boundRelease);
    process.on('SIGTERM', this.boundSignal);
    process.on('SIGINT', this.boundSignal);
  }

  private removeSignalHandlers(): void {
    if (!this.signalHandlersInstalled) {
      return;
    }
    this.signalHandlersInstalled = false;
    process.removeListener('exit', this.boundRelease);
    process.removeListener('SIGTERM', this.boundSignal);
    process.removeListener('SIGINT', this.boundSignal);
  }

  /**
   * SIGTERM/SIGINT handling. The first signal drains (via the shutdown hook),
   * releases the lock and terminates the process. A second signal exits
   * immediately with a synchronous release.
   */
  private async handleSignal(signal: NodeJS.Signals): Promise<void> {
    const exitCode = signal === 'SIGINT' ? 130 : 143;

    if (this.shuttingDown) {
      this.releaseSync();
      process.exit(128 + (signal === 'SIGINT' ? 2 : 15));
    }
    this.shuttingDown = true;

    if (this.onSignal) {
      try {
        await withTimeout(Promise.resolve(this.onSignal(signal)), SHUTDOWN_TIMEOUT_MS);
      } catch (error: unknown) {
        this.recordDiagnosticSync('shutdown_hook_failed', {
          signal,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    try {
      await this.release();
    } catch {
      this.releaseSync();
    }
    process.exit(exitCode);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function parseLockContents(raw: string): LockContents | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null) {
    return null;
  }
  const candidate = parsed as Partial<LockContents>;
  if (typeof candidate.pid !== 'number' || !Number.isInteger(candidate.pid) || candidate.pid <= 0) {
    return null;
  }
  if (typeof candidate.hostname !== 'string' || candidate.hostname.length === 0) {
    return null;
  }
  if (typeof candidate.acquiredAt !== 'string' || Number.isNaN(Date.parse(candidate.acquiredAt))) {
    return null;
  }
  if (typeof candidate.campaignId !== 'string') {
    return null;
  }
  return {
    pid: candidate.pid,
    hostname: candidate.hostname,
    acquiredAt: candidate.acquiredAt,
    campaignId: candidate.campaignId,
  };
}

function isPidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(`shutdown hook exceeded ${timeoutMs}ms`)), timeoutMs);
      }),
    ]);
  } finally {
    if (timer) {
      clearTimeout(timer);
    }
  }
}
