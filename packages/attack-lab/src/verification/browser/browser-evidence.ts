/**
 * Section 12.1 — Browser evidence contracts.
 *
 * Defines the typed evidence artifacts produced by the browser runner:
 * storage-state metadata, screenshots, console logs, and URL transitions.
 * All types are generic — no product-specific assumptions.
 */

import { randomUUID } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

// ---------------------------------------------------------------------------
// Evidence artifact types
// ---------------------------------------------------------------------------

/** A screenshot captured during browser execution. */
export interface BrowserScreenshot {
  /** Unique artifact ID. */
  artifactId: string;
  /** Page URL at the time of capture. */
  url: string;
  /** ISO timestamp of capture. */
  capturedAt: string;
  /** Relative path within the evidence directory. */
  relativePath: string;
  /** Optional label (e.g. "after-login", "error-state"). */
  label?: string;
}

/** A console log entry captured from the browser. */
export interface BrowserConsoleEntry {
  /** Log level: log, warn, error, info, debug. */
  level: 'log' | 'warn' | 'error' | 'info' | 'debug';
  /** The logged text. */
  text: string;
  /** ISO timestamp. */
  at: string;
  /** Page URL when the message was logged. */
  url: string;
}

/** A URL transition (navigation) observed during execution. */
export interface BrowserUrlTransition {
  /** Source URL (empty string for initial navigation). */
  from: string;
  /** Destination URL. */
  to: string;
  /** ISO timestamp. */
  at: string;
}

/** Storage-state metadata captured from the browser context. */
export interface BrowserStorageState {
  /** Cookies present in the context, with metadata only (values are redacted). */
  cookies: BrowserCookieMeta[];
  /** localStorage/sessionStorage key counts per origin. */
  storageKeyCounts: Record<string, { localStorage: number; sessionStorage: number }>;
  /** ISO timestamp of capture. */
  capturedAt: string;
}

/** Cookie metadata — values are intentionally excluded from evidence. */
export interface BrowserCookieMeta {
  name: string;
  domain: string;
  path: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'Strict' | 'Lax' | 'None' | string;
  expires: number;
}

// ---------------------------------------------------------------------------
// Aggregate evidence bundle
// ---------------------------------------------------------------------------

/** Complete evidence bundle from a browser execution. */
export interface BrowserEvidenceBundle {
  /** Unique bundle ID. */
  bundleId: string;
  /** Finding ID this evidence relates to (if any). */
  findingId?: string;
  /** Screenshots taken during execution. */
  screenshots: BrowserScreenshot[];
  /** Console log entries. */
  consoleLogs: BrowserConsoleEntry[];
  /** URL transitions observed. */
  urlTransitions: BrowserUrlTransition[];
  /** Storage state captured at end of execution. */
  storageState: BrowserStorageState | null;
  /** ISO timestamp when the bundle was finalized. */
  finalizedAt: string;
}

// ---------------------------------------------------------------------------
// Evidence collector
// ---------------------------------------------------------------------------

/**
 * Collects browser evidence artifacts during a runner session and
 * persists them to the evidence directory.
 */
export class BrowserEvidenceCollector {
  private readonly screenshots: BrowserScreenshot[] = [];
  private readonly consoleLogs: BrowserConsoleEntry[] = [];
  private readonly urlTransitions: BrowserUrlTransition[] = [];
  private storageState: BrowserStorageState | null = null;
  private readonly bundleId: string;

  constructor(
    private readonly evidenceDir: string,
    private readonly findingId?: string,
  ) {
    this.bundleId = `browser-${randomUUID().slice(0, 8)}`;
  }

  /** Record a screenshot. The caller provides the raw PNG buffer. */
  async addScreenshot(url: string, png: Buffer, label?: string): Promise<BrowserScreenshot> {
    const artifactId = `screenshot-${randomUUID().slice(0, 8)}`;
    const relativePath = `browser/${this.bundleId}/${artifactId}.png`;
    const fullPath = join(this.evidenceDir, relativePath);
    await mkdir(join(this.evidenceDir, 'browser', this.bundleId), { recursive: true });
    await writeFile(fullPath, png);

    const entry: BrowserScreenshot = {
      artifactId,
      url,
      capturedAt: new Date().toISOString(),
      relativePath,
      label,
    };
    this.screenshots.push(entry);
    return entry;
  }

  /** Record a console log entry. */
  addConsoleEntry(level: BrowserConsoleEntry['level'], text: string, url: string): void {
    this.consoleLogs.push({
      level,
      text,
      at: new Date().toISOString(),
      url,
    });
  }

  /** Record a URL transition. */
  addUrlTransition(from: string, to: string): void {
    this.urlTransitions.push({
      from,
      to,
      at: new Date().toISOString(),
    });
  }

  /** Capture storage-state metadata from a browser context. */
  setStorageState(state: BrowserStorageState): void {
    this.storageState = state;
  }

  /** Finalize and persist the evidence bundle. Returns the bundle. */
  async finalize(): Promise<BrowserEvidenceBundle> {
    const bundle: BrowserEvidenceBundle = {
      bundleId: this.bundleId,
      findingId: this.findingId,
      screenshots: this.screenshots,
      consoleLogs: this.consoleLogs,
      urlTransitions: this.urlTransitions,
      storageState: this.storageState,
      finalizedAt: new Date().toISOString(),
    };

    const bundleDir = join(this.evidenceDir, 'browser', this.bundleId);
    await mkdir(bundleDir, { recursive: true });
    await writeFile(
      join(bundleDir, 'bundle.json'),
      JSON.stringify(bundle, null, 2),
    );

    return bundle;
  }
}
