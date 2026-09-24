/**
 * Section 12.1 — Generic browser runner.
 *
 * Playwright-backed browser automation that targets can opt into
 * by declaring `browser` capability in their profile. The runner
 * handles launching a browser context, navigating to target-declared
 * pages, capturing storage state, screenshots, console logs, and
 * URL transitions.
 *
 * This module is the substrate only — exploit-specific browser
 * probe families come in 12.2.
 */

import type {
  BrowserConsoleEntry,
  BrowserCookieMeta,
  BrowserEvidenceBundle,
  BrowserStorageState,
} from './browser-evidence.js';
import { BrowserEvidenceCollector } from './browser-evidence.js';

// ---------------------------------------------------------------------------
// Target-declared browser configuration
// ---------------------------------------------------------------------------

/** Browser capability declared in a target profile. */
export interface BrowserCapability {
  /** Whether browser support is enabled. Defaults to false. */
  enabled: boolean;
  /** URL to navigate to for bootstrapping the session. */
  bootstrapUrl?: string;
  /**
   * Storage-state capture expectations. When present, the runner
   * validates that the expected cookies/storage keys are present
   * after bootstrapping.
   */
  storageStateExpectations?: {
    /** Cookie names expected to be present after bootstrap. */
    expectedCookies?: string[];
    /** Origins expected to have localStorage entries. */
    expectedStorageOrigins?: string[];
  };
  /** Paths to navigate for evidence collection (screenshots, DOM). */
  evidencePaths?: string[];
  /** Browser launch options. */
  launchOptions?: {
    headless?: boolean;
    /** Viewport width. */
    viewportWidth?: number;
    /** Viewport height. */
    viewportHeight?: number;
    /** Navigation timeout in ms. Default 30000. */
    navigationTimeoutMs?: number;
  };
}

/** Default browser capability — disabled. */
export const DEFAULT_BROWSER_CAPABILITY: BrowserCapability = {
  enabled: false,
};

// ---------------------------------------------------------------------------
// Browser runner result
// ---------------------------------------------------------------------------

/** Result of a browser runner session. */
export interface BrowserRunnerResult {
  /** Whether the session completed successfully. */
  success: boolean;
  /** Evidence bundle from the session. */
  evidence: BrowserEvidenceBundle;
  /** Storage-state validation result (if expectations were declared). */
  storageStateValidation?: {
    passed: boolean;
    missingCookies: string[];
    missingStorageOrigins: string[];
  };
  /** Error message if the session failed. */
  error?: string;
  /** Total duration of the session in ms. */
  durationMs: number;
}

// ---------------------------------------------------------------------------
// Browser page abstraction
// ---------------------------------------------------------------------------

/**
 * Minimal page interface the runner needs. This decouples the runner
 * from Playwright's concrete types so tests can inject mocks and
 * production code can pass a real Playwright Page.
 */
export interface BrowserPage {
  goto(url: string, options?: { timeout?: number; waitUntil?: 'load' | 'domcontentloaded' | 'networkidle' }): Promise<{ url(): string } | null>;
  url(): string;
  screenshot(options?: { fullPage?: boolean }): Promise<Buffer>;
  evaluate<T, A = undefined>(fn: (arg: A) => T, arg?: A): Promise<T>;
  on(event: 'console', handler: (msg: { type(): string; text(): string }) => void): void;
  close(): Promise<void>;
}

/**
 * Minimal browser context interface. Provides page creation and
 * cookie access for storage-state capture.
 */
export interface BrowserContext {
  newPage(): Promise<BrowserPage>;
  cookies(): Promise<Array<{
    name: string;
    domain: string;
    path: string;
    httpOnly: boolean;
    secure: boolean;
    sameSite: 'Strict' | 'Lax' | 'None';
    expires: number;
  }>>;
  close(): Promise<void>;
}

/**
 * Minimal browser interface. Wraps Playwright's Browser.
 */
export interface Browser {
  newContext(options?: {
    viewport?: { width: number; height: number } | null;
  }): Promise<BrowserContext>;
  close(): Promise<void>;
}

/**
 * Factory that launches a browser. In production this calls
 * `playwright.chromium.launch()`. Tests inject a mock.
 */
export type BrowserLauncher = (options: {
  headless: boolean;
}) => Promise<Browser>;

// ---------------------------------------------------------------------------
// Browser runner
// ---------------------------------------------------------------------------

/**
 * Runs a browser session against a target-declared configuration.
 * Captures evidence throughout and returns a structured result.
 */
export async function runBrowserSession(
  capability: BrowserCapability,
  launcher: BrowserLauncher,
  evidenceDir: string,
  findingId?: string,
): Promise<BrowserRunnerResult> {
  const start = Date.now();
  const collector = new BrowserEvidenceCollector(evidenceDir, findingId);
  const launchOpts = capability.launchOptions ?? {};
  const headless = launchOpts.headless !== false;
  const navTimeout = launchOpts.navigationTimeoutMs ?? 30_000;
  const viewportWidth = launchOpts.viewportWidth ?? 1280;
  const viewportHeight = launchOpts.viewportHeight ?? 720;

  let browser: Browser | null = null;
  let context: BrowserContext | null = null;

  try {
    browser = await launcher({ headless });
    context = await browser.newContext({
      viewport: { width: viewportWidth, height: viewportHeight },
    });

    const page = await context.newPage();

    // Wire up console log capture
    page.on('console', (msg) => {
      const type = msg.type() as BrowserConsoleEntry['level'];
      const level = ['log', 'warn', 'error', 'info', 'debug'].includes(type) ? type : 'log';
      collector.addConsoleEntry(level as BrowserConsoleEntry['level'], msg.text(), page.url());
    });

    // Navigate to bootstrap URL
    let previousUrl = '';
    if (capability.bootstrapUrl) {
      const response = await page.goto(capability.bootstrapUrl, {
        timeout: navTimeout,
        waitUntil: 'load',
      });
      const currentUrl = response?.url() ?? page.url();
      collector.addUrlTransition(previousUrl, currentUrl);
      previousUrl = currentUrl;

      // Capture screenshot after bootstrap
      const png = await page.screenshot({ fullPage: true });
      await collector.addScreenshot(currentUrl, png, 'after-bootstrap');
    }

    // Navigate to evidence collection paths
    if (capability.evidencePaths) {
      for (const path of capability.evidencePaths) {
        const url = new URL(path, capability.bootstrapUrl).toString();
        const response = await page.goto(url, {
          timeout: navTimeout,
          waitUntil: 'load',
        });
        const currentUrl = response?.url() ?? page.url();
        collector.addUrlTransition(previousUrl, currentUrl);
        previousUrl = currentUrl;

        const png = await page.screenshot({ fullPage: true });
        await collector.addScreenshot(currentUrl, png, `evidence-${path.replace(/[^a-zA-Z0-9]/g, '-')}`);
      }
    }

    // Capture storage state
    const cookies = await context.cookies();
    const cookieMeta: BrowserCookieMeta[] = cookies.map((c) => ({
      name: c.name,
      domain: c.domain,
      path: c.path,
      httpOnly: c.httpOnly,
      secure: c.secure,
      sameSite: c.sameSite,
      expires: c.expires,
    }));

    // Get localStorage/sessionStorage key counts via page.evaluate.
    // The callback runs in the browser context where window/localStorage
    // exist. We type the return value explicitly to avoid Node-side TS
    // errors for browser globals.
    const storageKeyCounts = await page.evaluate<Record<string, { localStorage: number; sessionStorage: number }>>(() => {
      /* eslint-disable no-undef -- browser globals */
      const w = globalThis as unknown as {
        location: { origin: string };
        localStorage: { length: number };
        sessionStorage: { length: number };
      };
      const counts: Record<string, { localStorage: number; sessionStorage: number }> = {};
      counts[w.location.origin] = {
        localStorage: w.localStorage.length,
        sessionStorage: w.sessionStorage.length,
      };
      return counts;
      /* eslint-enable no-undef */
    });

    const storageState: BrowserStorageState = {
      cookies: cookieMeta,
      storageKeyCounts,
      capturedAt: new Date().toISOString(),
    };
    collector.setStorageState(storageState);

    // Validate storage-state expectations
    let storageStateValidation: BrowserRunnerResult['storageStateValidation'];
    if (capability.storageStateExpectations) {
      const exp = capability.storageStateExpectations;
      const presentCookieNames = new Set(cookieMeta.map((c) => c.name));
      const missingCookies = (exp.expectedCookies ?? []).filter(
        (name) => !presentCookieNames.has(name),
      );
      const presentOrigins = new Set(Object.keys(storageKeyCounts));
      const missingStorageOrigins = (exp.expectedStorageOrigins ?? []).filter(
        (origin) => !presentOrigins.has(origin),
      );
      storageStateValidation = {
        passed: missingCookies.length === 0 && missingStorageOrigins.length === 0,
        missingCookies,
        missingStorageOrigins,
      };
    }

    await page.close();
    const evidence = await collector.finalize();

    return {
      success: true,
      evidence,
      storageStateValidation,
      durationMs: Date.now() - start,
    };
  } catch (err) {
    const evidence = await collector.finalize();
    return {
      success: false,
      evidence,
      error: err instanceof Error ? err.message : String(err),
      durationMs: Date.now() - start,
    };
  } finally {
    try { await context?.close(); } catch { /* best effort */ }
    try { await browser?.close(); } catch { /* best effort */ }
  }
}
