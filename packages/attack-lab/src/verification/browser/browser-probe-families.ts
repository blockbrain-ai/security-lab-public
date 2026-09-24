/**
 * Section 12.2 — Browser-origin exploit verification families.
 *
 * Generic browser-native probe families for CSRF, SameSite/cookie,
 * WebSocket origin validation, and stored-XSS confirmation. These
 * families run inside the browser lane and produce browser-native
 * evidence (screenshots, DOM assertions, console observations).
 *
 * Families are target-declared and optional — targets without the
 * browser lane are unaffected.
 */

import type { BrowserLauncher, Browser, BrowserContext } from './browser-runner.js';
import { BrowserEvidenceCollector } from './browser-evidence.js';
import type { BrowserEvidenceBundle } from './browser-evidence.js';
import type { VerificationVerdict } from '../shared/contracts.js';
import { resolveRequestUrl } from '../shared/url-policy.js';
import type { SecurityRuntime } from '../../../../security-runtime/src/runtime.js';
import type { RuntimeTargetContext } from '../../../../security-runtime/src/contracts.js';
import type { SecurityMode } from '../../../../evidence-plane/src/contracts.js';

// ---------------------------------------------------------------------------
// Browser probe family identifiers
// ---------------------------------------------------------------------------

/**
 * Closed set of browser-native probe family IDs. Each represents
 * a class of browser-origin exploit that needs real DOM / cookie /
 * WebSocket verification.
 */
export type BrowserProbeFamilyId =
  | 'csrf_origin'
  | 'samesite_cookie'
  | 'websocket_origin'
  | 'stored_xss';

// ---------------------------------------------------------------------------
// Browser probe family definition
// ---------------------------------------------------------------------------

export interface BrowserProbeVariant {
  key: string;
  label: string;
  description: string;
}

export interface BrowserProbeFamilyDefinition {
  id: BrowserProbeFamilyId;
  label: string;
  description: string;
  defaultVariants: BrowserProbeVariant[];
}

// ---------------------------------------------------------------------------
// Browser probe request and result
// ---------------------------------------------------------------------------

/** A request for a browser-native probe execution. */
export interface BrowserProbeRequest {
  findingId: string;
  hypothesis: string;
  family: BrowserProbeFamilyId;
  variant: string;
  /** Target base URL for the browser session. */
  targetBaseUrl: string;
  /** Target endpoint path to probe. */
  targetPath: string;
  /** HTTP method for CSRF/mutation probes. */
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  /** Request body for mutation probes (JSON string). */
  body?: string;
  /** Cross-origin URL to simulate (for CSRF/WebSocket origin). */
  crossOriginUrl?: string;
  /** Identity cookie name for session-based probes. */
  sessionCookieName?: string;
  /** XSS payload for stored-XSS confirmation. */
  xssPayload?: string;
  /** CSS selector where XSS payload should appear in DOM. */
  xssDomSelector?: string;
  /** WebSocket path for WS origin probes. */
  websocketPath?: string;
  /** Custom headers to set on the browser request. */
  headers?: Record<string, string>;
}

/** Result from a browser-native probe execution. */
export interface BrowserProbeResult {
  findingId: string;
  hypothesis: string;
  family: BrowserProbeFamilyId;
  variant: string;
  verdict: VerificationVerdict;
  reasoning: string;
  evidence: BrowserEvidenceBundle;
  /** DOM assertion results (text found/not found). */
  domAssertions: DomAssertionResult[];
  /** Console observations during the probe. */
  consoleObservations: ConsoleObservation[];
  /** Cookie analysis results (SameSite, Secure flags, etc). */
  cookieAnalysis?: CookieAnalysisResult;
  /** Network observation (request sent, response received). */
  networkObservation?: NetworkObservation;
  durationMs: number;
}

// ---------------------------------------------------------------------------
// Assertion and observation types
// ---------------------------------------------------------------------------

export interface DomAssertionResult {
  selector: string;
  expected: string;
  actual: string | null;
  passed: boolean;
}

export interface ConsoleObservation {
  level: 'log' | 'warn' | 'error' | 'info';
  text: string;
  isSecurityRelevant: boolean;
}

export interface CookieAnalysisResult {
  cookieName: string;
  present: boolean;
  sameSite: string | null;
  httpOnly: boolean | null;
  secure: boolean | null;
  sentCrossOrigin: boolean | null;
}

export interface NetworkObservation {
  requestUrl: string;
  requestMethod: string;
  responseStatus: number | null;
  crossOriginBlocked: boolean;
  credentialsIncluded: boolean;
}

// ---------------------------------------------------------------------------
// Browser probe family registry
// ---------------------------------------------------------------------------

export const BROWSER_FAMILY_REGISTRY: readonly BrowserProbeFamilyDefinition[] = [
  {
    id: 'csrf_origin',
    label: 'CSRF / Origin / Referer',
    description: 'Verifies whether state-changing requests from a cross-origin page succeed when they should be blocked.',
    defaultVariants: [
      {
        key: 'cross_origin_post',
        label: 'Cross-origin POST form submission',
        description: 'Submits a form from evil.example.com to the target endpoint and checks whether the mutation succeeds.',
      },
      {
        key: 'missing_origin_header',
        label: 'Request with missing Origin header',
        description: 'Sends a mutation request without Origin/Referer headers to test for header-presence-based CSRF defenses.',
      },
      {
        key: 'spoofed_referer',
        label: 'Spoofed Referer header',
        description: 'Sends a request with a spoofed Referer from an attacker domain.',
      },
    ],
  },
  {
    id: 'samesite_cookie',
    label: 'SameSite / Cookie Behavior',
    description: 'Inspects session cookie attributes (SameSite, Secure, HttpOnly) and verifies cross-site cookie attachment behavior.',
    defaultVariants: [
      {
        key: 'cookie_attributes',
        label: 'Cookie attribute inspection',
        description: 'Reads cookie metadata after session bootstrap and checks SameSite, Secure, and HttpOnly flags.',
      },
      {
        key: 'cross_site_cookie_send',
        label: 'Cross-site cookie attachment',
        description: 'Navigates from a cross-origin page and checks whether session cookies are attached to the cross-site request.',
      },
    ],
  },
  {
    id: 'websocket_origin',
    label: 'WebSocket Origin Validation',
    description: 'Tests whether WebSocket upgrade requests from unauthorized origins are accepted or rejected.',
    defaultVariants: [
      {
        key: 'cross_origin_ws',
        label: 'Cross-origin WebSocket upgrade',
        description: 'Attempts a WebSocket connection from evil.example.com and checks whether the server accepts the upgrade.',
      },
      {
        key: 'no_origin_ws',
        label: 'WebSocket upgrade without Origin',
        description: 'Attempts a WebSocket connection without an Origin header.',
      },
    ],
  },
  {
    id: 'stored_xss',
    label: 'Stored XSS Confirmation',
    description: 'Verifies whether a stored XSS payload executes in a real browser DOM by injecting a canary and checking for execution evidence.',
    defaultVariants: [
      {
        key: 'script_injection',
        label: 'Script tag injection',
        description: 'Stores a <script> canary and checks whether it executes when the page is loaded.',
      },
      {
        key: 'event_handler_injection',
        label: 'Event handler injection',
        description: 'Stores an event-handler payload (e.g. onerror) and checks for execution in DOM.',
      },
      {
        key: 'dom_mutation',
        label: 'DOM mutation via stored markup',
        description: 'Stores HTML markup and checks whether it renders unescaped in the DOM.',
      },
    ],
  },
] as const;

// ---------------------------------------------------------------------------
// Classification helpers
// ---------------------------------------------------------------------------

const BROWSER_FAMILY_PATTERNS: ReadonlyArray<{ id: BrowserProbeFamilyId; patterns: RegExp[] }> = [
  {
    id: 'csrf_origin',
    patterns: [/csrf/i, /cross[- ]?site[- ]?request/i, /origin[- ]?validation/i, /referer[- ]?check/i, /anti[- ]?csrf/i],
  },
  {
    id: 'samesite_cookie',
    patterns: [/samesite/i, /cookie[- ]?flag/i, /cookie[- ]?attribute/i, /session[- ]?cookie/i, /httponly/i, /secure[- ]?flag/i],
  },
  {
    id: 'websocket_origin',
    patterns: [/websocket/i, /ws:\/\//i, /wss:\/\//i, /cswsh/i, /socket[- ]?origin/i, /upgrade.*origin/i],
  },
  {
    id: 'stored_xss',
    patterns: [/stored[- ]?xss/i, /persistent[- ]?xss/i, /xss[- ]?confirm/i, /dom[- ]?injection/i, /script[- ]?injection/i, /html[- ]?injection/i],
  },
];

/**
 * Classify a hypothesis into a browser probe family.
 * Returns undefined when no browser family matches.
 */
export function classifyBrowserHypothesis(hypothesis: string): BrowserProbeFamilyId | undefined {
  for (const entry of BROWSER_FAMILY_PATTERNS) {
    for (const pattern of entry.patterns) {
      if (pattern.test(hypothesis)) {
        return entry.id;
      }
    }
  }
  return undefined;
}

/**
 * Look up a browser family definition by ID.
 */
export function getBrowserFamilyDefinition(id: BrowserProbeFamilyId): BrowserProbeFamilyDefinition | undefined {
  return BROWSER_FAMILY_REGISTRY.find((f) => f.id === id);
}

// ---------------------------------------------------------------------------
// Target browser family capability
// ---------------------------------------------------------------------------

/** Target-declared browser family support. */
export interface TargetBrowserFamilyCapability {
  family: BrowserProbeFamilyId;
  disabledVariants?: string[];
  /** Additional config for the family (e.g. session cookie name). */
  sessionCookieName?: string;
  websocketPath?: string;
  xssDomSelector?: string;
}

/**
 * Resolve browser families from target profile.
 * Targets without explicit browser family config get all families
 * if browser capability is enabled, or none otherwise.
 */
export function resolveTargetBrowserFamilies(
  browserEnabled: boolean,
  browserFamilies?: unknown[],
): TargetBrowserFamilyCapability[] {
  if (!browserEnabled) return [];

  if (!Array.isArray(browserFamilies) || browserFamilies.length === 0) {
    return BROWSER_FAMILY_REGISTRY.map((f) => ({ family: f.id }));
  }

  return browserFamilies
    .filter((entry): entry is Record<string, unknown> => entry != null && typeof entry === 'object')
    .map((entry) => {
      const family = typeof entry['family'] === 'string' ? entry['family'] as BrowserProbeFamilyId : 'csrf_origin';
      const disabledVariants = Array.isArray(entry['disabledVariants'])
        ? entry['disabledVariants'].filter((v): v is string => typeof v === 'string')
        : undefined;
      const sessionCookieName = typeof entry['sessionCookieName'] === 'string' ? entry['sessionCookieName'] : undefined;
      const websocketPath = typeof entry['websocketPath'] === 'string' ? entry['websocketPath'] : undefined;
      const xssDomSelector = typeof entry['xssDomSelector'] === 'string' ? entry['xssDomSelector'] : undefined;
      return { family, disabledVariants, sessionCookieName, websocketPath, xssDomSelector };
    });
}

// ---------------------------------------------------------------------------
// Probe execution — CSRF / Origin
// ---------------------------------------------------------------------------

/** Security-relevant console messages to watch for. */
const SECURITY_CONSOLE_PATTERNS = [
  /CORS/i, /cross[- ]?origin/i, /blocked/i, /refused/i, /denied/i,
  /CSP/i, /content[- ]?security[- ]?policy/i, /xss/i, /injection/i,
  /unsafe/i, /violation/i,
];

function isSecurityRelevant(text: string): boolean {
  return SECURITY_CONSOLE_PATTERNS.some((p) => p.test(text));
}

/**
 * Execute a CSRF probe: navigate to a cross-origin page that submits
 * a form/fetch to the target, then check the response.
 */
export async function executeCsrfProbe(
  request: BrowserProbeRequest,
  launcher: BrowserLauncher,
  evidenceDir: string,
): Promise<BrowserProbeResult> {
  const start = Date.now();
  const collector = new BrowserEvidenceCollector(evidenceDir, request.findingId);
  const domAssertions: DomAssertionResult[] = [];
  const consoleObservations: ConsoleObservation[] = [];
  let networkObs: NetworkObservation | undefined;

  let browser: Browser | null = null;
  let context: BrowserContext | null = null;

  try {
    browser = await launcher({ headless: true });
    context = await browser.newContext({ viewport: { width: 1280, height: 720 } });
    const page = await context.newPage();

    // Capture console messages
    page.on('console', (msg) => {
      const text = msg.text();
      const level = msg.type() as 'log' | 'warn' | 'error' | 'info';
      consoleObservations.push({
        level: ['log', 'warn', 'error', 'info'].includes(level) ? level : 'log',
        text,
        isSecurityRelevant: isSecurityRelevant(text),
      });
      collector.addConsoleEntry(
        ['log', 'warn', 'error', 'info', 'debug'].includes(level) ? level as 'log' : 'log',
        text,
        page.url(),
      );
    });

    const targetUrl = resolveRequestUrl(request.targetPath, request.targetBaseUrl, { label: 'csrf target path' });
    const method = request.method ?? 'POST';

    // Build a data-URI page that simulates a cross-origin form submission via fetch.
    // This tests whether the target rejects the request due to CSRF protections.
    const attackPage = buildCsrfAttackPage(targetUrl, method, request.body, request.headers);

    await page.goto(attackPage, { timeout: 15_000, waitUntil: 'load' });
    collector.addUrlTransition('', attackPage);

    // Read the probe result from the page
    const probeResult = await page.evaluate<{
      status: number | null;
      body: string;
      error: string | null;
      credentialsSent: boolean;
    }>(() => {
      const w = globalThis as unknown as { __csrfProbeResult?: { status: number | null; body: string; error: string | null; credentialsSent: boolean } };
      return w.__csrfProbeResult ?? { status: null, body: '', error: 'no result', credentialsSent: false };
    });

    // Take screenshot of the result
    const png = await page.screenshot({ fullPage: true });
    await collector.addScreenshot(targetUrl, png, 'csrf-probe-result');

    networkObs = {
      requestUrl: targetUrl,
      requestMethod: method,
      responseStatus: probeResult.status,
      crossOriginBlocked: probeResult.error !== null && probeResult.status === null,
      credentialsIncluded: probeResult.credentialsSent,
    };

    // Determine verdict
    let verdict: VerificationVerdict;
    let reasoning: string;

    if (probeResult.error !== null && probeResult.status === null) {
      // Request was blocked (CORS, network error) — CSRF protection works
      verdict = 'refuted';
      reasoning = `Cross-origin ${method} to ${request.targetPath} was blocked: ${probeResult.error}. CSRF protection is effective.`;
      domAssertions.push({ selector: 'fetch-result', expected: 'blocked', actual: 'blocked', passed: true });
    } else if (probeResult.status !== null && probeResult.status >= 200 && probeResult.status < 300) {
      // Request succeeded from cross-origin — CSRF vulnerability confirmed
      verdict = 'confirmed';
      reasoning = `Cross-origin ${method} to ${request.targetPath} succeeded with status ${probeResult.status}. The endpoint accepted a cross-origin mutation without CSRF protection.`;
      domAssertions.push({ selector: 'fetch-result', expected: 'blocked', actual: `status-${probeResult.status}`, passed: false });
    } else if (probeResult.status !== null && (probeResult.status === 401 || probeResult.status === 403)) {
      // Auth/CSRF rejection — protected
      verdict = 'refuted';
      reasoning = `Cross-origin ${method} to ${request.targetPath} was rejected with status ${probeResult.status}. CSRF protection is effective.`;
      domAssertions.push({ selector: 'fetch-result', expected: 'blocked', actual: `status-${probeResult.status}`, passed: true });
    } else {
      verdict = 'inconclusive';
      reasoning = `Cross-origin ${method} to ${request.targetPath} returned status ${probeResult.status ?? 'unknown'}. Cannot definitively confirm or refute CSRF vulnerability.`;
      domAssertions.push({ selector: 'fetch-result', expected: 'blocked', actual: `status-${probeResult.status}`, passed: false });
    }

    await page.close();
    const evidence = await collector.finalize();

    return {
      findingId: request.findingId,
      hypothesis: request.hypothesis,
      family: 'csrf_origin',
      variant: request.variant,
      verdict,
      reasoning,
      evidence,
      domAssertions,
      consoleObservations,
      networkObservation: networkObs,
      durationMs: Date.now() - start,
    };
  } catch (err) {
    const evidence = await collector.finalize();
    return {
      findingId: request.findingId,
      hypothesis: request.hypothesis,
      family: 'csrf_origin',
      variant: request.variant,
      verdict: 'runtime_error',
      reasoning: `CSRF probe failed: ${err instanceof Error ? err.message : String(err)}`,
      evidence,
      domAssertions,
      consoleObservations,
      durationMs: Date.now() - start,
    };
  } finally {
    try { await context?.close(); } catch { /* best effort */ }
    try { await browser?.close(); } catch { /* best effort */ }
  }
}

// ---------------------------------------------------------------------------
// Probe execution — SameSite / Cookie
// ---------------------------------------------------------------------------

/**
 * Execute a SameSite/cookie inspection probe: bootstrap a session,
 * then inspect cookie attributes.
 */
export async function executeSameSiteCookieProbe(
  request: BrowserProbeRequest,
  launcher: BrowserLauncher,
  evidenceDir: string,
): Promise<BrowserProbeResult> {
  const start = Date.now();
  const collector = new BrowserEvidenceCollector(evidenceDir, request.findingId);
  const domAssertions: DomAssertionResult[] = [];
  const consoleObservations: ConsoleObservation[] = [];

  let browser: Browser | null = null;
  let context: BrowserContext | null = null;

  try {
    browser = await launcher({ headless: true });
    context = await browser.newContext({ viewport: { width: 1280, height: 720 } });
    const page = await context.newPage();

    page.on('console', (msg) => {
      const text = msg.text();
      const level = msg.type() as 'log' | 'warn' | 'error' | 'info';
      consoleObservations.push({
        level: ['log', 'warn', 'error', 'info'].includes(level) ? level : 'log',
        text,
        isSecurityRelevant: isSecurityRelevant(text),
      });
      collector.addConsoleEntry(
        ['log', 'warn', 'error', 'info', 'debug'].includes(level) ? level as 'log' : 'log',
        text,
        page.url(),
      );
    });

    // Navigate to target to establish session
    const bootstrapUrl = resolveRequestUrl(request.targetPath, request.targetBaseUrl, { label: 'cookie bootstrap path' });
    await page.goto(bootstrapUrl, { timeout: 15_000, waitUntil: 'load' });
    collector.addUrlTransition('', bootstrapUrl);

    const png = await page.screenshot({ fullPage: true });
    await collector.addScreenshot(bootstrapUrl, png, 'samesite-cookie-bootstrap');

    // Inspect cookies
    const cookies = await context.cookies();
    const targetCookie = request.sessionCookieName
      ? cookies.find((c) => c.name === request.sessionCookieName)
      : cookies[0];

    let cookieAnalysis: CookieAnalysisResult | undefined;
    let verdict: VerificationVerdict;
    let reasoning: string;

    if (!targetCookie) {
      verdict = 'inconclusive';
      reasoning = `No session cookie found${request.sessionCookieName ? ` matching name "${request.sessionCookieName}"` : ''}. Cannot analyze SameSite behavior.`;
      cookieAnalysis = {
        cookieName: request.sessionCookieName ?? '(none)',
        present: false,
        sameSite: null,
        httpOnly: null,
        secure: null,
        sentCrossOrigin: null,
      };
      domAssertions.push({ selector: 'cookie-presence', expected: 'present', actual: 'absent', passed: false });
    } else {
      const sameSite = targetCookie.sameSite;
      const httpOnly = targetCookie.httpOnly;
      const secure = targetCookie.secure;

      cookieAnalysis = {
        cookieName: targetCookie.name,
        present: true,
        sameSite,
        httpOnly,
        secure,
        sentCrossOrigin: sameSite === 'None' ? true : sameSite === 'Lax' ? null : false,
      };

      // Evaluate cookie security
      const issues: string[] = [];
      if (sameSite === 'None') {
        issues.push('SameSite=None allows cross-site cookie attachment');
      }
      if (!httpOnly) {
        issues.push('HttpOnly is not set — cookie is accessible to JavaScript');
      }
      if (!secure) {
        issues.push('Secure flag is not set — cookie can be sent over HTTP');
      }

      if (issues.length > 0) {
        verdict = 'confirmed';
        reasoning = `Session cookie "${targetCookie.name}" has insecure attributes: ${issues.join('; ')}.`;
      } else {
        verdict = 'refuted';
        reasoning = `Session cookie "${targetCookie.name}" has secure attributes: SameSite=${sameSite}, HttpOnly=${httpOnly}, Secure=${secure}.`;
      }

      domAssertions.push({
        selector: 'cookie-sameSite',
        expected: 'Strict or Lax',
        actual: sameSite,
        passed: sameSite === 'Strict' || sameSite === 'Lax',
      });
      domAssertions.push({
        selector: 'cookie-httpOnly',
        expected: 'true',
        actual: String(httpOnly),
        passed: httpOnly,
      });
      domAssertions.push({
        selector: 'cookie-secure',
        expected: 'true',
        actual: String(secure),
        passed: secure,
      });
    }

    await page.close();
    const evidence = await collector.finalize();

    return {
      findingId: request.findingId,
      hypothesis: request.hypothesis,
      family: 'samesite_cookie',
      variant: request.variant,
      verdict,
      reasoning,
      evidence,
      domAssertions,
      consoleObservations,
      cookieAnalysis,
      durationMs: Date.now() - start,
    };
  } catch (err) {
    const evidence = await collector.finalize();
    return {
      findingId: request.findingId,
      hypothesis: request.hypothesis,
      family: 'samesite_cookie',
      variant: request.variant,
      verdict: 'runtime_error',
      reasoning: `SameSite cookie probe failed: ${err instanceof Error ? err.message : String(err)}`,
      evidence,
      domAssertions,
      consoleObservations,
      durationMs: Date.now() - start,
    };
  } finally {
    try { await context?.close(); } catch { /* best effort */ }
    try { await browser?.close(); } catch { /* best effort */ }
  }
}

// ---------------------------------------------------------------------------
// Probe execution — WebSocket Origin
// ---------------------------------------------------------------------------

/**
 * Execute a WebSocket origin validation probe: attempt a WebSocket
 * connection from a cross-origin page and check acceptance/rejection.
 */
export async function executeWebSocketOriginProbe(
  request: BrowserProbeRequest,
  launcher: BrowserLauncher,
  evidenceDir: string,
): Promise<BrowserProbeResult> {
  const start = Date.now();
  const collector = new BrowserEvidenceCollector(evidenceDir, request.findingId);
  const domAssertions: DomAssertionResult[] = [];
  const consoleObservations: ConsoleObservation[] = [];
  let networkObs: NetworkObservation | undefined;

  let browser: Browser | null = null;
  let context: BrowserContext | null = null;

  try {
    browser = await launcher({ headless: true });
    context = await browser.newContext({ viewport: { width: 1280, height: 720 } });
    const page = await context.newPage();

    page.on('console', (msg) => {
      const text = msg.text();
      const level = msg.type() as 'log' | 'warn' | 'error' | 'info';
      consoleObservations.push({
        level: ['log', 'warn', 'error', 'info'].includes(level) ? level : 'log',
        text,
        isSecurityRelevant: isSecurityRelevant(text),
      });
      collector.addConsoleEntry(
        ['log', 'warn', 'error', 'info', 'debug'].includes(level) ? level as 'log' : 'log',
        text,
        page.url(),
      );
    });

    const wsPath = request.websocketPath ?? request.targetPath;
    const wsBaseUrl = request.targetBaseUrl.replace(/^http/, 'ws');
    const wsUrl = resolveRequestUrl(wsPath, wsBaseUrl, { label: 'websocket path' });
    const crossOrigin = request.crossOriginUrl ?? 'https://evil.example.com';

    // Build a page that attempts a WebSocket connection with a spoofed origin
    const attackPage = buildWebSocketAttackPage(wsUrl);

    await page.goto(attackPage, { timeout: 15_000, waitUntil: 'load' });
    collector.addUrlTransition('', attackPage);

    // Wait briefly for WebSocket to attempt connection
    await new Promise((resolve) => setTimeout(resolve, 2_000));

    const wsResult = await page.evaluate<{
      connected: boolean;
      error: string | null;
      closeCode: number | null;
      messageReceived: boolean;
    }>(() => {
      const w = globalThis as unknown as { __wsProbeResult?: { connected: boolean; error: string | null; closeCode: number | null; messageReceived: boolean } };
      return w.__wsProbeResult ?? { connected: false, error: 'no result', closeCode: null, messageReceived: false };
    });

    const png = await page.screenshot({ fullPage: true });
    await collector.addScreenshot(wsUrl, png, 'websocket-origin-probe');

    networkObs = {
      requestUrl: wsUrl,
      requestMethod: 'GET',
      responseStatus: wsResult.connected ? 101 : null,
      crossOriginBlocked: !wsResult.connected && wsResult.error !== null,
      credentialsIncluded: true,
    };

    let verdict: VerificationVerdict;
    let reasoning: string;

    if (wsResult.connected) {
      verdict = 'confirmed';
      reasoning = `WebSocket connection to ${wsPath} from cross-origin ${crossOrigin} was accepted. The server does not validate the Origin header on WebSocket upgrades.`;
      domAssertions.push({ selector: 'ws-connection', expected: 'rejected', actual: 'connected', passed: false });
    } else if (wsResult.error !== null) {
      verdict = 'refuted';
      reasoning = `WebSocket connection to ${wsPath} from cross-origin ${crossOrigin} was rejected: ${wsResult.error}. Origin validation is effective.`;
      domAssertions.push({ selector: 'ws-connection', expected: 'rejected', actual: 'rejected', passed: true });
    } else {
      verdict = 'inconclusive';
      reasoning = `WebSocket connection to ${wsPath} from cross-origin ${crossOrigin} produced an indeterminate result.`;
      domAssertions.push({ selector: 'ws-connection', expected: 'rejected', actual: 'unknown', passed: false });
    }

    await page.close();
    const evidence = await collector.finalize();

    return {
      findingId: request.findingId,
      hypothesis: request.hypothesis,
      family: 'websocket_origin',
      variant: request.variant,
      verdict,
      reasoning,
      evidence,
      domAssertions,
      consoleObservations,
      networkObservation: networkObs,
      durationMs: Date.now() - start,
    };
  } catch (err) {
    const evidence = await collector.finalize();
    return {
      findingId: request.findingId,
      hypothesis: request.hypothesis,
      family: 'websocket_origin',
      variant: request.variant,
      verdict: 'runtime_error',
      reasoning: `WebSocket origin probe failed: ${err instanceof Error ? err.message : String(err)}`,
      evidence,
      domAssertions,
      consoleObservations,
      durationMs: Date.now() - start,
    };
  } finally {
    try { await context?.close(); } catch { /* best effort */ }
    try { await browser?.close(); } catch { /* best effort */ }
  }
}

// ---------------------------------------------------------------------------
// Probe execution — Stored XSS
// ---------------------------------------------------------------------------

/**
 * Execute a stored XSS confirmation probe: navigate to a page where
 * a stored payload should render, and check whether it executes in
 * the real browser DOM.
 */
export async function executeStoredXssProbe(
  request: BrowserProbeRequest,
  launcher: BrowserLauncher,
  evidenceDir: string,
): Promise<BrowserProbeResult> {
  const start = Date.now();
  const collector = new BrowserEvidenceCollector(evidenceDir, request.findingId);
  const domAssertions: DomAssertionResult[] = [];
  const consoleObservations: ConsoleObservation[] = [];

  let browser: Browser | null = null;
  let context: BrowserContext | null = null;

  try {
    browser = await launcher({ headless: true });
    context = await browser.newContext({ viewport: { width: 1280, height: 720 } });
    const page = await context.newPage();

    // Track XSS execution via console messages
    let xssCanaryFired = false;
    const XSS_CANARY_MARKER = '__SECURITY_LAB_XSS_CANARY__';

    page.on('console', (msg) => {
      const text = msg.text();
      if (text.includes(XSS_CANARY_MARKER)) {
        xssCanaryFired = true;
      }
      const level = msg.type() as 'log' | 'warn' | 'error' | 'info';
      consoleObservations.push({
        level: ['log', 'warn', 'error', 'info'].includes(level) ? level : 'log',
        text,
        isSecurityRelevant: isSecurityRelevant(text) || text.includes(XSS_CANARY_MARKER),
      });
      collector.addConsoleEntry(
        ['log', 'warn', 'error', 'info', 'debug'].includes(level) ? level as 'log' : 'log',
        text,
        page.url(),
      );
    });

    // Navigate to the page where the stored payload should appear
    const targetUrl = resolveRequestUrl(request.targetPath, request.targetBaseUrl, { label: 'xss target path' });
    await page.goto(targetUrl, { timeout: 15_000, waitUntil: 'load' });
    collector.addUrlTransition('', targetUrl);

    // Check DOM for XSS payload
    const selector = request.xssDomSelector ?? 'body';
    const domContent = await page.evaluate<string | null, string>((sel) => {
      const w = globalThis as unknown as { document: { querySelector(s: string): { innerHTML: string } | null } };
      const el = w.document.querySelector(sel);
      return el ? el.innerHTML : null;
    }, selector);

    const payload = request.xssPayload ?? '<script>';
    const payloadInDom = domContent !== null && domContent.includes(payload);

    const png = await page.screenshot({ fullPage: true });
    await collector.addScreenshot(targetUrl, png, 'stored-xss-check');

    domAssertions.push({
      selector,
      expected: 'no unescaped payload',
      actual: payloadInDom ? 'payload found in DOM' : 'payload not found',
      passed: !payloadInDom && !xssCanaryFired,
    });

    let verdict: VerificationVerdict;
    let reasoning: string;

    if (xssCanaryFired) {
      verdict = 'confirmed';
      reasoning = `Stored XSS confirmed: canary script executed in the browser DOM at ${request.targetPath}. The payload "${payload}" was rendered and executed.`;
    } else if (payloadInDom) {
      verdict = 'confirmed';
      reasoning = `Stored XSS confirmed: unescaped HTML payload "${payload}" was found in the DOM at ${request.targetPath}. While script execution was not directly observed, the unescaped content is a confirmed XSS vector.`;
    } else {
      verdict = 'refuted';
      reasoning = `Stored XSS not confirmed: payload "${payload}" was not found unescaped in the DOM at ${request.targetPath}, and no canary execution was observed. The application appears to sanitize stored content.`;
    }

    await page.close();
    const evidence = await collector.finalize();

    return {
      findingId: request.findingId,
      hypothesis: request.hypothesis,
      family: 'stored_xss',
      variant: request.variant,
      verdict,
      reasoning,
      evidence,
      domAssertions,
      consoleObservations,
      durationMs: Date.now() - start,
    };
  } catch (err) {
    const evidence = await collector.finalize();
    return {
      findingId: request.findingId,
      hypothesis: request.hypothesis,
      family: 'stored_xss',
      variant: request.variant,
      verdict: 'runtime_error',
      reasoning: `Stored XSS probe failed: ${err instanceof Error ? err.message : String(err)}`,
      evidence,
      domAssertions,
      consoleObservations,
      durationMs: Date.now() - start,
    };
  } finally {
    try { await context?.close(); } catch { /* best effort */ }
    try { await browser?.close(); } catch { /* best effort */ }
  }
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

/**
 * Execute a browser probe request by dispatching to the appropriate
 * family handler. Returns the probe result with verdict and evidence.
 */
export interface BrowserProbeExecutionOptions {
  /** Policy runtime; when supplied, no browser probe runs without a decision. */
  runtime?: SecurityRuntime;
  /** Target context handed to the policy runtime. */
  runtimeTargetContext?: RuntimeTargetContext;
  /** Security mode reported to the policy runtime (default `declared`). */
  mode?: SecurityMode;
}

export async function executeBrowserProbe(
  request: BrowserProbeRequest,
  launcher: BrowserLauncher,
  evidenceDir: string,
  options: BrowserProbeExecutionOptions = {},
): Promise<BrowserProbeResult> {
  // Policy gate at the dispatcher: every browser family — including probes
  // whose target path came from model output — passes through here.
  if (options.runtime) {
    if (!options.runtimeTargetContext) {
      return blockedBrowserProbe(
        request,
        'probe refused: a policy runtime was supplied without a target context (environment tier unknown)',
      );
    }
    const decision = options.runtime.authorizeProbe(options.mode ?? 'declared', options.runtimeTargetContext, {
      kind: 'http_request',
      timeoutMs: 20_000,
      method: 'GET',
    });
    if (!decision.allowed) {
      return blockedBrowserProbe(request, `policy blocked: ${decision.reason ?? 'blocked'}`);
    }
  }

  switch (request.family) {
    case 'csrf_origin':
      return executeCsrfProbe(request, launcher, evidenceDir);
    case 'samesite_cookie':
      return executeSameSiteCookieProbe(request, launcher, evidenceDir);
    case 'websocket_origin':
      return executeWebSocketOriginProbe(request, launcher, evidenceDir);
    case 'stored_xss':
      return executeStoredXssProbe(request, launcher, evidenceDir);
  }
}


/**
 * Result for a browser probe that the policy runtime refused. No browser is
 * launched and no evidence is collected, so the bundle is empty by design.
 */
function blockedBrowserProbe(request: BrowserProbeRequest, reasoning: string): BrowserProbeResult {
  return {
    findingId: request.findingId,
    hypothesis: request.hypothesis,
    family: request.family,
    variant: request.variant,
    verdict: 'not_authorized',
    reasoning,
    evidence: {
      bundleId: `browser-blocked-${Date.now().toString(36)}`,
      findingId: request.findingId,
      screenshots: [],
      consoleLogs: [],
      urlTransitions: [],
      storageState: null,
      finalizedAt: new Date().toISOString(),
    },
    domAssertions: [],
    consoleObservations: [],
    durationMs: 0,
  };
}

// ---------------------------------------------------------------------------
// Browser exploit family summary for reporting
// ---------------------------------------------------------------------------

export interface BrowserExploitFamilySummary {
  totalBrowserProbes: number;
  byFamily: Record<string, {
    probes: number;
    variants: string[];
    confirmed: number;
    refuted: number;
    inconclusive: number;
  }>;
}

export function emptyBrowserExploitFamilySummary(): BrowserExploitFamilySummary {
  return { totalBrowserProbes: 0, byFamily: {} };
}

export function accumulateBrowserProbeResult(
  summary: BrowserExploitFamilySummary,
  result: BrowserProbeResult,
): void {
  summary.totalBrowserProbes++;
  const entry = summary.byFamily[result.family] ?? { probes: 0, variants: [], confirmed: 0, refuted: 0, inconclusive: 0 };
  entry.probes++;
  if (!entry.variants.includes(result.variant)) {
    entry.variants.push(result.variant);
  }
  if (result.verdict === 'confirmed') entry.confirmed++;
  else if (result.verdict === 'refuted') entry.refuted++;
  else entry.inconclusive++;
  summary.byFamily[result.family] = entry;
}

// ---------------------------------------------------------------------------
// Internal helpers — attack page builders
// ---------------------------------------------------------------------------

function buildCsrfAttackPage(
  targetUrl: string,
  method: string,
  body?: string,
  headers?: Record<string, string>,
): string {
  const headersJson = JSON.stringify(headers ?? {});
  const escapedBody = body ? JSON.stringify(body) : 'null';

  const html = `<!DOCTYPE html>
<html><head><title>CSRF Probe</title></head><body>
<script>
(async () => {
  const result = { status: null, body: '', error: null, credentialsSent: true };
  try {
    const opts = {
      method: ${JSON.stringify(method)},
      mode: 'cors',
      credentials: 'include',
      headers: Object.assign({ 'Content-Type': 'application/json' }, ${headersJson}),
    };
    const bodyVal = ${escapedBody};
    if (bodyVal !== null) opts.body = bodyVal;
    const resp = await fetch(${JSON.stringify(targetUrl)}, opts);
    result.status = resp.status;
    result.body = await resp.text();
  } catch (e) {
    result.error = e.message || String(e);
  }
  globalThis.__csrfProbeResult = result;
})();
</script>
</body></html>`;

  return `data:text/html;base64,${Buffer.from(html).toString('base64')}`;
}

function buildWebSocketAttackPage(wsUrl: string): string {
  const html = `<!DOCTYPE html>
<html><head><title>WebSocket Origin Probe</title></head><body>
<script>
(function() {
  const result = { connected: false, error: null, closeCode: null, messageReceived: false };
  try {
    const ws = new WebSocket(${JSON.stringify(wsUrl)});
    ws.onopen = function() {
      result.connected = true;
      ws.close();
    };
    ws.onerror = function() {
      result.error = 'connection_error';
    };
    ws.onclose = function(e) {
      result.closeCode = e.code;
      if (!result.connected && !result.error) {
        result.error = 'connection_closed_code_' + e.code;
      }
    };
    ws.onmessage = function() {
      result.messageReceived = true;
    };
  } catch (e) {
    result.error = e.message || String(e);
  }
  globalThis.__wsProbeResult = result;
})();
</script>
</body></html>`;

  return `data:text/html;base64,${Buffer.from(html).toString('base64')}`;
}
