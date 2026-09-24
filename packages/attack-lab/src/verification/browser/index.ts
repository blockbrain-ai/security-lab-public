/**
 * Section 12.1 / 12.2 — Browser lane public API.
 */
export type {
  BrowserCapability,
  BrowserRunnerResult,
  BrowserPage,
  BrowserContext,
  Browser,
  BrowserLauncher,
} from './browser-runner.js';
export {
  DEFAULT_BROWSER_CAPABILITY,
  runBrowserSession,
} from './browser-runner.js';

export type {
  BrowserScreenshot,
  BrowserConsoleEntry,
  BrowserUrlTransition,
  BrowserStorageState,
  BrowserCookieMeta,
  BrowserEvidenceBundle,
} from './browser-evidence.js';
export { BrowserEvidenceCollector } from './browser-evidence.js';

// Section 12.2 — browser-origin exploit verification families
export type {
  BrowserProbeFamilyId,
  BrowserProbeVariant,
  BrowserProbeFamilyDefinition,
  BrowserProbeRequest,
  BrowserProbeResult,
  DomAssertionResult,
  ConsoleObservation,
  CookieAnalysisResult,
  NetworkObservation,
  TargetBrowserFamilyCapability,
  BrowserExploitFamilySummary,
} from './browser-probe-families.js';
export {
  BROWSER_FAMILY_REGISTRY,
  classifyBrowserHypothesis,
  getBrowserFamilyDefinition,
  resolveTargetBrowserFamilies,
  executeBrowserProbe,
  executeCsrfProbe,
  executeSameSiteCookieProbe,
  executeWebSocketOriginProbe,
  executeStoredXssProbe,
  emptyBrowserExploitFamilySummary,
  accumulateBrowserProbeResult,
} from './browser-probe-families.js';
