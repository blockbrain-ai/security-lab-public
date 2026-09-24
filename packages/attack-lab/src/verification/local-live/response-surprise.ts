/**
 * Section 6.1 — Response surprise classifier.
 *
 * Lightweight heuristic that decides whether a live probe response is
 * "expected" (matches the canary harness's safe/exploitable profile) or
 * "surprising" (status mismatch, error leakage in the body, anomalous
 * response time). Surprising responses drive the adaptive exploration
 * follow-up generation step in {@link ./followup-generator.ts}.
 *
 * The classifier is intentionally deterministic — no model calls, no
 * network. It only inspects already-captured response data.
 */

import type { CanarySpec, ExpectedResponse, LiveExecutionResult } from './contracts.js';

export type ResponseSurpriseVerdict = 'expected' | 'surprising' | 'neither';

export interface ResponseSurpriseClassification {
  verdict: ResponseSurpriseVerdict;
  /** Human-readable reasons behind the classification. */
  reasons: string[];
  /** Structured surprise indicators (useful for evidence events). */
  indicators: {
    statusMismatch: boolean;
    errorLeakage: boolean;
    anomalousLatency: boolean;
    canaryMatched: 'safe' | 'exploitable' | 'neither' | 'unknown';
  };
}

export interface SurpriseClassifierOptions {
  /**
   * Latency threshold in milliseconds. Responses with durationMs above
   * this value are considered anomalous. Defaults to 5000ms (empirically
   * suspicious for local targets).
   */
  anomalousLatencyMs?: number;
  /**
   * Optional canary spec that produced the probe. If provided, the
   * classifier matches the observed status against it.
   */
  canary?: Pick<CanarySpec, 'expectedWhenSafe' | 'expectedWhenExploitable'>;
}

/** Error-leakage patterns: stack traces, SQL fragments, internal paths. */
const ERROR_LEAKAGE_PATTERNS: RegExp[] = [
  /\bTraceback\s*\(most recent call last\)/i,
  /\bat\s+\S+\s*\([^)]*\.(?:js|ts|py|rb|java|go|php):\d+/,
  /\bException\s+in\s+thread\b/i,
  /\b(SyntaxError|TypeError|ReferenceError|ValueError|KeyError|NullPointerException)\b/,
  /\b(?:SQL\s+syntax|syntax\s+error\s+near|unterminated\s+quoted\s+string|ORA-\d|psql:|mysql_fetch)/i,
  /\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[\s\S]{0,80}\b(?:syntax error|near\s+"|unterminated)/i,
  /\bORA-\d{5}\b/,
  /\bpg_(?:query|exec|connect)\b/,
  /(?:\/home|\/Users|\/var|\/root|C:\\Users|C:\\Windows)\//,
  /\bnode_modules\/[^\s'"]+\.js:\d+/,
  /\bstack trace:/i,
];

function statusMatchesExpected(status: number, expected?: ExpectedResponse): boolean {
  if (!expected) return false;
  if (typeof expected.status === 'number' && expected.status === status) return true;
  if (Array.isArray(expected.statusIn) && expected.statusIn.includes(status)) return true;
  return false;
}

function bodyMatchesExpected(body: string, expected?: ExpectedResponse): boolean {
  if (!expected) return false;
  if (expected.bodyContains?.length) {
    if (!expected.bodyContains.every((needle) => body.includes(needle))) return false;
  }
  if (expected.bodyNotContains?.length) {
    if (expected.bodyNotContains.some((needle) => body.includes(needle))) return false;
  }
  return true;
}

/** Detect common error-leakage markers in a response body. */
export function detectErrorLeakage(body: string): { leaked: boolean; patterns: string[] } {
  if (!body) return { leaked: false, patterns: [] };
  const matched: string[] = [];
  for (const pattern of ERROR_LEAKAGE_PATTERNS) {
    if (pattern.test(body)) {
      matched.push(pattern.source);
    }
  }
  return { leaked: matched.length > 0, patterns: matched };
}

/**
 * Classify a live probe response as `expected`, `surprising`, or `neither`.
 *
 * The caller should pass the raw {@link LiveExecutionResult} and, if the
 * probe was canary-backed, the canary spec so status matches can be
 * evaluated against declared safe/exploitable profiles.
 */
export function classifyResponse(
  result: Pick<LiveExecutionResult, 'canaryMatched' | 'response'>,
  options: SurpriseClassifierOptions = {},
): ResponseSurpriseClassification {
  const { response } = result;
  const anomalousLatencyMs = options.anomalousLatencyMs ?? 5000;
  const canary = options.canary;

  const reasons: string[] = [];
  const indicators = {
    statusMismatch: false,
    errorLeakage: false,
    anomalousLatency: false,
    canaryMatched: (result.canaryMatched ?? 'unknown') as 'safe' | 'exploitable' | 'neither' | 'unknown',
  };

  // Status mismatch: response does not match safe OR exploitable expectation.
  if (canary) {
    const safeMatch =
      statusMatchesExpected(response.status, canary.expectedWhenSafe)
      && bodyMatchesExpected(response.body, canary.expectedWhenSafe);
    const exploitableMatch =
      statusMatchesExpected(response.status, canary.expectedWhenExploitable)
      && bodyMatchesExpected(response.body, canary.expectedWhenExploitable);
    if (!safeMatch && !exploitableMatch) {
      indicators.statusMismatch = true;
      reasons.push(`Status ${response.status} does not match declared canary expectations.`);
    }
  } else if (result.canaryMatched === 'neither' || result.canaryMatched === undefined) {
    // No canary supplied and nothing matched; keep status mismatch neutral
    // unless the status is an unusual value (server error).
    if (response.status >= 500) {
      indicators.statusMismatch = true;
      reasons.push(`Server error status ${response.status} returned.`);
    }
  }

  // Error leakage in body.
  const leakage = detectErrorLeakage(response.body ?? '');
  if (leakage.leaked) {
    indicators.errorLeakage = true;
    reasons.push(`Response body contains error-leakage patterns: ${leakage.patterns.slice(0, 2).join(', ')}.`);
  }

  // Anomalous latency.
  if (typeof response.durationMs === 'number' && response.durationMs >= anomalousLatencyMs) {
    indicators.anomalousLatency = true;
    reasons.push(`Response duration ${response.durationMs}ms exceeds surprise threshold ${anomalousLatencyMs}ms.`);
  }

  const surprising =
    indicators.statusMismatch || indicators.errorLeakage || indicators.anomalousLatency;

  if (surprising) {
    return { verdict: 'surprising', reasons, indicators };
  }

  if (canary && (indicators.canaryMatched === 'safe' || indicators.canaryMatched === 'exploitable')) {
    return { verdict: 'expected', reasons: ['Canary matched cleanly.'], indicators };
  }

  return { verdict: 'neither', reasons, indicators };
}
