/**
 * Secret redaction shared by the live and hosted verification lanes.
 *
 * Evidence files are written to disk, copied between machines and attached to
 * reports, so credentials must not survive into them. Header *names* are kept
 * (an auditor needs to know which credential was used) with the value replaced
 * by a short digest, so a value can still be matched against a known secret
 * without the secret being stored.
 */

import { createHash } from 'node:crypto';

/** Header names whose values are secrets. */
const SENSITIVE_HEADERS = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'api-key',
  'x-auth-token',
  'x-access-token',
  'x-csrf-token',
  'x-xsrf-token',
  'x-session-token',
]);

/** Value shapes that are secrets wherever they appear. */
const SECRET_PATTERNS: Array<[RegExp, string]> = [
  [/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, '[redacted-jwt]'],
  [/\bBearer\s+[A-Za-z0-9._~+/-]{8,}=*/gi, 'Bearer [redacted-token]'],
  [/\bsk-ant-[A-Za-z0-9_-]{8,}/g, '[redacted-key]'],
  [/\bsk-proj-[A-Za-z0-9_-]{8,}/g, '[redacted-key]'],
  [/\bsk-[A-Za-z0-9]{20,}/g, '[redacted-key]'],
  [/\bAIza[A-Za-z0-9_-]{20,}/g, '[redacted-key]'],
  [/\bAKIA[0-9A-Z]{12,}/g, '[redacted-key]'],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}/g, '[redacted-token]'],
  [/((?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret)"?\s*[:=]\s*"?)[^"\s,}&]{4,}/gi, '$1[redacted]'],
];

/** Short, stable digest so a redacted value can still be compared. */
export function secretDigest(value: string): string {
  return createHash('sha256').update(value).digest('hex').slice(0, 8);
}

/** Redact secret-shaped substrings from free text (bodies, messages). */
export function redactSecretString(input: string): string {
  let output = input;
  for (const [pattern, replacement] of SECRET_PATTERNS) {
    output = output.replace(pattern, replacement);
  }
  return output;
}

/** Redact a single header value, keeping a digest for auditability. */
export function redactHeaderValue(name: string, value: string): string {
  if (SENSITIVE_HEADERS.has(name.toLowerCase())) {
    return `[redacted:${secretDigest(value)}]`;
  }
  return redactSecretString(value);
}

/** Redact a header map, preserving names and order. */
export function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const output: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    output[name] = redactHeaderValue(name, value);
  }
  return output;
}

/**
 * Redact a body and bound its size. Returns the body plus whether anything was
 * removed, so callers can note the truncation in evidence.
 */
export function redactBody(body: string, limitBytes: number): { body: string; truncated: boolean; redacted: boolean } {
  const redactedText = redactSecretString(body);
  const redacted = redactedText !== body;
  if (Buffer.byteLength(redactedText, 'utf8') <= limitBytes) {
    return { body: redactedText, truncated: false, redacted };
  }
  // Slice on a character boundary that respects the byte budget.
  let sliced = redactedText.slice(0, limitBytes);
  while (Buffer.byteLength(sliced, 'utf8') > limitBytes) {
    sliced = sliced.slice(0, -1);
  }
  return { body: sliced, truncated: true, redacted };
}
