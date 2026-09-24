/**
 * Request URL policy.
 *
 * Probe paths come from target profiles, model output and worker suggestions.
 * `new URL(path, baseUrl)` silently accepts an *absolute* URL, so a "path" of
 * `http://169.254.169.254/latest/meta-data/` escapes the configured target and
 * turns any probe lane into an SSRF primitive. Every lane therefore resolves
 * its request URL through this helper, which refuses to leave the target host
 * unless the caller explicitly declares that crossing the origin is the thing
 * being tested.
 */

const ALLOWED_PROTOCOLS = new Set(['http:', 'https:', 'ws:', 'wss:']);

export interface UrlPolicyOptions {
  /**
   * Permit a resolved URL on a different host than the base. Only for probes
   * whose subject *is* a cross-origin request (e.g. a WebSocket handshake with
   * a spoofed Origin); never for model-derived paths.
   */
  allowCrossOrigin?: boolean;
  /** What is being resolved, for error messages (e.g. 'probe path'). */
  label?: string;
}

/**
 * Resolve `pathOrUrl` against `baseUrl`, refusing anything that leaves the
 * target host or uses a non-web scheme.
 *
 * The comparison is by host (hostname + port), not by full origin, so the
 * browser lane can swap `http:` for `ws:` while still targeting the same host.
 */
export function resolveRequestUrl(pathOrUrl: string, baseUrl: string, options: UrlPolicyOptions = {}): string {
  const label = options.label ?? 'request path';
  const candidate = (pathOrUrl ?? '').trim();
  if (candidate === '') {
    throw new Error(`${label} is empty`);
  }

  let base: URL;
  try {
    base = new URL(baseUrl);
  } catch {
    throw new Error(`${label} cannot be resolved: target base URL is not a valid URL`);
  }

  let resolved: URL;
  try {
    resolved = new URL(candidate, base);
  } catch {
    throw new Error(`${label} is not a valid URL or path: ${candidate}`);
  }

  if (!ALLOWED_PROTOCOLS.has(resolved.protocol)) {
    throw new Error(`${label} uses unsupported scheme "${resolved.protocol}" (expected http, https, ws or wss)`);
  }

  if (resolved.host !== base.host && options.allowCrossOrigin !== true) {
    throw new Error(
      `${label} resolves to a different host (${resolved.host}) than the target (${base.host}). ` +
        'Absolute URLs outside the target are refused; declare allowCrossOrigin only for a probe whose ' +
        'subject is the cross-origin request itself.',
    );
  }

  return resolved.toString();
}

/** True when a probe path would leave the target host (used for policy diagnostics). */
export function escapesTargetHost(pathOrUrl: string, baseUrl: string): boolean {
  try {
    resolveRequestUrl(pathOrUrl, baseUrl);
    return false;
  } catch {
    return true;
  }
}
