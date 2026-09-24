/**
 * Route-kind detection (Section 11.3) — infers the kind of endpoint
 * that produced a response based on content type, path shape, status
 * code, response headers, and body characteristics.
 *
 * Used by the assertion classifier to avoid counting SPA HTML shells,
 * redirects, static assets, or websocket upgrades as meaningful API
 * exploit confirmations.
 */

import type { RouteKind } from './contracts.js';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface RouteKindInput {
  /** HTTP path of the request (e.g. `/api/v1/users/42`). */
  path: string;
  /** HTTP status code of the response. */
  status: number;
  /** Response headers (lowercased keys expected). */
  headers: Record<string, string>;
  /** Response body (truncated is fine). */
  body: string;
}

/**
 * Infer the route kind from response characteristics.
 * Checks are ordered from most specific to least specific.
 */
export function detectRouteKind(input: RouteKindInput): RouteKind {
  const contentType = (input.headers['content-type'] ?? '').toLowerCase();

  // Websocket upgrade (101 Switching Protocols)
  if (input.status === 101) {
    const upgrade = (input.headers['upgrade'] ?? '').toLowerCase();
    if (upgrade === 'websocket') return 'websocket_upgrade';
  }

  // Redirect / bootstrap (3xx)
  if (input.status >= 300 && input.status < 400) {
    return 'redirect_bootstrap';
  }

  // JSON API — content-type is application/json (or vendor JSON)
  if (isJsonContentType(contentType)) {
    return 'json_api';
  }

  // Static asset — known asset extensions or content types
  if (isStaticAsset(input.path, contentType)) {
    return 'asset_static';
  }

  // HTML responses need further inspection
  if (isHtmlContentType(contentType) || (contentType === '' && looksLikeHtml(input.body))) {
    // SPA shell detection: HTML that loads a JS bundle without real content
    if (isSpaShell(input.body)) {
      return 'spa_shell';
    }
    return 'html_page';
  }

  // API-like path with no content type — likely JSON API
  if (isApiPath(input.path) && input.status >= 200 && input.status < 300) {
    return 'json_api';
  }

  return 'unknown';
}

// ---------------------------------------------------------------------------
// Heuristics
// ---------------------------------------------------------------------------

function isJsonContentType(ct: string): boolean {
  return ct.includes('application/json')
    || ct.includes('+json')
    || ct.includes('application/hal+json')
    || ct.includes('application/vnd.');
}

function isHtmlContentType(ct: string): boolean {
  return ct.includes('text/html') || ct.includes('application/xhtml');
}

function looksLikeHtml(body: string): boolean {
  const trimmed = body.trimStart().slice(0, 200).toLowerCase();
  return trimmed.startsWith('<!doctype html')
    || trimmed.startsWith('<html')
    || trimmed.startsWith('<!doctype');
}

const STATIC_EXTENSIONS = /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map|webp|avif)(\?|$)/i;
const STATIC_CONTENT_TYPES = [
  'text/css',
  'text/javascript',
  'application/javascript',
  'image/',
  'font/',
  'application/octet-stream',
];

function isStaticAsset(path: string, contentType: string): boolean {
  if (STATIC_EXTENSIONS.test(path)) return true;
  return STATIC_CONTENT_TYPES.some((prefix) => contentType.includes(prefix));
}

const API_PATH_PATTERN = /\/(api|graphql|v[0-9]+|rest|rpc)\b/i;

function isApiPath(path: string): boolean {
  return API_PATH_PATTERN.test(path);
}

/**
 * Detect SPA shell HTML — pages that are just a wrapper that loads
 * a JS bundle. These return 200 for any path and contain no real
 * content, so they must never count as exploit confirmation.
 *
 * Heuristics:
 * - Very little visible text content
 * - Contains a `<script src=...>` or `<script type="module">`
 * - Has a mount point div (`id="root"`, `id="app"`, `id="__next"`)
 */
export function isSpaShell(body: string): boolean {
  const lower = body.toLowerCase();

  // Must be HTML
  if (!lower.includes('<html') && !lower.includes('<!doctype')) return false;

  // Check for SPA mount points
  const hasMountPoint = /id=["'](root|app|__next|__nuxt|__gatsby|main-app)["']/i.test(body);

  // Check for bundled script tags
  const hasBundleScript = /<script[^>]*\s(src|type\s*=\s*["']module["'])/i.test(body);

  // Check for minimal body content — strip all tags and see what's left
  const textContent = body
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/<[^>]+>/g, '')
    .replace(/\s+/g, ' ')
    .trim();

  const hasMinimalContent = textContent.length < 200;

  // SPA shell: has mount point + bundle script + minimal content
  if (hasMountPoint && hasBundleScript && hasMinimalContent) return true;

  // Alternatively: very minimal content with a bundle script (no mount point named)
  if (hasBundleScript && textContent.length < 50) return true;

  return false;
}
