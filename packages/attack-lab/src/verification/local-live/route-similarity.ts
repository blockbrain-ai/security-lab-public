/**
 * Route similarity — ranks surface-map routes by relevance to a
 * hypothesis using token-overlap scoring. No hardcoded route literals.
 */

import type { RouteSurface } from '../../intelligence/contracts.js';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface RankedRoute {
  method: string;
  path: string;
  score: number;
}

/**
 * Rank routes from the surface map by relevance to a hypothesis.
 * Returns the top N routes sorted by descending score.
 */
export function rankRoutesByRelevance(
  hypothesis: string,
  routes: RouteSurface[],
  topN: number = 5,
): RankedRoute[] {
  if (routes.length === 0) {
    return [];
  }

  const hypothesisTokens = tokenize(hypothesis);
  if (hypothesisTokens.length === 0) {
    return [];
  }

  const scored = routes.map((route) => ({
    method: route.method,
    path: route.path,
    score: scoreRoute(hypothesisTokens, route, hypothesis),
  }));

  scored.sort((a, b) => b.score - a.score);

  return scored
    .filter((entry) => entry.score > 0)
    .slice(0, topN);
}

// ---------------------------------------------------------------------------
// Scoring internals
// ---------------------------------------------------------------------------

function scoreRoute(
  hypothesisTokens: string[],
  route: RouteSurface,
  rawHypothesis: string,
): number {
  const pathTokens = tokenize(route.path);
  const fileTokens = tokenize(route.file);
  const allRouteTokens = [...pathTokens, ...fileTokens];

  let score = 0;

  // Token overlap between hypothesis and route path + file
  for (const token of hypothesisTokens) {
    for (const routeToken of allRouteTokens) {
      if (token === routeToken) {
        score += 2;
      } else if (routeToken.includes(token) || token.includes(routeToken)) {
        score += 1;
      }
    }
  }

  // Method match bonus
  const lower = rawHypothesis.toLowerCase();
  const methodFromHypothesis = extractMethodHint(lower);
  if (methodFromHypothesis && route.method.toUpperCase() === methodFromHypothesis) {
    score += 1;
  }

  // Auth-relevant bonus if the hypothesis mentions auth concepts
  if (/auth|bypass|unauth|anonymous|guest|missing auth|no auth/.test(lower)) {
    if (!route.hasAuth || route.authObservation === 'not_observed') {
      score += 2;
    }
  }

  // Bonus for routes that are more security-relevant
  if (/admin|execute|approve|delete|create|update|write|upload|eval/.test(route.path.toLowerCase())) {
    score += 1;
  }

  return score;
}

function extractMethodHint(lower: string): string | null {
  if (/\bpost\b/.test(lower)) return 'POST';
  if (/\bdelete\b/.test(lower)) return 'DELETE';
  if (/\bput\b/.test(lower)) return 'PUT';
  if (/\bpatch\b/.test(lower)) return 'PATCH';
  if (/\bget\b/.test(lower)) return 'GET';
  return null;
}

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[{}/:._\-\\]/g, ' ')
    .split(/\s+/)
    .filter((token) => token.length >= 2)
    .filter((token) => !STOP_WORDS.has(token));
}

const STOP_WORDS = new Set([
  'the', 'is', 'at', 'of', 'in', 'to', 'for', 'on', 'by', 'an', 'if',
  'or', 'be', 'it', 'no', 'as', 'so', 'do', 'ts', 'js', 'api', 'v1',
  'v2', 'src', 'app',
]);
