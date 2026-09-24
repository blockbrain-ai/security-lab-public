/**
 * Hosted verdict derivation.
 *
 * A 2xx response is not evidence of a vulnerability: catch-all routes, SPA
 * shells and empty collections all answer 2xx. A hosted probe therefore has to
 * declare what "exploited" would look like for it, and a probe without an
 * assertion can only ever produce `inconclusive`.
 */

import type { HostedProbeRequest } from './contracts.js';
import type { VerificationVerdict } from '../shared/contracts.js';

export interface HostedVerdictInput {
  status: number;
  body: string;
  /** Content-Length as reported by the server, when present. */
  contentLength?: number;
}

export interface HostedVerdict {
  verdict: VerificationVerdict;
  reasoning: string;
  /** Which assertion parts were checked, for the evidence trail. */
  checks: string[];
}

const HARD_DENIAL_STATUSES = new Set([401, 403, 404, 405, 410, 451]);

export function deriveHostedVerdict(probe: HostedProbeRequest, input: HostedVerdictInput): HostedVerdict {
  const assertion = probe.expect;

  if (!assertion || Object.keys(assertion).length === 0) {
    return {
      verdict: 'inconclusive',
      reasoning:
        `Status ${input.status} with no declared assertion — a 2xx response is not by itself ` +
        'evidence of a boundary crossing. Declare probe.expect (statusIn, bodyContains, ' +
        'bodyNotContains or minBodyBytes) to make this probe decidable.',
      checks: [],
    };
  }

  const checks: string[] = [];
  const bytes = Buffer.byteLength(input.body, 'utf8');

  const statusOk = assertion.statusIn
    ? assertion.statusIn.includes(input.status)
    : input.status >= 200 && input.status < 300;
  checks.push(`status ${input.status} ${statusOk ? 'in' : 'not in'} expected set`);

  const bodyContainsOk = assertion.bodyContains ? input.body.includes(assertion.bodyContains) : true;
  if (assertion.bodyContains) {
    checks.push(`body ${bodyContainsOk ? 'contains' : 'does not contain'} marker`);
  }

  const bodyNotContainsOk = assertion.bodyNotContains ? !input.body.includes(assertion.bodyNotContains) : true;
  if (assertion.bodyNotContains) {
    checks.push(`body ${bodyNotContainsOk ? 'does not contain' : 'contains'} forbidden marker`);
  }

  const sizeOk = assertion.minBodyBytes !== undefined ? bytes >= assertion.minBodyBytes : true;
  if (assertion.minBodyBytes !== undefined) {
    checks.push(`body size ${bytes}B ${sizeOk ? 'meets' : 'below'} ${assertion.minBodyBytes}B minimum`);
  }

  if (statusOk && bodyContainsOk && bodyNotContainsOk && sizeOk) {
    return {
      verdict: 'confirmed',
      reasoning: `Assertion satisfied: ${checks.join('; ')}`,
      checks,
    };
  }

  // A flat denial is positive evidence that the boundary held.
  if (HARD_DENIAL_STATUSES.has(input.status) && !statusOk) {
    return {
      verdict: 'refuted',
      reasoning: `Boundary held: status ${input.status} is a denial and the assertion expected otherwise (${checks.join('; ')})`,
      checks,
    };
  }

  return {
    verdict: 'inconclusive',
    reasoning: `Assertion not satisfied and not a clean denial: ${checks.join('; ')}`,
    checks,
  };
}
