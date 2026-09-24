/**
 * Section 6.1 — Follow-up probe generator.
 *
 * When {@link ./response-surprise.ts} classifies a response as
 * "surprising", this module asks a planner adapter to propose 1-3
 * follow-up HTTP probes that exercise the surprising aspect. The
 * generator is intentionally separate from {@link ./hypothesis-translator.ts}
 * so that adaptive exploration can evolve its "think like Mythos" prompt
 * without coupling to the base hypothesis → probe contract.
 */

import { z } from 'zod';
import type { InvokeOptions, ModelAdapter } from '../../providers/contracts.js';
import { tryParseStructured } from '../../providers/parse-structured.js';
import type { LiveExecutionResult, LiveProbeRequest } from './contracts.js';
import type { ResponseSurpriseClassification } from './response-surprise.js';

// ---------------------------------------------------------------------------
// Prompt
// ---------------------------------------------------------------------------

export const FOLLOWUP_SYSTEM_PROMPT = `You are an adaptive security verification engineer. You receive an unexpected live HTTP response and propose follow-up probes that exercise the surprising aspect. Think like Mythos: do not just replay the obvious route — chase what the response is hinting at.

Rules:
- Propose at most 3 follow-up probes.
- Every probe must have: probeKind=http, identityId (from the available ladder), an http { method, path } payload.
- DO NOT invoke any orchestrator, CLI, or Security Lab subprocess.
- DO NOT attempt destructive operations outside the original probe's scope — focus on discovery.

Output JSON:
{
  "probes": [
    {
      "probeKind": "http",
      "identityId": "anonymous | user_a_low | ...",
      "http": { "method": "GET | POST | ...", "path": "/api/...", "headers": {}, "body": "..." },
      "rationale": "why this probe helps explore the surprise"
    }
  ],
  "reasoning": "one or two sentences about the overall exploration strategy"
}`;

// ---------------------------------------------------------------------------
// Request / result shapes
// ---------------------------------------------------------------------------

export interface FollowupGenerationContext {
  /** The probe that originally fired. */
  originalProbe: LiveProbeRequest;
  /** The response that was flagged as surprising. */
  result: LiveExecutionResult;
  /** Surprise classification that triggered this generation step. */
  classification: ResponseSurpriseClassification;
  /** Original hypothesis being verified. */
  hypothesis: string;
  /** Finding ID that owns the hypothesis. */
  findingId: string;
  /** Available identity IDs from the target's identity ladder. */
  availableIdentities: string[];
  /** Related assets (routes, files) from the surface map. */
  relatedAssets?: string[];
  /** Max follow-ups to generate (default 3). */
  maxFollowups?: number;
  /** Optional truncation limit for the response body payload (default 2000). */
  bodyTruncationBytes?: number;
  /** Optional planner invoke options (sessionId, timeouts, etc.). */
  invokeOptions?: Partial<InvokeOptions<unknown>>;
}

export interface FollowupGenerationResult {
  probes: LiveProbeRequest[];
  reasoning: string;
  source: 'model' | 'deterministic' | 'disabled';
  fallbackReason?: string;
}

const FollowupProbeSchema = z.object({
  probeKind: z.string().optional(),
  identityId: z.string().optional(),
  http: z
    .object({
      method: z.string().optional(),
      path: z.string().optional(),
      headers: z.record(z.union([z.string(), z.number(), z.boolean()])).optional(),
      body: z.unknown().optional(),
    })
    .passthrough()
    .optional(),
  rationale: z.string().optional(),
}).passthrough();

const FollowupResponseSchema = z.object({
  probes: z.array(FollowupProbeSchema).default([]),
  reasoning: z.string().default(''),
}).passthrough();

type FollowupResponsePayload = z.infer<typeof FollowupResponseSchema>;

const DEFAULT_BODY_TRUNCATION = 2000;

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

const REDACT_PATTERNS: Array<[RegExp, string]> = [
  [/eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/g, '[redacted-jwt]'],
  [/Bearer\s+[A-Za-z0-9._\-]+/g, 'Bearer [redacted-token]'],
  [/sk-[A-Za-z0-9]{16,}/g, '[redacted-key]'],
  [/("(?:password|secret|api_key|token)"\s*:\s*)"[^"]+"/gi, '$1"[redacted]"'],
];

function redactBody(body: string, limit: number): string {
  let safe = body.slice(0, limit);
  for (const [pattern, replacement] of REDACT_PATTERNS) {
    safe = safe.replace(pattern, replacement);
  }
  if (body.length > limit) {
    safe += `\n[...truncated ${body.length - limit} bytes]`;
  }
  return safe;
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

export async function generateFollowupProbes(
  context: FollowupGenerationContext,
  adapter?: ModelAdapter,
): Promise<FollowupGenerationResult> {
  const maxFollowups = Math.max(1, Math.min(3, context.maxFollowups ?? 3));

  if (!adapter) {
    return buildDeterministicFollowups(context, 'no planner adapter available', maxFollowups);
  }

  const prompt = buildFollowupPrompt(context);

  try {
    const response = await adapter.invoke<FollowupResponsePayload>({
      ...((context.invokeOptions ?? {}) as Partial<InvokeOptions<FollowupResponsePayload>>),
      systemPrompt: FOLLOWUP_SYSTEM_PROMPT,
      prompt,
      maxTokens: 1024,
      temperature: 0.3,
      schema: FollowupResponseSchema,
    });

    const parsed = parseFollowupResponse(response, context, maxFollowups);
    if (parsed.probes.length === 0) {
      return buildDeterministicFollowups(
        context,
        `model returned zero valid probes: ${response.content.slice(0, 180)}`,
        maxFollowups,
      );
    }
    return parsed;
  } catch (error) {
    return buildDeterministicFollowups(
      context,
      error instanceof Error ? error.message : String(error),
      maxFollowups,
    );
  }
}

function buildFollowupPrompt(context: FollowupGenerationContext): string {
  const truncation = context.bodyTruncationBytes ?? DEFAULT_BODY_TRUNCATION;
  const redactedBody = redactBody(context.result.response.body ?? '', truncation);
  const related = (context.relatedAssets ?? []).slice(0, 8);

  const lines = [
    '## Finding ID',
    context.findingId,
    '',
    '## Hypothesis Under Test',
    context.hypothesis,
    '',
    '## Original Probe',
    `${context.originalProbe.http?.method ?? 'GET'} ${context.originalProbe.http?.path ?? '/'} as ${context.originalProbe.identityId}`,
    context.originalProbe.rationale ? `Rationale: ${context.originalProbe.rationale}` : '',
    '',
    '## Surprising Response',
    `Status: ${context.result.response.status}`,
    `Latency: ${context.result.response.durationMs}ms`,
    '',
    '### Surprise Indicators',
    `- statusMismatch: ${context.classification.indicators.statusMismatch}`,
    `- errorLeakage: ${context.classification.indicators.errorLeakage}`,
    `- anomalousLatency: ${context.classification.indicators.anomalousLatency}`,
    '',
    '### Redacted Body',
    '```',
    redactedBody,
    '```',
    '',
    '## Available Identities',
    context.availableIdentities.join(', '),
    '',
    '## Related Assets',
    related.length > 0 ? related.join('\n') : 'None',
    '',
    '## Constraint',
    `Propose up to ${context.maxFollowups ?? 3} follow-up probes.`,
  ];

  return lines.filter((line) => line !== '').join('\n');
}

function parseFollowupResponse(
  response: { content: string; structured?: FollowupResponsePayload },
  context: FollowupGenerationContext,
  maxFollowups: number,
): FollowupGenerationResult {
  const parsed = response.structured ?? tryParseStructured(response.content, FollowupResponseSchema);
  if (!parsed) {
    return {
      probes: [],
      reasoning: '',
      source: 'model',
      fallbackReason: `failed to parse follow-up response: ${response.content.slice(0, 180)}`,
    };
  }

  const probes: LiveProbeRequest[] = parsed.probes
    .flatMap((probe, index) => {
      const http = normalizeFollowupHttp(probe.http);
      if (!http) {
        return [];
      }
      return [{
        findingId: context.findingId,
        hypothesis: context.hypothesis,
        probeKind: 'http' as const,
        identityId: normalizeIdentity(probe.identityId, context.availableIdentities),
        rationale: probe.rationale ?? `adaptive follow-up #${index + 1}`,
        http,
      }];
    })
    .slice(0, maxFollowups);

  return {
    probes,
    reasoning: parsed.reasoning,
    source: 'model',
  };
}

function buildDeterministicFollowups(
  context: FollowupGenerationContext,
  fallbackReason: string,
  maxFollowups: number,
): FollowupGenerationResult {
  // Deterministic fallback: retry the original probe path with a different
  // identity + an OPTIONS probe to enumerate allowed methods. This never
  // mutates and does not need a model.
  const identities = context.availableIdentities;
  const otherIdentity = identities.find((id) => id !== context.originalProbe.identityId) ?? identities[0] ?? 'anonymous';
  const path = context.originalProbe.http?.path ?? '/';
  const probes: LiveProbeRequest[] = [
    {
      findingId: context.findingId,
      hypothesis: context.hypothesis,
      probeKind: 'http',
      identityId: otherIdentity,
      rationale: 'deterministic follow-up: replay with a different identity to compare behavior',
      http: {
        method: (context.originalProbe.http?.method ?? 'GET') as 'GET',
        path,
      },
    },
    {
      findingId: context.findingId,
      hypothesis: context.hypothesis,
      probeKind: 'http',
      identityId: context.originalProbe.identityId,
      rationale: 'deterministic follow-up: HEAD probe to enumerate response headers without side effects',
      http: {
        method: 'HEAD',
        path,
      },
    },
  ];
  return {
    probes: probes.slice(0, maxFollowups),
    reasoning: `Deterministic follow-up fallback: ${fallbackReason}`,
    source: 'deterministic',
    fallbackReason,
  };
}

function normalizeIdentity(value: string | undefined, available: string[]): string {
  if (value && available.includes(value)) return value;
  return available[0] ?? 'anonymous';
}

function normalizeFollowupHttp(
  http: FollowupResponsePayload['probes'][number]['http'],
): LiveProbeRequest['http'] | undefined {
  if (!http?.path || http.path.trim().length === 0) {
    return undefined;
  }

  return {
    method: normalizeMethod(http.method),
    path: http.path,
    headers: normalizeHeaders(http.headers),
    body: normalizeBody(http.body),
  };
}

function normalizeMethod(value: string | undefined): 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' {
  const upper = value?.toUpperCase?.() ?? 'GET';
  if (upper === 'GET' || upper === 'POST' || upper === 'PUT' || upper === 'PATCH' || upper === 'DELETE' || upper === 'HEAD') {
    return upper;
  }
  return 'GET';
}

function normalizeHeaders(
  headers: Record<string, string | number | boolean> | undefined,
): Record<string, string> | undefined {
  if (!headers) {
    return undefined;
  }

  const normalized = Object.fromEntries(
    Object.entries(headers).map(([key, value]) => [key, String(value)]),
  );
  return Object.keys(normalized).length > 0 ? normalized : undefined;
}

function normalizeBody(body: unknown): string | undefined {
  if (body == null) {
    return undefined;
  }
  if (typeof body === 'string') {
    return body;
  }
  if (typeof body === 'number' || typeof body === 'boolean') {
    return String(body);
  }
  try {
    return JSON.stringify(body);
  } catch {
    return undefined;
  }
}
