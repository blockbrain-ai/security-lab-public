/**
 * Hypothesis translator — converts a static security hypothesis
 * into a sequence of live HTTP probes that would confirm or refute it.
 */

import { z } from 'zod';
import type { InvokeOptions, ModelAdapter, ModelResponse } from '../../providers/contracts.js';
import { tryParseStructured } from '../../providers/parse-structured.js';
import type { RouteSurface } from '../../intelligence/contracts.js';
import type { ExpectedResponse, LiveProbeRequest } from './contracts.js';
import { rankRoutesByRelevance } from './route-similarity.js';
import { classifyHypothesis } from '../probe-intelligence/probe-families.js';
import {
  generateFamilyVariants,
  type VariantGenerationRequest,
} from '../probe-intelligence/probe-variant-generator.js';
import type { TargetFamilyCapability } from '../probe-intelligence/probe-families.js';

// ---------------------------------------------------------------------------
// Translation request
// ---------------------------------------------------------------------------

export interface TranslationRequest {
  findingId: string;
  hypothesis: string;
  /** Available identity IDs from the target's identity ladder. */
  availableIdentities: string[];
  /** Hints from the target profile. */
  targetHints?: Record<string, unknown>;
  /** Related files, routes, or assets from the static/runtime graph. */
  relatedAssets?: string[];
  /** Round number inside the iterative local-live loop. */
  round?: number;
  /** Prior probe observations for this packet. */
  priorProbeResults?: Array<{
    verdict: string;
    reasoning: string;
    method?: string;
    path?: string;
    status?: number;
  }>;
  /** Dormant thread summaries that may become relevant at runtime. */
  dormantSignals?: string[];
  /** Runtime-discovered weak signal summaries from earlier rounds. */
  runtimeSignals?: string[];
  /** Maximum number of probes to generate. */
  maxProbes?: number;
  /** Routes from the target's surface map for route inference. */
  surfaceRoutes?: RouteSurface[];
  /** Optional packet context file for CLI-backed workers. */
  contextFilePath?: string;
}

// ---------------------------------------------------------------------------
// Translation prompts
// ---------------------------------------------------------------------------

export const TRANSLATOR_SYSTEM_PROMPT = `You are a security verification engineer. You receive a static hypothesis about a potential vulnerability and produce a sequence of live HTTP probes that would confirm or refute it against a locally-running instance.

You are NOT limited to replaying the obvious chain. Use prior runtime observations, dormant threads, and newly discovered weak signals to propose alternative confirmation routes when the first attempt is refuted or inconclusive.

Each probe must:
- Specify the HTTP method, path, headers, and body
- Specify which identity to use from the available identity ladder
- Be specific enough to actually be executed

Operational guardrails:
- Inspect files and prior evidence as needed, but DO NOT run Security Lab, restart the pipeline, or launch services yourself
- DO NOT execute npm run investigate, verify-from-campaign, tsx src/autonomous/cli.ts, docker compose, or equivalent wrappers
- DO NOT send live HTTP probes directly; describe the probes for the orchestrator to execute

Output JSON:
{
  "probes": [
    {
      "probeKind": "http",
      "identityId": "anonymous | user_a_low | etc.",
      "http": {
        "method": "GET | POST | etc",
        "path": "/api/...",
        "headers": { },
        "body": "..."
      },
      "rationale": "why this probe matters"
    }
  ],
  "reasoning": "overall translation strategy"
}`;

// ---------------------------------------------------------------------------
// Translator
// ---------------------------------------------------------------------------

export interface TranslationResult {
  probes: LiveProbeRequest[];
  reasoning: string;
  source: 'model' | 'deterministic';
  fallbackReason?: string;
  invocation?: {
    prompt: string;
    systemPrompt: string;
    response: ModelResponse<unknown>;
    parseSuccess: boolean;
  };
}

const HttpMethodSchema = z
  .string()
  .trim()
  .transform((value) => value.toUpperCase())
  .pipe(z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD']));

const TranslationExpectedResponseSchema = z.object({
  status: z.number().int().optional(),
  statusIn: z.array(z.number().int()).optional(),
  bodyContains: z.array(z.string()).optional(),
  bodyNotContains: z.array(z.string()).optional(),
}).passthrough();

const TranslationProbeSchema = z.object({
  probeKind: z.string().optional(),
  identityId: z.string().optional(),
  rationale: z.string().optional(),
  probeFamily: z.string().optional(),
  probeVariant: z.string().optional(),
  http: z.object({
    method: HttpMethodSchema.optional(),
    path: z.string().optional(),
    headers: z.record(z.union([z.string(), z.number(), z.boolean()])).optional(),
    body: z.unknown().optional(),
  }).optional(),
  expectedWhenSafe: TranslationExpectedResponseSchema.optional(),
  expectedWhenExploitable: TranslationExpectedResponseSchema.optional(),
  process: z.object({
    action: z.string().optional(),
    searchPatterns: z.array(z.string()).optional(),
  }).optional(),
  persistence: z.object({
    action: z.string().optional(),
  }).optional(),
}).passthrough();

const TranslationResponseSchema = z.object({
  probes: z.array(TranslationProbeSchema).default([]),
  reasoning: z.string().default(''),
}).passthrough();

type TranslationResponsePayload = z.infer<typeof TranslationResponseSchema>;

export async function translateHypothesisToLiveProbes(
  request: TranslationRequest,
  adapter?: ModelAdapter,
  options?: { invokeOptions?: Partial<InvokeOptions<TranslationResult>> },
): Promise<TranslationResult> {
  if (!adapter) {
    return buildDeterministicTranslation(request, 'no planner adapter available');
  }

  const prompt = buildTranslationPrompt(
    request,
    Boolean(options?.invokeOptions?.sessionId),
    isCliBackedAdapter(adapter),
  );

  try {
    const response = await adapter.invoke<TranslationResponsePayload>({
      ...((options?.invokeOptions ?? {}) as Partial<InvokeOptions<TranslationResponsePayload>>),
      systemPrompt: TRANSLATOR_SYSTEM_PROMPT,
      prompt,
      maxTokens: 2048,
      temperature: 0.2,
      schema: TranslationResponseSchema,
    });

    const parsed = parseTranslationResponse(response, request);
    return {
      ...parsed,
      invocation: {
        prompt,
        systemPrompt: TRANSLATOR_SYSTEM_PROMPT,
        response,
        parseSuccess: parsed.source === 'model',
      },
    };
  } catch (error) {
    return buildDeterministicTranslation(
      request,
      error instanceof Error ? error.message : String(error),
    );
  }
}

function buildTranslationPrompt(
  request: TranslationRequest,
  continuation: boolean,
  cliBacked: boolean,
): string {
  if (cliBacked && request.contextFilePath) {
    return [
      continuation
        ? 'Continue the same local-live investigation on the same target. Reuse the existing route and middleware understanding from this session unless runtime evidence changes it.'
        : 'Read the packet context file and translate the hypothesis into the next bounded local-live probe sequence.',
      '## Packet Context File',
      request.contextFilePath,
      '',
      'Read that JSON file directly with your tools before proposing probes.',
      'The file contains the hypothesis, identities, target hints, prior probe results, runtime signals, dormant signals, related assets, and route candidates for this packet.',
      'Use the packet file as the primary context. Only inspect additional source files if the packet evidence is insufficient to choose or refine probes.',
      'Do not broad-scan the repository before proposing the next bounded probe sequence.',
      '',
      '## Constraint',
      `Generate at most ${request.maxProbes ?? 5} live probes.`,
      '',
      'Return exactly one JSON object and nothing else.',
      'Put any explanation inside the JSON "reasoning" field.',
      'Return JSON only using the schema from the system prompt.',
    ].join('\n');
  }

  const compactHints = compactTargetHints(request.targetHints, { continuation });
  const relatedAssets = dedupeAndLimit(request.relatedAssets, continuation ? 6 : 10);
  const dormantSignals = dedupeAndLimit(request.dormantSignals, continuation ? 4 : 8);
  const runtimeSignals = dedupeAndLimit(request.runtimeSignals, continuation ? 4 : 8);
  const sections = continuation
    ? [
        'Continue the same local-live investigation on the same target. Reuse the existing target understanding and prior route/middleware context from this session unless new runtime evidence changes it.',
        '## Finding ID',
        request.findingId,
        '',
        '## Working Hypothesis Summary',
        summarizeForContinuation(request.hypothesis),
        '',
        '## Available Identities',
        request.availableIdentities.join(', '),
        '',
        '## Local-Live Round',
        String(request.round ?? 1),
        '',
        '## Delta Since Last Round',
        `Prior probe results:\n${formatPriorProbeResults(request.priorProbeResults, 3)}`,
        '',
        'Runtime signals:',
        runtimeSignals.length > 0 ? runtimeSignals.join('\n') : 'None',
        '',
        'Dormant signals worth reconsidering:',
        dormantSignals.length > 0 ? dormantSignals.join('\n') : 'None',
        '',
        '## Related Assets',
        relatedAssets.length > 0 ? relatedAssets.join('\n') : 'None',
        '',
        '## Minimal Target Hints',
        JSON.stringify(compactHints, null, 2),
        '',
        '## Constraint',
        `Generate at most ${request.maxProbes ?? 5} live probes.`,
        '',
        'Translate only the next probe sequence for this packet. Prefer alternative confirmation routes if earlier probes were refuted or inconclusive.',
      ]
    : [
        '## Finding ID',
        request.findingId,
        '',
        '## Hypothesis',
        request.hypothesis,
        '',
        '## Available Identities',
        request.availableIdentities.join(', '),
        '',
        '## Target Hints',
        JSON.stringify(compactHints, null, 2),
        '',
        '## Related Assets',
        relatedAssets.length > 0 ? relatedAssets.join('\n') : 'None',
        '',
        '## Local-Live Round',
        String(request.round ?? 1),
        '',
        '## Prior Probe Results',
        formatPriorProbeResults(request.priorProbeResults, 8),
        '',
        '## Dormant Signals',
        dormantSignals.length > 0 ? dormantSignals.join('\n') : 'None',
        '',
        '## Runtime Signals',
        runtimeSignals.length > 0 ? runtimeSignals.join('\n') : 'None',
        '',
        '## Constraint',
        `Generate at most ${request.maxProbes ?? 5} live probes.`,
        '',
        'Translate the hypothesis into a probe sequence.',
      ];

  return sections.filter((section) => section !== null).join('\n');
}

function summarizeForContinuation(hypothesis: string): string {
  const normalized = hypothesis.replace(/\s+/g, ' ').trim();
  if (normalized.length <= 420) {
    return normalized;
  }
  return `${normalized.slice(0, 417)}...`;
}

function parseTranslationResponse(
  response: ModelResponse<TranslationResponsePayload>,
  request: TranslationRequest,
): TranslationResult {
  const parsed = response.structured ?? tryParseStructured(response.content, TranslationResponseSchema);
  if (parsed) {
    const modelResult = buildModelTranslation(parsed, request);
    if (modelResult.probes.length > 0) {
      return modelResult;
    }
    return buildDeterministicTranslation(
      request,
      `model returned zero valid probes: ${response.content.slice(0, 300)}`,
    );
  }

  return buildDeterministicTranslation(
    request,
    `failed to parse translation response: ${response.content.slice(0, 300)}`,
  );
}

function buildModelTranslation(
  parsed: TranslationResponsePayload,
  request: TranslationRequest,
): TranslationResult {
  const hypothesisFamily = classifyHypothesis(request.hypothesis);
  const probes = parsed.probes
    .map((probe) => buildLiveProbeRequest(probe, request, hypothesisFamily))
    .filter((probe): probe is LiveProbeRequest => probe !== null);

  return {
    probes,
    reasoning: parsed.reasoning,
    source: 'model',
  };
}

function buildDeterministicTranslation(
  request: TranslationRequest,
  fallbackReason: string,
): TranslationResult {
  const routeRefs = extractRouteReferences(request);
  const baseProbes = routeRefs.flatMap((routeRef) => buildProbesForRouteRef(routeRef, request));

  // Section 11.2 — enrich with family-shaped variants
  const familyCapabilities = resolveFamilyCapabilitiesFromHints(request.targetHints);
  const familyProbes = generateFamilyProbesForRoutes(routeRefs, request, familyCapabilities);

  // Merge: family variants first (they're more targeted), then base probes
  const allProbes = deduplicateProbes([...familyProbes, ...baseProbes]);

  return {
    probes: allProbes.slice(0, request.maxProbes ?? 5),
    reasoning: `Deterministic translation fallback used: ${fallbackReason}`,
    source: 'deterministic',
    fallbackReason,
  };
}

/**
 * Section 11.2 — Generate family-shaped probe variants for each route reference.
 */
function generateFamilyProbesForRoutes(
  routeRefs: RouteReference[],
  request: TranslationRequest,
  familyCapabilities?: TargetFamilyCapability[],
): LiveProbeRequest[] {
  const family = classifyHypothesis(request.hypothesis);
  if (family === 'generic') return [];

  const probes: LiveProbeRequest[] = [];
  for (const routeRef of routeRefs) {
    const genRequest: VariantGenerationRequest = {
      findingId: request.findingId,
      hypothesis: request.hypothesis,
      basePath: routeRef.path,
      baseMethod: routeRef.method,
      availableIdentities: request.availableIdentities,
      familyCapabilities,
      maxVariants: Math.max(2, Math.floor((request.maxProbes ?? 5) / Math.max(routeRefs.length, 1))),
    };
    const result = generateFamilyVariants(genRequest);
    probes.push(...result.probes);
  }
  return probes;
}

/**
 * Extract TargetFamilyCapability[] from target hints' liveProbing config.
 */
function resolveFamilyCapabilitiesFromHints(
  hints?: Record<string, unknown>,
): TargetFamilyCapability[] | undefined {
  const liveProbing = hints?.['liveProbing'] as Record<string, unknown> | undefined;
  if (!liveProbing) return undefined;
  const raw = liveProbing['probeFamilies'];
  if (!Array.isArray(raw)) return undefined;
  return raw
    .filter((entry): entry is Record<string, unknown> => entry != null && typeof entry === 'object')
    .map((entry) => ({
      family: (typeof entry['family'] === 'string' ? entry['family'] : 'generic') as TargetFamilyCapability['family'],
      disabledVariants: Array.isArray(entry['disabledVariants'])
        ? entry['disabledVariants'].filter((v): v is string => typeof v === 'string')
        : undefined,
      extraHeaders: entry['extraHeaders'] != null && typeof entry['extraHeaders'] === 'object'
        ? entry['extraHeaders'] as Record<string, string>
        : undefined,
    }));
}

/**
 * Deduplicate probes by (method, path, identityId) key.
 * Family-variant probes appear first and win ties.
 */
function deduplicateProbes(probes: LiveProbeRequest[]): LiveProbeRequest[] {
  const seen = new Set<string>();
  const result: LiveProbeRequest[] = [];
  for (const probe of probes) {
    const key = `${probe.http?.method ?? ''}:${probe.http?.path ?? ''}:${probe.identityId}:${probe.probeVariant ?? ''}`;
    if (!seen.has(key)) {
      seen.add(key);
      result.push(probe);
    }
  }
  return result;
}

function formatPriorProbeResults(
  priorProbeResults: TranslationRequest['priorProbeResults'],
  limit: number,
): string {
  if (!priorProbeResults || priorProbeResults.length === 0) {
    return 'None';
  }

  return priorProbeResults
    .slice(-limit)
    .map((result) => {
      const requestLine = [result.method, result.path].filter(Boolean).join(' ').trim();
      const status = typeof result.status === 'number' ? ` status=${result.status}` : '';
      return `- [${result.verdict}] ${requestLine || 'probe'}${status} :: ${result.reasoning}`;
    })
    .join('\n');
}

function compactTargetHints(
  targetHints?: Record<string, unknown>,
  options?: { continuation?: boolean },
): Record<string, unknown> {
  if (!targetHints) {
    return {};
  }

  const continuation = options?.continuation === true;
  const compact: Record<string, unknown> = {};
  const copyScalarKeys = [
    'stack',
    'framework',
    'apiPrefix',
    'healthEndpoint',
    'authMechanism',
    'tenantHeader',
  ];
  for (const key of copyScalarKeys) {
    if (typeof targetHints[key] === 'string') {
      compact[key] = targetHints[key];
    }
  }

  const copyArrayKeys = ['highValuePatterns'];
  for (const key of copyArrayKeys) {
    const value = targetHints[key];
    if (Array.isArray(value)) {
      compact[key] = value.slice(0, continuation ? 4 : 8);
    }
  }

  const seedData = targetHints['seedData'];
  if (seedData && typeof seedData === 'object') {
    const seed = seedData as {
      tenants?: Array<{ id?: string }>;
      records?: Array<{ id?: string; type?: string; tenantId?: string }>;
    };
    compact['seedData'] = {
      tenantIds: (seed.tenants ?? []).map((tenant) => tenant.id).filter(Boolean).slice(0, continuation ? 3 : 5),
      records: (seed.records ?? [])
        .map((record) => `${record.type ?? 'record'}:${record.id ?? 'unknown'}@${record.tenantId ?? 'unknown'}`)
        .slice(0, continuation ? 6 : 8),
    };
  }

  return compact;
}

function dedupeAndLimit(values: string[] | undefined, limit: number): string[] {
  return [...new Set((values ?? []).filter(Boolean))].slice(0, limit);
}

function isCliBackedAdapter(adapter: ModelAdapter | undefined): boolean {
  return adapter?.provider === 'claude_code' || adapter?.provider === 'codex_cli';
}

function extractRouteReferences(request: TranslationRequest): RouteReference[] {
  const refs = new Map<string, RouteReference>();
  const explicitRouteRegex = /\b(GET|POST|PUT|PATCH|DELETE|HEAD)\s+([/][^\s),.;]+)/gi;
  for (const match of request.hypothesis.matchAll(explicitRouteRegex)) {
    const method = match[1]?.toUpperCase() as RouteReference['method'] | undefined;
    const rawPath = match[2];
    if (!method || !rawPath) {
      continue;
    }
    const normalizedPath = normalizeRoutePath(rawPath, request);
    refs.set(`${method}:${normalizedPath}`, {
      method,
      path: normalizedPath,
      source: 'explicit',
    });
  }

  if (refs.size === 0) {
    for (const inferred of inferRouteReferencesFromSurfaceMap(request)) {
      refs.set(`${inferred.method}:${inferred.path}`, inferred);
    }
  }

  return [...refs.values()].slice(0, request.maxProbes ?? 5);
}

function inferRouteReferencesFromSurfaceMap(request: TranslationRequest): RouteReference[] {
  const apiPrefix = typeof request.targetHints?.['apiPrefix'] === 'string'
    ? String(request.targetHints['apiPrefix'])
    : '/api/v1';

  if (request.surfaceRoutes && request.surfaceRoutes.length > 0) {
    const ranked = rankRoutesByRelevance(request.hypothesis, request.surfaceRoutes, request.maxProbes ?? 5);
    if (ranked.length > 0) {
      return ranked.map((r) => ({
        method: (r.method.toUpperCase() as RouteReference['method']),
        path: materializeDynamicSegments(r.path, request),
        source: 'keyword' as const,
      }));
    }
  }

  // Fallback: derive a generic admin/health route when no surface map is available
  const lower = request.hypothesis.toLowerCase();
  const refs: RouteReference[] = [];
  const method = extractMethodFromHypothesis(lower);

  // Extract route-like segments from the hypothesis text itself
  const routeMatch = lower.match(/(?:\/[a-z0-9_-]+(?:\/[a-z0-9_{}-]*)*)/g);
  if (routeMatch) {
    for (const rawPath of routeMatch) {
      const normalizedPath = rawPath.startsWith(apiPrefix)
        ? rawPath
        : `${apiPrefix}${rawPath}`;
      refs.push({
        method,
        path: materializeDynamicSegments(normalizedPath, request),
        source: 'keyword',
      });
    }
  }

  if (refs.length === 0 && /admin|auth|jwt|tenant|organization|scope/.test(lower)) {
    refs.push({ method: 'GET', path: `${apiPrefix}/health`, source: 'keyword' });
  }

  return refs;
}

function extractMethodFromHypothesis(lower: string): RouteReference['method'] {
  if (/\bpost\b|execute|create|approve|reject|cancel|submit/.test(lower)) return 'POST';
  if (/\bdelete\b|revoke|remove/.test(lower)) return 'DELETE';
  if (/\bput\b|update|modify/.test(lower)) return 'PUT';
  if (/\bpatch\b/.test(lower)) return 'PATCH';
  return 'GET';
}

function buildProbesForRouteRef(routeRef: RouteReference, request: TranslationRequest): LiveProbeRequest[] {
  const identities = chooseProbeIdentities(routeRef, request);
  const expectations = inferExpectations(routeRef, request.hypothesis, identities);

  return identities.map((identityId) => ({
    findingId: request.findingId,
    hypothesis: request.hypothesis,
    probeKind: 'http',
    identityId,
    rationale: `Deterministic ${routeRef.source} route translation for ${routeRef.method} ${routeRef.path}`,
    http: {
      method: routeRef.method,
      path: routeRef.path,
    },
    expectedWhenSafe: expectations.safe[identityId] ?? expectations.defaultSafe,
    expectedWhenExploitable: expectations.exploitable[identityId] ?? expectations.defaultExploitable,
  }));
}

function chooseProbeIdentities(routeRef: RouteReference, request: TranslationRequest): string[] {
  const lower = `${request.hypothesis} ${routeRef.path}`.toLowerCase();
  const identities = new Set<string>();
  const unauthBoundary = isUnauthenticatedAccessHypothesis(lower);
  const privilegeBoundary = isPrivilegeOrTenantBoundaryHypothesis(lower);

  if (unauthBoundary && !privilegeBoundary) {
    identities.add(preferIdentity(request.availableIdentities, ['guest', 'anonymous', 'anon']) ?? request.availableIdentities[0] ?? 'guest');
    return [...identities].slice(0, request.maxProbes ?? 5);
  }

  if (privilegeBoundary) {
    identities.add(preferIdentity(request.availableIdentities, ['user_a_low', 'user_a_canary', 'service_canary', 'guest']) ?? request.availableIdentities[0] ?? 'guest');
  }

  if (identities.size === 0) {
    const fallbackIdentity = routeRef.method === 'GET'
      ? preferIdentity(request.availableIdentities, ['guest', 'anonymous', 'anon', 'user_a_low'])
      : preferIdentity(request.availableIdentities, ['user_a_low', 'service_canary', 'guest']);
    identities.add(fallbackIdentity ?? request.availableIdentities[0] ?? 'guest');
  }

  return [...identities].slice(0, request.maxProbes ?? 5);
}

function inferExpectations(
  routeRef: RouteReference,
  hypothesis: string,
  identities: string[],
): {
  defaultSafe: ExpectedResponse;
  defaultExploitable: ExpectedResponse;
  safe: Record<string, ExpectedResponse>;
  exploitable: Record<string, ExpectedResponse>;
} {
  const lower = `${hypothesis} ${routeRef.path}`.toLowerCase();
  const mutation = routeRef.method !== 'GET' && routeRef.method !== 'HEAD';
  const protectedBoundary = /(admin|approve|reject|cancel|bulk|execute|api key|api-key|tenant|org|organization|jwt|scope|buyer-room|protected)/.test(lower);
  const unauthBoundary = isUnauthenticatedAccessHypothesis(lower);
  const privilegeBoundary = isPrivilegeOrTenantBoundaryHypothesis(lower);
  const safeStatusIn = protectedBoundary || mutation ? [401, 403, 404] : [401, 403, 404];
  const guestExploitableStatusIn = mutation ? [200, 201, 202, 204, 400, 409, 422] : [200];
  const privilegeExploitableStatusIn = mutation ? [200, 201, 202, 204] : [200];
  const defaultSafe: ExpectedResponse = { statusIn: safeStatusIn };
  const defaultExploitable: ExpectedResponse = { statusIn: guestExploitableStatusIn };

  const safe: Record<string, ExpectedResponse> = {};
  const exploitable: Record<string, ExpectedResponse> = {};
  for (const identityId of identities) {
    if (identityId === 'guest' || identityId === 'anonymous' || identityId === 'anon') {
      safe[identityId] = { statusIn: [401, 403, 404] };
      exploitable[identityId] = { statusIn: guestExploitableStatusIn };
      continue;
    }

    if (unauthBoundary && !privilegeBoundary) {
      safe[identityId] = {
        statusIn: mutation ? [200, 201, 202, 204, 400, 401, 403, 404, 409, 422] : [200, 401, 403, 404],
      };
      exploitable[identityId] = { statusIn: [] };
      continue;
    }

    if (privilegeBoundary) {
      safe[identityId] = { statusIn: [401, 403, 404] };
      exploitable[identityId] = { statusIn: privilegeExploitableStatusIn };
      continue;
    }

    safe[identityId] = defaultSafe;
    exploitable[identityId] = { statusIn: privilegeExploitableStatusIn };
  }

  return { defaultSafe, defaultExploitable, safe, exploitable };
}

function isUnauthenticatedAccessHypothesis(lower: string): boolean {
  return /(anonymous|unauth|unauthenticated|without auth|missing auth|no auth|guest|auth bypass|fail-open jwt|auth=not_observed|public route|public router|route-order auth bypass|route bleed)/.test(lower);
}

function isPrivilegeOrTenantBoundaryHypothesis(lower: string): boolean {
  return /(cross-tenant|cross tenant|idor|impersonat|org b|organization b|tenant isolation|privilege escalation|elevated trust|scope|admin_canary|service_canary|header[- ]sourced org|x-[a-z]+-id|org id|organization id|wrong org|target org|tenant.?header)/.test(lower);
}

function normalizeRoutePath(path: string, request: TranslationRequest): string {
  const trimmed = path.replace(/[),.;:]+$/g, '');
  const apiPrefix = typeof request.targetHints?.['apiPrefix'] === 'string'
    ? String(request.targetHints['apiPrefix'])
    : undefined;

  let normalized = trimmed;
  if (!normalized.startsWith('/')) {
    normalized = `/${normalized}`;
  }

  if (apiPrefix && !normalized.startsWith(apiPrefix)) {
    const resourcePrefix = inferResourcePrefixFromSurfaceMap(request.hypothesis, normalized, request);
    if (normalized === '/' || /^\/:/.test(normalized)) {
      normalized = resourcePrefix ? `${apiPrefix}/${resourcePrefix}${normalized}` : `${apiPrefix}${normalized}`;
    } else if (!normalized.startsWith('/api/')) {
      if (resourcePrefix && !normalized.startsWith(`/${resourcePrefix}/`) && normalized !== `/${resourcePrefix}`) {
        normalized = `${apiPrefix}/${resourcePrefix}${normalized}`;
      } else {
        normalized = `${apiPrefix}${normalized}`;
      }
    }
  }

  return materializeDynamicSegments(normalized, request);
}

function materializeDynamicSegments(path: string, request: TranslationRequest): string {
  let normalized = path;
  // Infer record type from the path segments for seed data lookup
  const pathSegments = normalized.split('/').filter(Boolean);
  const resourceSegment = pathSegments.find((seg) => !seg.startsWith(':') && !seg.startsWith('{') && seg.length > 2);
  const recordType = resourceSegment ? inferRecordType(resourceSegment) : undefined;
  const crossTenantRecord =
    getCrossTenantRecordId(request, recordType) ??
    getSeededRecordId(request, recordType) ??
    getCrossTenantRecordId(request) ??
    getSeededRecordId(request) ??
    'canary_record';
  normalized = normalized.replace(/:id\b/g, crossTenantRecord);
  normalized = normalized.replace(/\{id\}/g, crossTenantRecord);
  normalized = normalized.replace(/:subjectId\b/g, crossTenantRecord);
  normalized = normalized.replace(/:recordId\b/g, crossTenantRecord);
  return normalized;
}

/**
 * Infer a record type from a path segment by singularizing common patterns.
 * No hardcoded target-specific knowledge — purely morphological.
 */
function inferRecordType(segment: string): string | undefined {
  const lower = segment.toLowerCase();
  // Simple singularization: strip trailing 's' for common plural resources
  if (lower.endsWith('ies')) return lower.slice(0, -3) + 'y';
  if (lower.endsWith('ses')) return lower.slice(0, -2);
  if (lower.endsWith('s') && !lower.endsWith('ss')) return lower.slice(0, -1);
  return lower;
}

function inferResourcePrefixFromSurfaceMap(
  hypothesis: string,
  _path: string,
  request: TranslationRequest,
): string | null {
  if (!request.surfaceRoutes || request.surfaceRoutes.length === 0) {
    return null;
  }
  const ranked = rankRoutesByRelevance(hypothesis, request.surfaceRoutes, 1);
  if (ranked.length === 0) {
    return null;
  }
  // Extract the first meaningful path segment from the best-matching route
  const segments = ranked[0]!.path.split('/').filter(Boolean);
  // Skip known API prefix segments
  const apiPrefix = typeof request.targetHints?.['apiPrefix'] === 'string'
    ? request.targetHints['apiPrefix'].split('/').filter(Boolean)
    : [];
  for (const seg of segments) {
    if (!apiPrefix.includes(seg) && !seg.startsWith(':') && !seg.startsWith('{')) {
      return seg;
    }
  }
  return null;
}

function getSeededRecordId(request: TranslationRequest, type?: string): string | undefined {
  const seedData = request.targetHints?.['seedData'] as { records?: Array<{ id?: string; type?: string }> } | undefined;
  const records = seedData?.records ?? [];
  const match = type
    ? records.find((record) => record.type === type && typeof record.id === 'string')
    : records.find((record) => typeof record.id === 'string');
  return typeof match?.id === 'string' ? match.id : undefined;
}

function getCrossTenantRecordId(request: TranslationRequest, type?: string): string | undefined {
  const seedData = request.targetHints?.['seedData'] as { records?: Array<{ id?: string }> } | undefined;
  const records = (seedData?.records ?? []).filter((record): record is { id: string; type?: string } => typeof record.id === 'string');
  const filtered = type ? records.filter((record) => record.type === type) : records;
  const preferred = filtered.find((record) => /(?:_b|-b)$/.test(record.id));
  return preferred?.id ?? filtered.at(-1)?.id;
}

function preferIdentity(availableIdentities: string[], candidates: string[]): string | undefined {
  for (const candidate of candidates) {
    const normalized = normalizeIdentityId(candidate, availableIdentities);
    if (availableIdentities.includes(normalized)) {
      return normalized;
    }
  }
  return undefined;
}

function buildLiveProbeRequest(
  probe: TranslationResponsePayload['probes'][number],
  request: TranslationRequest,
  hypothesisFamily: string,
): LiveProbeRequest | null {
  const http = normalizeHttpProbe(probe.http);
  const process = normalizeProcessProbe(probe.process);
  const persistence = normalizePersistenceProbe(probe.persistence);

  if (!http && !process && !persistence) {
    return null;
  }

  return {
    findingId: request.findingId,
    hypothesis: request.hypothesis,
    probeKind: normalizeProbeKind(probe.probeKind, { http, process, persistence }),
    identityId: normalizeIdentityId(probe.identityId ?? 'guest', request.availableIdentities),
    rationale: probe.rationale,
    probeFamily: probe.probeFamily ?? hypothesisFamily,
    probeVariant: probe.probeVariant,
    http,
    expectedWhenSafe: normalizeExpectedResponse(probe.expectedWhenSafe),
    expectedWhenExploitable: normalizeExpectedResponse(probe.expectedWhenExploitable),
    process,
    persistence,
  };
}

function normalizeProbeKind(
  value: string | undefined,
  payload: {
    http?: LiveProbeRequest['http'];
    process?: LiveProbeRequest['process'];
    persistence?: LiveProbeRequest['persistence'];
  },
): LiveProbeRequest['probeKind'] {
  switch (value) {
    case 'http':
    case 'process':
    case 'persistence':
    case 'browser':
      return value;
    default:
      if (payload.process) return 'process';
      if (payload.persistence) return 'persistence';
      return 'http';
  }
}

function normalizeHttpProbe(
  http: TranslationResponsePayload['probes'][number]['http'],
): LiveProbeRequest['http'] | undefined {
  if (!http?.path || http.path.trim().length === 0) {
    return undefined;
  }

  return {
    method: http.method ?? 'GET',
    path: http.path,
    headers: normalizeHeaders(http.headers),
    body: normalizeRequestBody(http.body),
  };
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

function normalizeRequestBody(body: unknown): string | undefined {
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

function normalizeProcessProbe(
  process: TranslationResponsePayload['probes'][number]['process'],
): LiveProbeRequest['process'] | undefined {
  switch (process?.action) {
    case 'env_scan':
    case 'fd_scan':
    case 'proc_self_read':
    case 'credential_search':
      return {
        action: process.action,
        searchPatterns: process.searchPatterns,
      };
    default:
      return undefined;
  }
}

function normalizePersistenceProbe(
  persistence: TranslationResponsePayload['probes'][number]['persistence'],
): LiveProbeRequest['persistence'] | undefined {
  switch (persistence?.action) {
    case 'cron_check':
    case 'launchd_check':
    case 'background_process_check':
    case 'startup_check':
      return { action: persistence.action };
    default:
      return undefined;
  }
}

function normalizeExpectedResponse(value: unknown): ExpectedResponse | undefined {
  if (!value || typeof value !== 'object') {
    return undefined;
  }
  const record = value as Record<string, unknown>;
  return {
    status: typeof record['status'] === 'number' ? record['status'] : undefined,
    statusIn: Array.isArray(record['statusIn'])
      ? record['statusIn'].filter((entry): entry is number => typeof entry === 'number')
      : undefined,
    bodyContains: Array.isArray(record['bodyContains'])
      ? record['bodyContains'].filter((entry): entry is string => typeof entry === 'string')
      : undefined,
    bodyNotContains: Array.isArray(record['bodyNotContains'])
      ? record['bodyNotContains'].filter((entry): entry is string => typeof entry === 'string')
      : undefined,
  };
}

function normalizeIdentityId(identityId: string, availableIdentities: string[]): string {
  if (availableIdentities.includes(identityId)) {
    return identityId;
  }

  if ((identityId === 'anonymous' || identityId === 'anon') && availableIdentities.includes('guest')) {
    return 'guest';
  }

  const firstAnonymous = availableIdentities.find((candidate) => candidate === 'guest');
  if ((identityId === 'anonymous' || identityId === 'anon') && firstAnonymous) {
    return firstAnonymous;
  }

  return identityId;
}

interface RouteReference {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD';
  path: string;
  source: 'explicit' | 'keyword';
}
