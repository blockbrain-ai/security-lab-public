/**
 * Section 6.2 — Source correlation worker.
 *
 * When a local-live probe result is `confirmed` or flagged as `surprising`
 * (Section 6.1), this module asks a claude-code (or any file-capable)
 * worker adapter to read the handler file(s) for the probe's URL and
 * explain whether the response is consistent with the source code. The
 * output is a structured `CorrelationResult` carrying source refs that
 * the Mythos sub-lane can hand back as provenance on new hypotheses and
 * findings.
 *
 * The worker does NOT send HTTP requests — it only reads local files under
 * the target's repoRoot. This preserves the 4.1 orchestrator-protection
 * rule: workers never reach the network directly.
 */

import { z } from 'zod';
import type { ModelAdapter, InvokeOptions } from '../../providers/contracts.js';
import { tryParseStructured } from '../../providers/parse-structured.js';
import type { LiveExecutionResult } from './contracts.js';
import {
  type SourceLocationRef,
  parseSourceRef,
  toWorkspaceRelative,
} from '../../../../evidence-plane/src/source-location-ref.js';

// ---------------------------------------------------------------------------
// Prompt
// ---------------------------------------------------------------------------

export const SOURCE_CORRELATION_SYSTEM_PROMPT = `You are a security verification engineer. You receive a live HTTP response and the repository of the target service. Your job is to find the handler code for the probe's URL, read it, and explain whether the observed response is consistent with what the handler actually does.

Rules:
- Use your local file-reading tools (read/list/grep) to locate the handler. Do not guess the path — read the code.
- Produce source refs in \`path:startLine-endLine\` form.
- DO NOT send any HTTP requests. DO NOT invoke Security Lab recursively.
- If you cannot find the handler, say so honestly.

Output JSON:
{
  "sourceRefs": ["src/path/to/handler.ts:10-42", ...],
  "analysis": "one or two sentences describing what the handler does",
  "consistencyVerdict": "consistent | inconsistent | inconclusive",
  "consistencyReasoning": "one sentence describing why"
}`;

// ---------------------------------------------------------------------------
// Shapes
// ---------------------------------------------------------------------------

export interface SourceCorrelationContext {
  probeResult: LiveExecutionResult;
  repoRoot: string;
  surfaceMap?: { routes?: Array<{ method?: string; path?: string; handlerFile?: string }> };
  hypothesis: string;
  findingId: string;
  /** Optional per-request timeout. */
  requestTimeoutMs?: number;
}

export interface CorrelationResult {
  sourceRefs: string[];
  /**
   * Section 7.1 — typed source location refs parsed from the worker's
   * `sourceRefs` strings. These flow into the hypothesis and finding.
   */
  sourceLocationRefs: SourceLocationRef[];
  analysis: string;
  consistencyVerdict: 'consistent' | 'inconsistent' | 'inconclusive';
  consistencyReasoning: string;
  source: 'worker' | 'disabled' | 'error';
  fallbackReason?: string;
}

const CorrelationResponseSchema = z.object({
  sourceRefs: z.array(z.string()).default([]),
  analysis: z.string().default(''),
  consistencyVerdict: z.string().default('inconclusive'),
  consistencyReasoning: z.string().default(''),
}).passthrough();

type CorrelationResponsePayload = z.infer<typeof CorrelationResponseSchema>;

// ---------------------------------------------------------------------------
// Per-campaign invocation limit
// ---------------------------------------------------------------------------

export const DEFAULT_SOURCE_CORRELATION_MAX = 10;

export class SourceCorrelationBudget {
  private used = 0;
  constructor(public readonly max: number = DEFAULT_SOURCE_CORRELATION_MAX) {}
  consume(): boolean {
    if (this.used >= this.max) return false;
    this.used += 1;
    return true;
  }
  get remaining(): number {
    return Math.max(0, this.max - this.used);
  }
  get count(): number {
    return this.used;
  }
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

export class SourceCorrelationWorker {
  constructor(
    private readonly adapter: ModelAdapter | undefined,
    private readonly budget: SourceCorrelationBudget,
  ) {}

  /** How many correlation calls have been made so far this campaign. */
  get invocationCount(): number {
    return this.budget.count;
  }

  async correlate(context: SourceCorrelationContext): Promise<CorrelationResult> {
    if (!this.adapter) {
      return {
        sourceRefs: [],
        sourceLocationRefs: [],
        analysis: '',
        consistencyVerdict: 'inconclusive',
        consistencyReasoning: '',
        source: 'disabled',
        fallbackReason: 'no worker adapter available',
      };
    }
    if (!this.budget.consume()) {
      return {
        sourceRefs: [],
        sourceLocationRefs: [],
        analysis: '',
        consistencyVerdict: 'inconclusive',
        consistencyReasoning: '',
        source: 'disabled',
        fallbackReason: 'source correlation budget exhausted',
      };
    }
    const prompt = buildSourceCorrelationPrompt(context);
    const invokeOptions: InvokeOptions<CorrelationResponsePayload> = {
      systemPrompt: SOURCE_CORRELATION_SYSTEM_PROMPT,
      prompt,
      maxTokens: 1024,
      temperature: 0.1,
      workingDirectory: context.repoRoot,
      requestTimeoutMs: context.requestTimeoutMs,
      schema: CorrelationResponseSchema,
    };
    try {
      const response = await this.adapter.invoke(invokeOptions);
      return parseCorrelationResponse(response, context.repoRoot);
    } catch (error) {
      return {
        sourceRefs: [],
        sourceLocationRefs: [],
        analysis: '',
        consistencyVerdict: 'inconclusive',
        consistencyReasoning: '',
        source: 'error',
        fallbackReason: error instanceof Error ? error.message : String(error),
      };
    }
  }
}

export function buildSourceCorrelationPrompt(context: SourceCorrelationContext): string {
  const { probeResult: r, hypothesis, findingId, surfaceMap } = context;
  const hintedRoute = surfaceMap?.routes?.find((route) =>
    route.path && r.request.url.includes(route.path),
  );
  const lines: string[] = [
    '## Finding ID',
    findingId,
    '',
    '## Hypothesis Under Test',
    hypothesis,
    '',
    '## Probe',
    `${r.request.method} ${r.request.url}`,
    `Identity: ${r.identityId}`,
    '',
    '## Response',
    `Status: ${r.response.status}`,
    `Latency: ${r.response.durationMs}ms`,
    `Body (truncated): ${(r.response.body ?? '').slice(0, 800)}`,
    '',
  ];
  if (hintedRoute?.handlerFile) {
    lines.push('## Surface map hint', `handlerFile: ${hintedRoute.handlerFile}`, '');
  }
  lines.push(
    '## Task',
    `Read the handler code that services this route under ${context.repoRoot}. Produce source refs and tell me if the observed response is consistent with the handler.`,
  );
  return lines.join('\n');
}

/**
 * Section 7.1 — parse raw source ref strings into typed SourceLocationRef
 * objects, converting absolute paths to workspace-relative.
 */
function parseSourceRefsToLocations(
  rawRefs: string[],
  repoRoot: string,
): SourceLocationRef[] {
  const results: SourceLocationRef[] = [];
  for (const raw of rawRefs) {
    const parsed = parseSourceRef(raw);
    if (parsed) {
      results.push({
        ...parsed,
        path: toWorkspaceRelative(parsed.path, repoRoot),
      });
    }
  }
  return results;
}

function parseCorrelationResponse(
  response: { content: string; structured?: CorrelationResponsePayload },
  repoRoot: string,
): CorrelationResult {
  const parsed = response.structured ?? tryParseStructured(response.content, CorrelationResponseSchema);
  if (!parsed) {
    return {
      sourceRefs: [],
      sourceLocationRefs: [],
      analysis: response.content.slice(0, 400),
      consistencyVerdict: 'inconclusive',
      consistencyReasoning: '',
      source: 'worker',
      fallbackReason: `failed to parse correlation response: ${response.content.slice(0, 180)}`,
    };
  }
  return {
    sourceRefs: parsed.sourceRefs,
    sourceLocationRefs: parseSourceRefsToLocations(parsed.sourceRefs, repoRoot),
    analysis: parsed.analysis,
    consistencyVerdict: normalizeCorrelationVerdict(parsed.consistencyVerdict),
    consistencyReasoning: parsed.consistencyReasoning,
    source: 'worker',
  };
}

function normalizeCorrelationVerdict(
  value: string,
): CorrelationResult['consistencyVerdict'] {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'consistent' || normalized === 'inconsistent' || normalized === 'inconclusive') {
    return normalized;
  }
  return 'inconclusive';
}
