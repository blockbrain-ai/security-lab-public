/**
 * Section 6.2 — Worker tools for the Mythos exploration sub-lane.
 *
 * The Mythos worker cannot send HTTP requests directly. Instead it emits
 * three structured "submit" tool invocations — `submitProbe`, `submitHypothesis`,
 * and `submitFinding` — that the orchestrator executes on its behalf through
 * the usual safety gates (rate limiter, probe authorization, mutation rollback,
 * focused-closure evidence-ref validation).
 *
 * This module owns:
 * 1. The Zod schemas for each tool call (the trust boundary — workers are
 *    treated as untrusted model outputs under SL1).
 * 2. The `MythosWorkerOutput` shape the worker must produce.
 * 3. The `bindWorkerTools` helper that wires the submit tools to an
 *    orchestrator binding and executes them in order, respecting budgets.
 *
 * The design ensures the 4.1 orchestrator-protection rule is preserved:
 * workers never reach the network directly; every probe request flows
 * through the caller-supplied `executeProbe` callback which wraps the
 * standard gates.
 */

import { z } from 'zod';
import { tryParseStructured } from '../../providers/parse-structured.js';
import type { LiveProbeRequest, LiveExecutionResult } from './contracts.js';

// ---------------------------------------------------------------------------
// Tool call schemas
// ---------------------------------------------------------------------------

const HttpMethodSchema = z
  .string()
  .trim()
  .transform((value) => value.toUpperCase())
  .pipe(z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD']));

const SeveritySchema = z
  .string()
  .trim()
  .transform((value) => value.toLowerCase())
  .pipe(z.enum(['low', 'medium', 'high', 'critical']));

const OptionalStringListSchema = z.union([
  z.array(z.string()),
  z.string().transform((value) => [value]),
]);

const RequiredStringListSchema = OptionalStringListSchema.pipe(z.array(z.string()).min(1));

const HeaderRecordSchema = z
  .record(z.union([z.string(), z.number(), z.boolean()]))
  .transform((headers) => Object.fromEntries(
    Object.entries(headers).map(([key, value]) => [key, String(value)]),
  ));

const RequestBodySchema = z
  .union([z.string(), z.number(), z.boolean(), z.record(z.unknown()), z.array(z.unknown())])
  .transform((value) => {
    if (typeof value === 'string') return value;
    if (typeof value === 'number' || typeof value === 'boolean') return String(value);
    return JSON.stringify(value);
  });

export const SubmitProbeSchema = z.object({
  kind: z.literal('submitProbe'),
  findingId: z.string().min(1),
  hypothesis: z.string().min(1),
  identityId: z.string().min(1),
  rationale: z.string().optional(),
  http: z.object({
    method: HttpMethodSchema,
    path: z.string().min(1),
    headers: HeaderRecordSchema.optional(),
    body: RequestBodySchema.optional(),
  }).passthrough(),
}).passthrough();

export const SubmitHypothesisSchema = z.object({
  kind: z.literal('submitHypothesis'),
  description: z.string().min(1),
  severity: SeveritySchema.default('medium'),
  rationale: z.string().optional(),
  relatedAssets: OptionalStringListSchema.optional(),
  sourceRefs: OptionalStringListSchema.optional(),
}).passthrough();

export const SubmitFindingSchema = z.object({
  kind: z.literal('submitFinding'),
  description: z.string().min(1),
  severity: SeveritySchema.default('medium'),
  reproductionSteps: RequiredStringListSchema,
  remediationSuggestion: z.string().min(1),
  evidenceRefs: RequiredStringListSchema,
  sourceRefs: OptionalStringListSchema.optional(),
}).passthrough();

export const WorkerToolCallSchema = z.discriminatedUnion('kind', [
  SubmitProbeSchema,
  SubmitHypothesisSchema,
  SubmitFindingSchema,
]);

export const MythosWorkerOutputSchema = z.object({
  toolCalls: z.array(WorkerToolCallSchema).default([]),
  reasoning: z.string().optional(),
});

export type SubmitProbeInput = z.infer<typeof SubmitProbeSchema>;
export type SubmitHypothesisInput = z.infer<typeof SubmitHypothesisSchema>;
export type SubmitFindingInput = z.infer<typeof SubmitFindingSchema>;
export type WorkerToolCall = z.infer<typeof WorkerToolCallSchema>;
export type MythosWorkerOutput = z.infer<typeof MythosWorkerOutputSchema>;

// ---------------------------------------------------------------------------
// Orchestrator binding
// ---------------------------------------------------------------------------

export interface SubmittedHypothesis {
  id: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  rationale?: string;
  relatedAssets: string[];
  sourceRefs: string[];
}

export interface SubmittedFinding {
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  reproductionSteps: string[];
  remediationSuggestion: string;
  evidenceRefs: string[];
  sourceRefs: string[];
}

/**
 * The executeProbe callback takes a probe spec from the worker and runs it
 * through the orchestrator's live-probe batch path (rate limiter, auth gate,
 * mutation journal). A rejection here means the orchestrator declined to
 * run the probe — we surface that back to the worker as a `rejected` entry
 * so the Mythos loop can still record the intent.
 */
export interface WorkerToolOrchestrator {
  executeProbe(probe: LiveProbeRequest): Promise<LiveExecutionResult | { rejected: true; reason: string }>;
  submitHypothesis(h: SubmittedHypothesis): Promise<void>;
  submitFinding(f: SubmittedFinding): Promise<{ accepted: boolean; reason?: string }>;
  /** Remaining probe budget for this Mythos invocation. */
  getRemainingProbeBudget(): number;
  /** True if the time budget has been exhausted. */
  isTimeExhausted(): boolean;
  /** Optional hook invoked whenever a tool call is processed. */
  onToolCall?(call: WorkerToolCall, outcome: ToolCallOutcome): void;
}

export type ToolCallOutcome =
  | { kind: 'probe_executed'; result: LiveExecutionResult }
  | { kind: 'probe_rejected'; reason: string }
  | { kind: 'probe_budget_exhausted' }
  | { kind: 'time_budget_exhausted' }
  | { kind: 'hypothesis_accepted'; id: string }
  | { kind: 'finding_accepted' }
  | { kind: 'finding_rejected'; reason: string };

export interface BindWorkerToolsResult {
  probesExecuted: LiveExecutionResult[];
  hypothesesSubmitted: SubmittedHypothesis[];
  findingsAccepted: SubmittedFinding[];
  findingsRejected: Array<{ finding: SubmittedFinding; reason: string }>;
  budgetExhausted: null | 'probe_budget_exhausted' | 'time_budget_exhausted';
}

/**
 * Generate a deterministic id for a Mythos-proposed hypothesis. The id is
 * derived purely from `campaignId` + the per-call `index` so IDs are
 * reproducible across test runs and never leak state between invocations
 * or campaigns.
 */
function mythosHypothesisId(campaignId: string, index: number): string {
  return `hyp-mythos-${campaignId.slice(0, 12)}-${index}`;
}

/**
 * Execute a parsed worker output against the orchestrator, honoring the
 * probe and time budgets. Returns a structured audit of what was run.
 */
export async function bindWorkerTools(
  output: MythosWorkerOutput,
  orchestrator: WorkerToolOrchestrator,
  context: { campaignId: string },
): Promise<BindWorkerToolsResult> {
  const result: BindWorkerToolsResult = {
    probesExecuted: [],
    hypothesesSubmitted: [],
    findingsAccepted: [],
    findingsRejected: [],
    budgetExhausted: null,
  };

  let hypothesisIndex = 0;

  for (const call of output.toolCalls) {
    if (orchestrator.isTimeExhausted()) {
      result.budgetExhausted = 'time_budget_exhausted';
      orchestrator.onToolCall?.(call, { kind: 'time_budget_exhausted' });
      break;
    }

    if (call.kind === 'submitProbe') {
      if (orchestrator.getRemainingProbeBudget() <= 0) {
        result.budgetExhausted = 'probe_budget_exhausted';
        orchestrator.onToolCall?.(call, { kind: 'probe_budget_exhausted' });
        break;
      }
      const probe: LiveProbeRequest = {
        findingId: call.findingId,
        hypothesis: call.hypothesis,
        probeKind: 'http',
        identityId: call.identityId,
        rationale: call.rationale,
        http: call.http,
      };
      const exec = await orchestrator.executeProbe(probe);
      if ('rejected' in exec) {
        orchestrator.onToolCall?.(call, { kind: 'probe_rejected', reason: exec.reason });
      } else {
        result.probesExecuted.push(exec);
        orchestrator.onToolCall?.(call, { kind: 'probe_executed', result: exec });
      }
      continue;
    }

    if (call.kind === 'submitHypothesis') {
      hypothesisIndex += 1;
      const hypothesis: SubmittedHypothesis = {
        id: mythosHypothesisId(context.campaignId, hypothesisIndex),
        description: call.description,
        severity: call.severity,
        rationale: call.rationale,
        relatedAssets: call.relatedAssets ?? [],
        sourceRefs: call.sourceRefs ?? [],
      };
      await orchestrator.submitHypothesis(hypothesis);
      result.hypothesesSubmitted.push(hypothesis);
      orchestrator.onToolCall?.(call, { kind: 'hypothesis_accepted', id: hypothesis.id });
      continue;
    }

    if (call.kind === 'submitFinding') {
      const finding: SubmittedFinding = {
        description: call.description,
        severity: call.severity,
        reproductionSteps: call.reproductionSteps,
        remediationSuggestion: call.remediationSuggestion,
        evidenceRefs: call.evidenceRefs,
        sourceRefs: call.sourceRefs ?? [],
      };
      const decision = await orchestrator.submitFinding(finding);
      if (decision.accepted) {
        result.findingsAccepted.push(finding);
        orchestrator.onToolCall?.(call, { kind: 'finding_accepted' });
      } else {
        result.findingsRejected.push({ finding, reason: decision.reason ?? 'rejected' });
        orchestrator.onToolCall?.(call, {
          kind: 'finding_rejected',
          reason: decision.reason ?? 'rejected',
        });
      }
      continue;
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/**
 * Parse a raw worker response into a validated `MythosWorkerOutput`. Accepts
 * either a fenced ```json code block or a bare JSON object. Returns a
 * zero-tool-call output with an error reason when parsing fails so the
 * caller can still record the attempt.
 */
export function parseMythosWorkerOutput(raw: string): {
  output: MythosWorkerOutput;
  error?: string;
} {
  const parsed = tryParseStructured(raw, MythosWorkerOutputSchema);
  if (!parsed) {
    return {
      output: { toolCalls: [] },
      error: `failed to parse worker response: ${raw.slice(0, 180)}`,
    };
  }
  return { output: parsed };
}

/**
 * Finding evidence-ref validator consistent with the focused-closure rule
 * (Section 5.2): a Mythos-proposed finding must cite at least one evidence
 * ref that matches a known probe ID or an `artifact:` ref. Returns the
 * first violation or `null` if the finding passes.
 */
export function validateFindingEvidenceRefs(
  finding: SubmittedFinding,
  knownProbeIds: ReadonlySet<string>,
): string | null {
  if (finding.evidenceRefs.length === 0) {
    return 'submitFinding requires at least one evidence ref';
  }
  for (const ref of finding.evidenceRefs) {
    if (ref.startsWith('artifact:') || ref.startsWith('probe:') || knownProbeIds.has(ref)) {
      return null;
    }
  }
  return `evidence refs do not match any known probe id or artifact: ${finding.evidenceRefs.join(', ')}`;
}
