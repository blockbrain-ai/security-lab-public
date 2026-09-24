/**
 * Section 6.2 — Mythos exploration sub-lane.
 *
 * Dedicated adversarial exploration lane that runs a claude-code (or any
 * file-capable) worker in open-ended creative mode. The worker receives the
 * current hypothesis set, the probe history, the target repo, and a
 * "think like Mythos" prompt, and is free to invent probes the static phase
 * never produced. All probe execution flows through an orchestrator binding
 * that enforces rate limiting, authorization, and mutation rollback — the
 * 4.1 orchestrator-protection rule still holds.
 *
 * Inputs:
 *   - Hypothesis snapshot (proposed/tested/confirmed/refuted)
 *   - Probe history (flat list from the lane so far)
 *   - repoRoot and live baseUrl
 *   - Time budget (ms)
 *   - Probe budget (counted against the main rate limiter)
 *
 * Outputs are folded back into the local-live round via `SubLaneResult` —
 * new probes, new hypotheses, new findings, plus the evidence events that
 * make the section auditable.
 */

import type { ModelAdapter, InvokeOptions } from '../../providers/contracts.js';
import type { LiveExecutionResult } from './contracts.js';
import {
  bindWorkerTools,
  MythosWorkerOutputSchema,
  parseMythosWorkerOutput,
  type BindWorkerToolsResult,
  type SubmittedFinding,
  type SubmittedHypothesis,
  type WorkerToolCall,
  type WorkerToolOrchestrator,
} from './worker-tools.js';

// ---------------------------------------------------------------------------
// Prompt
// ---------------------------------------------------------------------------

export const MYTHOS_SYSTEM_PROMPT = `You are Mythos: an adversarial security creative. You have access to a target repository and a live probe orchestrator. Your job is to find angles the static analysis phase and the hypothesis-driven probes never covered.

Think like an attacker who already read the code. Read handler files. Chase dangling leads. Invent probes that surprise the defender — routes the hypothesis list never considered, method/identity combinations nobody tried, boundary conditions the canaries skipped.

Rules:
- You CANNOT send HTTP requests directly. To execute a probe you emit a \`submitProbe\` tool call; the orchestrator runs it through the rate limiter, identity ladder, and mutation journal.
- You CAN read files, list directories, and grep the repo via your native tools.
- Every new hypothesis you propose should cite source evidence (path:line range) when possible.
- Every finding you propose MUST carry at least one evidence ref that matches an executed probe ID or an \`artifact:\` reference.
- Respect the probe and time budgets — if you run out, stop cleanly.
- DO NOT bypass the orchestrator. DO NOT invoke Security Lab recursively.

Output JSON (you may interleave probes and hypotheses/findings in any order):
{
  "reasoning": "one or two sentences describing the angle you pursued",
  "toolCalls": [
    { "kind": "submitProbe", "findingId": "...", "hypothesis": "...", "identityId": "anonymous", "http": { "method": "GET", "path": "/..." }, "rationale": "why this probe" },
    { "kind": "submitHypothesis", "description": "...", "severity": "medium", "sourceRefs": ["src/handler.ts:10-40"] },
    { "kind": "submitFinding", "description": "...", "severity": "high", "reproductionSteps": ["..."], "remediationSuggestion": "...", "evidenceRefs": ["<probeId>"], "sourceRefs": ["src/handler.ts:10-40"] }
  ]
}`;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface MythosExplorationConfig {
  enabled: boolean;
  /** Milliseconds the sub-lane is allowed to run end-to-end. */
  timeBudgetMs: number;
  /** Maximum number of probes the worker may submit in one invocation. */
  probeBudget: number;
  /** Maximum invocations per campaign (at least 1 runs once per campaign). */
  invocationsPerCampaign: number;
  /** Whether source correlation is enabled. */
  sourceCorrelationEnabled: boolean;
  /** Maximum source correlation calls per campaign. */
  sourceCorrelationMax: number;
}

export const DEFAULT_MYTHOS_CONFIG: MythosExplorationConfig = {
  enabled: false,
  timeBudgetMs: 300_000,
  probeBudget: 20,
  invocationsPerCampaign: 1,
  sourceCorrelationEnabled: true,
  sourceCorrelationMax: 10,
};

// ---------------------------------------------------------------------------
// Context + result
// ---------------------------------------------------------------------------

export interface HypothesisSnapshot {
  id: string;
  description: string;
  status: string;
  severity?: string;
}

export interface ProbeHistoryEntry {
  probeId: string;
  method: string;
  path: string;
  status: number;
  verdict: string;
  origin?: string;
}

export interface MythosSubLaneContext {
  campaignId: string;
  hypotheses: HypothesisSnapshot[];
  probeHistory: ProbeHistoryEntry[];
  repoRoot: string;
  baseUrl: string;
  config: MythosExplorationConfig;
}

export interface SubLaneResult {
  invoked: boolean;
  reason?: string;
  reasoning?: string;
  probesExecuted: LiveExecutionResult[];
  hypothesesProposed: SubmittedHypothesis[];
  findingsProposed: SubmittedFinding[];
  findingsRejected: Array<{ finding: SubmittedFinding; reason: string }>;
  budgetExhausted: BindWorkerToolsResult['budgetExhausted'];
  durationMs: number;
  parseError?: string;
}

// ---------------------------------------------------------------------------
// Sub-lane
// ---------------------------------------------------------------------------

export class MythosExplorationSubLane {
  constructor(
    private readonly adapter: ModelAdapter | undefined,
    private readonly orchestratorFactory: (
      timeDeadline: number,
    ) => WorkerToolOrchestrator,
  ) {}

  async run(context: MythosSubLaneContext): Promise<SubLaneResult> {
    const startedAt = Date.now();

    if (!context.config.enabled) {
      return emptyResult('mythos disabled', startedAt);
    }
    if (!this.adapter) {
      return emptyResult('no worker adapter available', startedAt);
    }

    const deadline = startedAt + context.config.timeBudgetMs;
    const orchestrator = this.orchestratorFactory(deadline);
    const abort = new AbortController();
    const timeoutHandle = setTimeout(() => abort.abort(), context.config.timeBudgetMs);

    try {
      const prompt = buildMythosPrompt(context);
      const invokeOptions: InvokeOptions<unknown> = {
        systemPrompt: MYTHOS_SYSTEM_PROMPT,
        prompt,
        maxTokens: 4096,
        temperature: 0.6,
        workingDirectory: context.repoRoot,
        requestTimeoutMs: context.config.timeBudgetMs,
        schema: MythosWorkerOutputSchema,
      };
      const response = await this.adapter.invoke(invokeOptions);
      const parsed = parseMythosWorkerOutput(response.content);
      const bindResult = await bindWorkerTools(parsed.output, orchestrator, {
        campaignId: context.campaignId,
      });
      return {
        invoked: true,
        reasoning: parsed.output.reasoning,
        probesExecuted: bindResult.probesExecuted,
        hypothesesProposed: bindResult.hypothesesSubmitted,
        findingsProposed: bindResult.findingsAccepted,
        findingsRejected: bindResult.findingsRejected,
        budgetExhausted: bindResult.budgetExhausted,
        durationMs: Date.now() - startedAt,
        parseError: parsed.error,
      };
    } catch (error) {
      return {
        invoked: true,
        reason: error instanceof Error ? error.message : String(error),
        probesExecuted: [],
        hypothesesProposed: [],
        findingsProposed: [],
        findingsRejected: [],
        budgetExhausted: null,
        durationMs: Date.now() - startedAt,
      };
    } finally {
      clearTimeout(timeoutHandle);
    }
  }
}

function emptyResult(reason: string, startedAt: number): SubLaneResult {
  return {
    invoked: false,
    reason,
    probesExecuted: [],
    hypothesesProposed: [],
    findingsProposed: [],
    findingsRejected: [],
    budgetExhausted: null,
    durationMs: Date.now() - startedAt,
  };
}

export function buildMythosPrompt(context: MythosSubLaneContext): string {
  const lines: string[] = [
    '## Campaign',
    context.campaignId,
    '',
    '## Target',
    `baseUrl: ${context.baseUrl}`,
    `repoRoot: ${context.repoRoot}`,
    '',
    '## Current Hypotheses',
  ];
  if (context.hypotheses.length === 0) {
    lines.push('None yet.');
  } else {
    for (const h of context.hypotheses.slice(0, 20)) {
      lines.push(`- [${h.status}] ${h.id}: ${h.description}${h.severity ? ` (${h.severity})` : ''}`);
    }
  }
  lines.push('');
  lines.push('## Probe History');
  if (context.probeHistory.length === 0) {
    lines.push('No probes fired yet.');
  } else {
    for (const p of context.probeHistory.slice(-40)) {
      lines.push(
        `- [${p.verdict}] ${p.origin ?? 'hypothesis'} ${p.method} ${p.path} -> ${p.status}`,
      );
    }
  }
  lines.push('');
  lines.push('## Budgets');
  lines.push(`Time budget: ${context.config.timeBudgetMs}ms`);
  lines.push(`Probe budget: ${context.config.probeBudget}`);
  lines.push('');
  lines.push('## Task');
  lines.push(
    'Read the repository. Find angles the above hypotheses and probes missed. Emit submitProbe tool calls through the orchestrator. When you have a new idea worth tracking, emit submitHypothesis. When you can evidence a vulnerability, emit submitFinding with proper evidence refs.',
  );
  return lines.join('\n');
}

/** Helper re-export for orchestrator wiring. */
export type { WorkerToolOrchestrator, WorkerToolCall };
