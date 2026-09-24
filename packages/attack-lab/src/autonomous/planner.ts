/**
 * AI Planner role — consumes surface maps and campaign memory,
 * generates probe hypotheses and weak-signal follow-ups.
 */

import type { InvokeOptions, ModelAdapter, ModelResponse } from '../providers/contracts.js';
import type { CampaignMemory } from './contracts.js';
import type { PlannerOutput } from './schemas.js';
import { PlannerOutputSchema } from './schemas.js';
import {
  PLANNER_SYSTEM_PROMPT,
  PLANNER_ROUND1_TEMPLATE,
  PLANNER_ROUNDN_TEMPLATE,
  renderPrompt,
  getModeInstructions,
} from './prompts.js';
import { memorySnapshot } from './campaign-memory.js';
import { summarizeGraph } from './attack-graph.js';
import { getDormantSignals } from './weak-signal-ledger.js';
import { parseWithRepair } from './response-repair.js';
import type { RoleSessionStore } from './role-session-store.js';

/**
 * Brief-mode context for planner invocations. When supplied AND the adapter
 * supports native session resume, the planner writes its heavy context
 * (target surface on round 1, campaign memory / attack graph / dormant
 * signals / last-results on round N) to disk and sends a compact pointer
 * prompt instead of a multi-megabyte monolith.
 *
 * Round 1 used to always inline the full target surface map (see commit
 * history for CODEX-BRIEF-MODE-FIX.md). That path still exists as a
 * fallback for adapters that do not support session resume, but any
 * adapter that DOES support resume now takes the brief-mode path on every
 * round — the cost saving is 5×+ on large Python/FastAPI targets where
 * the surface map alone can reach multi-megabyte scale.
 */
export interface PlannerBriefModeContext {
  store: RoleSessionStore;
  iteration: number;
  /** Role label for the manifest subdirectory ('planner' or 'counter_planner'). */
  roleLabel: 'planner' | 'counter_planner';
}

export async function plan(
  memory: CampaignMemory,
  adapter: ModelAdapter,
  targetSurface: string,
  context: {
    mode: 'declared' | 'blind';
    lastResults?: string;
    iteration: number;
    maxIterations: number;
    maxCostUsd: number;
    budgetRemainingUsd: number;
  },
  options?: {
    retrievedContext?: string;
    roleTranscript?: string;
    priorKnowledge?: string;
    invokeOptions?: Partial<InvokeOptions<PlannerOutput>>;
    briefModeContext?: PlannerBriefModeContext;
  },
): Promise<PlannerInvocation> {
  const isFirstRound = memory.iteration === 0;
  const retrievedContext = options?.retrievedContext ?? memorySnapshot(memory);
  const roleTranscript = options?.roleTranscript ?? 'No prior planner role memory.';
  const priorKnowledge = options?.priorKnowledge ?? 'No prior knowledge was consulted.';

  // Brief-mode applies to every round for adapters that support native
  // session resume. The round-1 inline fallback remains for adapters that
  // do not (currently api-only Anthropic / OpenAI / Gemini).
  const wantBriefMode =
    options?.briefModeContext != null
    && adapter.supportsNativeSessionResume === true;

  let prompt: string;
  let briefInvokeAddition: Partial<InvokeOptions<PlannerOutput>> = {};

  if (wantBriefMode && options?.briefModeContext) {
    const { store, iteration, roleLabel } = options.briefModeContext;
    const scopeId = `iteration-${iteration}`;

    // Round 1 evidence set: target surface + mode + priors. No campaign
    // memory / attack graph yet — there isn't one.
    // Round N evidence set: campaign memory, attack graph, last results,
    // dormant signals, role memory, priors, iteration state.
    // The TWO key pieces that used to live inline and blow the prompt are
    // `target-surface.md` (round 1) and `campaign-memory.md` (round N);
    // both now live on disk.
    const evidence = isFirstRound
      ? [
          { name: 'target-surface.md', content: targetSurface },
          { name: 'prior-knowledge.md', content: priorKnowledge },
          { name: 'role-memory.md', content: roleTranscript },
          {
            name: 'mode.md',
            content: [
              `Mode: ${context.mode}`,
              '',
              getModeInstructions(context.mode),
            ].join('\n'),
          },
          {
            name: 'iteration-state.md',
            content: [
              `Iteration: ${context.iteration}`,
              `Max iterations: ${context.maxIterations}`,
              `Budget remaining: $${context.budgetRemainingUsd.toFixed(4)}`,
              `Max cost: $${context.maxCostUsd.toFixed(4)}`,
              `Mode: ${context.mode}`,
              'This is round 1 — there is no prior state to carry over.',
            ].join('\n'),
          },
        ]
      : [
          { name: 'campaign-memory.md', content: retrievedContext },
          { name: 'attack-graph.md', content: summarizeGraph(memory.graph) },
          { name: 'last-results.md', content: context.lastResults ?? 'No results from last iteration.' },
          { name: 'dormant-signals.md', content: formatDormantSignals(memory) },
          { name: 'role-memory.md', content: roleTranscript },
          { name: 'prior-knowledge.md', content: priorKnowledge },
          {
            name: 'iteration-state.md',
            content: [
              `Iteration: ${context.iteration}`,
              `Max iterations: ${context.maxIterations}`,
              `Budget remaining: $${context.budgetRemainingUsd.toFixed(4)}`,
              `Max cost: $${context.maxCostUsd.toFixed(4)}`,
              `Mode: ${context.mode}`,
            ].join('\n'),
          },
        ];

    const whatToDecide = isFirstRound
      ? 'Analyze the target surface map in `target-surface.md`. Identify weak signals visible from the surface alone, generate initial probes to investigate the most promising surfaces, and propose any chain hypotheses that seem plausible. Focus on routes where local auth is not observed, config files with sensitive keys, raw database queries, public surfaces that might leak internal data, dependency risks, and trust-boundary crossings. This is round 1 — there is no prior state to carry over.'
      : 'Propose the next iteration of probes. Read `campaign-memory.md`, `attack-graph.md`, `last-results.md`, `dormant-signals.md`, and any `prior-knowledge.md`. Generate new signals, probe requests, and chain hypotheses. Mark dormant signals, reactivate any that now correlate with fresh evidence.';

    const manifest = await store.writeBriefManifest({
      role: roleLabel,
      scopeId,
      iteration,
      whatToDecide,
      outputSchemaReminder:
        'Return ONLY valid JSON matching the PlannerOutput schema: newSignals[], ' +
        'probeRequests[], newChainHypotheses[], markDormant[], reactivations[], reasoning. ' +
        'No prose outside the JSON.',
      evidence,
    });
    prompt = buildBriefPlannerPrompt({
      iteration: context.iteration,
      briefPath: manifest.briefPath,
      evidencePaths: manifest.evidencePaths,
      isFirstRound,
    });
    briefInvokeAddition = {
      briefMode: {
        briefPath: manifest.briefPath,
        artifactsDir: manifest.briefPath.replace(/\/[^/]+$/, '/..'),
        scopeId,
        evidencePointers: manifest.evidencePaths,
      },
    };
  } else if (isFirstRound) {
    // Fallback for adapters without native session resume (api-only
    // providers). The round-1 template inlines the entire target surface
    // map; acceptable on small Node targets, expensive on large Python
    // ones — but api-only providers don't benefit from file-pointer
    // prompts the same way CLI workers do.
    prompt = renderPrompt(PLANNER_ROUND1_TEMPLATE, {
      TARGET_SURFACE: targetSurface,
      PRIOR_KNOWLEDGE: priorKnowledge,
      ROLE_MEMORY: roleTranscript,
      MODE: context.mode,
      MODE_INSTRUCTIONS: getModeInstructions(context.mode),
    });
  } else {
    prompt = renderPrompt(PLANNER_ROUNDN_TEMPLATE, {
      CAMPAIGN_MEMORY: retrievedContext,
      PRIOR_KNOWLEDGE: priorKnowledge,
      ROLE_MEMORY: roleTranscript,
      ATTACK_GRAPH: summarizeGraph(memory.graph),
      LAST_RESULTS: context.lastResults ?? 'No results from last iteration.',
      DORMANT_SIGNALS: formatDormantSignals(memory),
      ITERATION: String(context.iteration),
      MAX_ITERATIONS: String(context.maxIterations),
      BUDGET_REMAINING_USD: context.budgetRemainingUsd.toFixed(4),
      MAX_COST_USD: context.maxCostUsd.toFixed(4),
    });
  }

  const response = await adapter.invoke({
    ...(options?.invokeOptions ?? {}),
    ...briefInvokeAddition,
    systemPrompt: PLANNER_SYSTEM_PROMPT,
    prompt,
    maxTokens: 8192,
    temperature: 0.2,
  });

  const fallback = parseFromContent(response.content);
  const parsed = fallback.output;

  return {
    output: parsed,
    prompt,
    systemPrompt: PLANNER_SYSTEM_PROMPT,
    response,
    parseSuccess: response.structured != null || fallback.parsed,
  };
}

function buildBriefPlannerPrompt(args: {
  iteration: number;
  briefPath: string;
  evidencePaths: string[];
  isFirstRound: boolean;
}): string {
  const continuityLine = args.isFirstRound
    ? 'Build your context from disk — do NOT expect the caller to reassemble '
      + 'it. This is round 1; there is no prior session.'
    : 'Build your context from disk — do NOT expect the caller to reassemble '
      + 'it. Use your prior session memory when resuming; this is iteration N > 0.';
  const lines = [
    `You are the Security Lab planner worker. Round: ${args.iteration}.`,
    '',
    `Read your brief first: ${args.briefPath}`,
    '',
    'Then read every evidence pointer listed in the brief:',
    ...args.evidencePaths.map((p) => `- ${p}`),
    '',
    continuityLine,
    '',
    'Return JSON only, matching the PlannerOutput schema described in the brief.',
  ];
  return lines.join('\n');
}

function formatDormantSignals(memory: CampaignMemory): string {
  const dormant = getDormantSignals(memory);
  if (dormant.length === 0) return 'No dormant signals.';

  return dormant
    .map(
      (s) =>
        `- [${s.id}] (${s.surface}, conf=${s.confidence.toFixed(2)}) ${s.description}` +
        (s.unresolvedCorrelations.length > 0
          ? `\n  unresolved: ${s.unresolvedCorrelations.join(', ')}`
          : ''),
    )
    .join('\n');
}

function parseFromContent(content: string): { output: PlannerOutput; parsed: boolean; repaired: boolean; failureKind: string } {
  const result = parseWithRepair(content, PlannerOutputSchema as unknown as import('zod').ZodType<PlannerOutput>);

  if (result.success && result.output) {
    return {
      output: PlannerOutputSchema.parse(result.output),
      parsed: true,
      repaired: result.repairAttempted && result.repairSucceeded,
      failureKind: result.failureKind,
    };
  }

  // Return empty output with the reasoning
  return {
    output: {
      newSignals: [],
      probeRequests: [],
      newChainHypotheses: [],
      markDormant: [],
      reactivations: [],
      reasoning: `Failed to parse structured output (${result.failureKind}). Raw: ${content.slice(0, 500)}`,
    },
    parsed: false,
    repaired: false,
    failureKind: result.failureKind,
  };
}

export interface PlannerInvocation {
  output: PlannerOutput;
  prompt: string;
  systemPrompt: string;
  response: ModelResponse;
  parseSuccess: boolean;
}
