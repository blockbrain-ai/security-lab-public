/**
 * AI Judge role — evaluates probe observations against chain hypotheses,
 * determines progress, and manages signal lifecycle (promote, dismiss,
 * reactivate dormant).
 */

import type { InvokeOptions, ModelAdapter, ModelResponse } from '../providers/contracts.js';
import type { CampaignMemory, ChainHypothesis } from './contracts.js';
import type { JudgeOutput } from './schemas.js';
import { JudgeOutputSchema } from './schemas.js';
import {
  JUDGE_SYSTEM_PROMPT,
  JUDGE_TEMPLATE,
  renderPrompt,
} from './prompts.js';
import { memorySnapshot } from './campaign-memory.js';
import { getDormantSignals } from './weak-signal-ledger.js';
import type { RoleSessionStore } from './role-session-store.js';

/**
 * Brief-mode context: when supplied AND the adapter advertises native
 * session resume, the judge writes a compact brief + evidence artifacts
 * to disk and sends a short pointer prompt instead of the ~30 KB
 * JUDGE_TEMPLATE payload. This is the loose-schema "loose
 * exploration, tight execution" pattern that eliminates heavy-prompt
 * timeouts on deep chain hypotheses. See the recovery plan.
 */
export interface JudgeBriefModeContext {
  store: RoleSessionStore;
  iteration: number;
}

export async function judge(
  memory: CampaignMemory,
  adapter: ModelAdapter,
  hypothesis: ChainHypothesis,
  observations: string,
  options?: {
    retrievedContext?: string;
    roleTranscript?: string;
    invokeOptions?: Partial<InvokeOptions<JudgeOutput>>;
    briefModeContext?: JudgeBriefModeContext;
  },
): Promise<JudgeInvocation> {
  const retrievedContext = options?.retrievedContext ?? memorySnapshot(memory, 20_000);
  const roleTranscript = options?.roleTranscript ?? 'No prior judge role memory.';

  // Decide path: brief-mode only when caller provided the context AND the
  // adapter supports native session resume. Otherwise fall back to the
  // legacy one-shot full-context prompt.
  const wantBriefMode =
    options?.briefModeContext != null && adapter.supportsNativeSessionResume === true;

  let prompt: string;
  let briefInvokeAddition: Partial<InvokeOptions<JudgeOutput>> = {};

  if (wantBriefMode && options?.briefModeContext) {
    const { store, iteration } = options.briefModeContext;
    const evidence = [
      { name: 'hypothesis.md', content: formatHypothesis(hypothesis) },
      { name: 'observations.md', content: observations || 'No probe observations recorded.' },
      { name: 'role-memory.md', content: roleTranscript },
      { name: 'campaign-memory.md', content: retrievedContext },
      { name: 'dormant-signals.md', content: formatDormantForJudge(memory) },
    ];
    const manifest = await store.writeBriefManifest({
      role: 'judge',
      scopeId: hypothesis.id,
      iteration,
      whatToDecide:
        'Evaluate the hypothesis described in `hypothesis.md` against the observations in ' +
        '`observations.md`. Use `campaign-memory.md`, `role-memory.md`, and `dormant-signals.md` ' +
        'as supporting context. Decide on a verdict and return the JudgeOutput JSON. ' +
        'Promote or dismiss signals as appropriate; consider reactivating dormant signals that ' +
        'share assets, surfaces, or unresolved correlations with active signals.',
      outputSchemaReminder:
        'Return ONLY valid JSON matching the JudgeOutput schema. No prose outside the JSON. '
        + '\n\n'
        + 'The `verdict` field MUST be one of:\n'
        + '  - "continue" (partial progress, needs more probes, hypothesis still plausible — '
        + 'this is also the right verdict when you would otherwise say "refuted", "partial", '
        + '"needs_more_evidence", or "insufficient_evidence")\n'
        + '  - "confirmed_finding" (evidence already proves the vuln; static-only runs rarely earn this)\n'
        + '  - "dead_end" (decisively refuted by concrete evidence — the code path does not exist, '
        + 'the defense already fires, the precondition is impossible)\n'
        + '  - "merge_with_existing" (this is a duplicate of another active hypothesis)\n'
        + '  - "needs_dormant_review" (a dormant signal should be reactivated)\n\n'
        + 'Other fields: promoteSignals[], dismissSignals[], reactivateSignals[], '
        + 'newCorrelations[], partialProgress (boolean), reasoning (string), and optionally '
        + '`finding` when `verdict=confirmed_finding`.',
      evidence,
    });
    prompt = buildBriefPrompt({
      hypothesisId: hypothesis.id,
      briefPath: manifest.briefPath,
      evidencePaths: manifest.evidencePaths,
    });
    briefInvokeAddition = {
      briefMode: {
        briefPath: manifest.briefPath,
        artifactsDir: manifest.briefPath.replace(/\/[^/]+$/, '/..'),
        scopeId: hypothesis.id,
        evidencePointers: manifest.evidencePaths,
      },
    };
  } else {
    prompt = renderPrompt(JUDGE_TEMPLATE, {
      HYPOTHESIS: formatHypothesis(hypothesis),
      OBSERVATIONS: observations,
      ROLE_MEMORY: roleTranscript,
      CAMPAIGN_MEMORY: retrievedContext,
      DORMANT_SIGNALS: formatDormantForJudge(memory),
    });
  }

  const response = await adapter.invoke({
    ...(options?.invokeOptions ?? {}),
    ...briefInvokeAddition,
    systemPrompt: JUDGE_SYSTEM_PROMPT,
    prompt,
    maxTokens: 8192,
    temperature: 0,
  });

  const fallback = parseJudgeOutput(response.content);
  const parsed = fallback.output;

  return {
    output: parsed,
    prompt,
    systemPrompt: JUDGE_SYSTEM_PROMPT,
    response,
    parseSuccess: response.structured != null || fallback.parsed,
  };
}

function buildBriefPrompt(args: {
  hypothesisId: string;
  briefPath: string;
  evidencePaths: string[];
}): string {
  const lines = [
    `You are the Security Lab judge worker. Scope: hypothesis ${args.hypothesisId}.`,
    '',
    `Read your brief first: ${args.briefPath}`,
    '',
    'Then read every evidence pointer listed in the brief:',
    ...args.evidencePaths.map((p) => `- ${p}`),
    '',
    'Do NOT wait for context in the prompt — everything you need is on disk in the ' +
      'paths above. Use your session memory from prior turns if present.',
    '',
    'When you have decided, return JSON only, matching the JudgeOutput schema described in the brief.',
  ];
  return lines.join('\n');
}

function formatHypothesis(h: ChainHypothesis): string {
  const lines = [
    `ID: ${h.id}`,
    `Severity: ${h.severity}`,
    `Status: ${h.status}`,
    `Description: ${h.description}`,
    `Signals: ${h.signalIds.join(', ')}`,
    `Prerequisites: ${h.prerequisites.join(', ') || 'none'}`,
    `Attempts so far: ${h.attempts.length}`,
  ];

  if (h.attempts.length > 0) {
    const last = h.attempts[h.attempts.length - 1]!;
    lines.push(`Last attempt verdict: ${last.verdict}`);
    lines.push(`Last attempt reasoning: ${last.reasoning}`);
  }

  return lines.join('\n');
}

function formatDormantForJudge(memory: CampaignMemory): string {
  const dormant = getDormantSignals(memory);
  if (dormant.length === 0) return 'No dormant signals available.';

  return dormant
    .slice(0, 10)
    .map((s) => `- [${s.id}] (${s.surface}) ${s.description}`)
    .join('\n');
}

/**
 * Map free-form verdict strings that model producers commonly emit to the
 * canonical JudgeOutputSchema enum values. This captures the aliases we
 * observed on the fixture-target audit (inv-1776170280103) where both judges
 * returned `partial_progress`, `needs_more_evidence`, `partial`, etc. —
 * all of which failed strict zod parsing and got masked to `dead_end` by
 * the fallback path.
 *
 * The rule of thumb: if in doubt, return `continue`. Only map to
 * `dead_end` when the model explicitly says the chain is dead /
 * hopeless / impossible. Everything else is "hypothesis stays open".
 * This matches the JUDGE_SYSTEM_PROMPT guidance to distinguish
 * "hypothesis refuted" from "hypothesis needs different approach".
 */
function normalizeVerdict(raw: unknown): JudgeOutput['verdict'] | undefined {
  if (typeof raw !== 'string') return undefined;
  const v = raw.trim().toLowerCase().replace(/[\s-]/g, '_');
  if (!v) return undefined;

  // Canonical values pass through
  if (
    v === 'continue'
    || v === 'confirmed_finding'
    || v === 'dead_end'
    || v === 'merge_with_existing'
    || v === 'needs_dormant_review'
  ) {
    return v as JudgeOutput['verdict'];
  }

  // Positive / confirmed aliases
  if (
    v === 'confirmed'
    || v === 'confirm'
    || v === 'proved'
    || v === 'proven'
    || v === 'exploitable'
    || v === 'confirmed_vulnerability'
    || v === 'finding'
  ) {
    return 'confirmed_finding';
  }

  // Decisively-refuted aliases — only these map to dead_end
  if (
    v === 'hopeless'
    || v === 'not_exploitable'
    || v === 'impossible'
    || v === 'definitely_refuted'
    || v === 'decisively_refuted'
  ) {
    return 'dead_end';
  }

  // Merge / dormant
  if (v === 'merge' || v === 'duplicate' || v === 'duplicate_of_existing') {
    return 'merge_with_existing';
  }
  if (v === 'dormant' || v === 'reopen' || v === 'reactivate') {
    return 'needs_dormant_review';
  }

  // Everything uncertain → continue. This includes the aliases we
  // observed in the wild: partial, partial_progress, needs_more_evidence,
  // needs_more_probes, insufficient_evidence, refuted (NOT decisively),
  // testing, in_progress, unclear.
  if (
    v === 'partial'
    || v === 'partial_progress'
    || v === 'needs_more_evidence'
    || v === 'needs_more_probes'
    || v === 'insufficient_evidence'
    || v === 'refuted'
    || v === 'refute'
    || v === 'inconclusive'
    || v === 'testing'
    || v === 'in_progress'
    || v === 'unclear'
    || v === 'plausible'
  ) {
    return 'continue';
  }

  return undefined;
}

/**
 * Normalize model-side field-name drift — some providers write
 * `hypothesis_confidence` or `confidence_score` instead of `confidence`,
 * `partial_progress` instead of `partialProgress`, etc. The JudgeOutput
 * schema uses camelCase TypeScript conventions; worker models often
 * reach for snake_case. Apply a small alias map before zod validation.
 */
function aliasJudgeFields(raw: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = { ...raw };

  // Verdict alias normalization
  const verdictRaw = out['verdict'] ?? out['hypothesis_status'] ?? out['status'];
  const verdict = normalizeVerdict(verdictRaw);
  if (verdict) out['verdict'] = verdict;

  // partialProgress (camelCase) ← partial_progress (snake_case)
  if (out['partialProgress'] === undefined && out['partial_progress'] !== undefined) {
    out['partialProgress'] = out['partial_progress'];
  }
  // If the model explicitly says the verdict is continue AND no
  // partialProgress was set, infer partialProgress=true — the judge
  // was saying "still advancing, not confirmed yet".
  if (out['verdict'] === 'continue' && out['partialProgress'] === undefined) {
    out['partialProgress'] = true;
  }

  // promoteSignals alias
  if (out['promoteSignals'] === undefined && out['promote_signals'] !== undefined) {
    out['promoteSignals'] = out['promote_signals'];
  }
  // dismissSignals alias
  if (out['dismissSignals'] === undefined && out['dismiss_signals'] !== undefined) {
    out['dismissSignals'] = out['dismiss_signals'];
  }
  // reactivateSignals alias
  if (out['reactivateSignals'] === undefined && out['reactivate_signals'] !== undefined) {
    out['reactivateSignals'] = out['reactivate_signals'];
  }
  // newCorrelations alias
  if (out['newCorrelations'] === undefined && out['new_correlations'] !== undefined) {
    out['newCorrelations'] = out['new_correlations'];
  }

  // Coerce promoteSignals/dismissSignals from objects to strings.
  // Local models return {signalId, newConfidence, reason} instead of bare IDs.
  for (const field of ['promoteSignals', 'dismissSignals'] as const) {
    const arr = out[field];
    if (Array.isArray(arr)) {
      out[field] = arr.map((item: unknown) => {
        if (typeof item === 'string') return item;
        if (typeof item === 'object' && item !== null) {
          const r = item as Record<string, unknown>;
          const id = r['signalId'] ?? r['id'] ?? r['signal'] ?? r['name'];
          if (typeof id === 'string') return id;
        }
        return item;
      });
    }
  }

  // Coerce newCorrelations from {signals: [a, b]} to {signalIdA, signalIdB, resolved}.
  // Drop bare strings — local models sometimes emit prose descriptions instead of objects.
  const nc = out['newCorrelations'];
  if (Array.isArray(nc)) {
    out['newCorrelations'] = nc
      .filter((item: unknown) => typeof item === 'object' && item !== null)
      .map((item: unknown) => {
        const r = item as Record<string, unknown>;
        const signals = r['signals'];
        if (Array.isArray(signals) && signals.length >= 2) {
          return { signalIdA: String(signals[0]), signalIdB: String(signals[1]), resolved: r['resolved'] ?? false };
        }
        return item;
      });
  }

  // Coerce reactivateSignals from {id, ...} to {signalId, reason}.
  const rs = out['reactivateSignals'];
  if (Array.isArray(rs)) {
    out['reactivateSignals'] = rs.map((item: unknown) => {
      if (typeof item !== 'object' || item === null) return item;
      const r = item as Record<string, unknown>;
      if (!('signalId' in r) && ('id' in r || 'signal' in r)) {
        return { signalId: String(r['id'] ?? r['signal']), reason: String(r['reason'] ?? '') };
      }
      return item;
    });
  }

  // If there's no reasoning, synthesize one from available text fields
  if (out['reasoning'] === undefined || out['reasoning'] === null || out['reasoning'] === '') {
    const summary = out['summary'] ?? out['explanation'] ?? out['analysis'] ?? out['rationale'];
    if (typeof summary === 'string') out['reasoning'] = summary;
  }

  // Zod `.optional()` accepts `undefined` but not `null`. Models (and
  // fixtures) commonly return `finding: null` as a "no finding" marker;
  // treat that as unset so schema validation doesn't choke on it.
  if (out['finding'] === null) delete out['finding'];

  return out;
}

/**
 * Extract the JSON payload from a judge response, tolerating:
 *  - fenced ```json``` blocks
 *  - unfenced bare objects
 *  - leading reasoning text before the object (Opus tool-use style)
 *  - trailing reasoning text after the object
 *  - multiple objects in the response (last-one-wins if it has `verdict`)
 */
function extractJudgeJson(content: string): unknown {
  // Try fenced blocks first — they're unambiguous when present.
  const fenced = content.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  if (fenced && fenced[1]) {
    try { return JSON.parse(fenced[1]); } catch { /* fall through */ }
  }

  // Walk the string looking for balanced-brace JSON objects, preferring
  // the last one that actually contains a `verdict` key (models commonly
  // include small tool-call JSON objects earlier in the response).
  const candidates: unknown[] = [];
  for (let i = 0; i < content.length; i++) {
    if (content[i] !== '{') continue;
    let depth = 0;
    let inString = false;
    let escape = false;
    for (let j = i; j < content.length; j++) {
      const ch = content[j]!;
      if (escape) { escape = false; continue; }
      if (ch === '\\') { escape = true; continue; }
      if (ch === '"') { inString = !inString; continue; }
      if (inString) continue;
      if (ch === '{') depth++;
      else if (ch === '}') {
        depth--;
        if (depth === 0) {
          const slice = content.slice(i, j + 1);
          try {
            candidates.push(JSON.parse(slice));
          } catch { /* malformed; skip */ }
          i = j;
          break;
        }
      }
    }
  }

  // Prefer the last candidate that has a `verdict` key (judge output
  // shape), otherwise fall back to the last parseable object.
  for (let i = candidates.length - 1; i >= 0; i--) {
    const c = candidates[i];
    if (c && typeof c === 'object' && 'verdict' in (c as Record<string, unknown>)) {
      return c;
    }
  }
  return candidates[candidates.length - 1];
}

function parseJudgeOutput(content: string): { output: JudgeOutput; parsed: boolean } {
  const raw = extractJudgeJson(content);
  if (raw && typeof raw === 'object') {
    const aliased = aliasJudgeFields(raw as Record<string, unknown>);
    const result = JudgeOutputSchema.safeParse(aliased);
    if (result.success) {
      return { output: result.data, parsed: true };
    }
  }

  // Fallback — prefer `continue` so that a parse failure doesn't silently
  // kill the hypothesis. The previous default of `dead_end` hid real
  // uncertainty; see docs/CODEX-BRIEF-MODE-FIX.md (fixture-target campaign) for
  // the analysis that motivated this change.
  return {
    output: {
      verdict: 'continue',
      promoteSignals: [],
      dismissSignals: [],
      reactivateSignals: [],
      newCorrelations: [],
      partialProgress: true,
      reasoning: `Failed to parse judge output, defaulting to continue. Raw: ${content.slice(0, 500)}`,
    },
    parsed: false,
  };
}

export interface JudgeInvocation {
  output: JudgeOutput;
  prompt: string;
  systemPrompt: string;
  response: ModelResponse;
  parseSuccess: boolean;
}
