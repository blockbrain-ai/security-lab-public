/**
 * Portfolio profiles — predefined model assignments for different
 * investigation modes. Each profile declares which models fill
 * which roles, when to escalate, and cost ceilings.
 */

import type { ModelConfig } from '../providers/contracts.js';

// Local Codex runs use the official Ollama qwen3.6:27b tag so that Codex's
// automatic `ollama pull` succeeds. The judge still runs on llama-server.
export const LOCAL_QWEN_CODEX_MODEL = 'qwen3.6:27b';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PortfolioProfile {
  id: string;
  name: string;
  planner: ModelConfig;
  counterPlanner?: ModelConfig;
  /** Optional role-specific worker for local-live translation rounds. */
  localLivePlanner?: ModelConfig;
  /** Optional role-specific counter worker for local-live translation rounds. */
  localLiveCounterPlanner?: ModelConfig;
  judge: ModelConfig;
  /** Judge panel members for critical/disputed findings. */
  judgePanel?: ModelConfig[];
  /** Final synthesizer for panel reconciliation. */
  synthesizer?: ModelConfig;
  reporter?: ModelConfig;
  /** When to invoke counter-planner. */
  counterPlannerTriggers: CounterPlannerTrigger[];
  /** When to invoke full judge panel instead of single judge. */
  panelTriggers: PanelTrigger[];
  /** When to invoke final synthesizer. */
  synthesizerTriggers: SynthesizerTrigger[];
  /** Budget ceiling per campaign in USD. */
  budgetCeiling: number;
  /**
   * Roles that should use persistent-session brief mode instead of one-shot
   * heavy prompts. Only applies to providers whose adapter supports it
   * (currently claude_code + codex_cli). Other providers are invoked the
   * old way regardless. Set to an empty array (or omit) to disable brief
   * mode and fall back to the classic full-context path for every role.
   */
  briefModeRoles?: BriefModeRole[];
}

export type BriefModeRole = 'planner' | 'counter_planner' | 'judge' | 'judge_panel' | 'synthesizer' | 'test_synthesis' | 'local_live_planner' | 'local_live_counter_planner';

export type CounterPlannerTrigger = 'consecutive_dead_ends' | 'high_novelty_hypothesis' | 'chain_depth_exceeds_3' | 'budget_above_50_percent';

export type PanelTrigger = 'severity_critical' | 'severity_high' | 'planner_judge_disagree' | 'chain_involves_dormant_reactivation' | 'finding_crosses_trust_boundary';

export type SynthesizerTrigger = 'panel_disagreement' | 'contested_finding' | 'multi_surface_chain' | 'always';

// ---------------------------------------------------------------------------
// Predefined profiles
// ---------------------------------------------------------------------------

export const BALANCED_PROFILE: PortfolioProfile = {
  id: 'balanced',
  name: 'Balanced — single planner + single judge, panel on critical',
  planner: { provider: 'anthropic', model: 'claude-sonnet-4-6' },
  judge: { provider: 'anthropic', model: 'claude-sonnet-4-6' },
  judgePanel: [
    { provider: 'anthropic', model: 'claude-sonnet-4-6' },
    { provider: 'openai', model: 'gpt-4o' },
  ],
  synthesizer: { provider: 'anthropic', model: 'claude-sonnet-4-6' },
  reporter: { provider: 'anthropic', model: 'claude-sonnet-4-6' },
  counterPlannerTriggers: ['consecutive_dead_ends'],
  panelTriggers: ['severity_critical', 'planner_judge_disagree'],
  synthesizerTriggers: ['panel_disagreement'],
  budgetCeiling: 10,
};

export const ULTIMATE_PROFILE: PortfolioProfile = {
  id: 'ultimate',
  name: 'Ultimate — multi-model planner/judge panel + Opus synthesizer',
  planner: { provider: 'openai', model: 'gpt-5.4' },
  counterPlanner: { provider: 'gemini', model: 'gemini-3.1-pro-preview' },
  judge: { provider: 'openai', model: 'gpt-5.4' },
  judgePanel: [
    { provider: 'openai', model: 'gpt-5.4' },
    { provider: 'anthropic', model: 'claude-opus-4-6' },
    { provider: 'gemini', model: 'gemini-3.1-pro-preview' },
  ],
  synthesizer: { provider: 'anthropic', model: 'claude-opus-4-6' },
  reporter: { provider: 'anthropic', model: 'claude-opus-4-6' },
  counterPlannerTriggers: ['consecutive_dead_ends', 'high_novelty_hypothesis', 'chain_depth_exceeds_3'],
  panelTriggers: ['severity_critical', 'severity_high', 'planner_judge_disagree', 'chain_involves_dormant_reactivation', 'finding_crosses_trust_boundary'],
  synthesizerTriggers: ['panel_disagreement', 'contested_finding', 'multi_surface_chain'],
  budgetCeiling: 50,
};

export const COST_SENSITIVE_PROFILE: PortfolioProfile = {
  id: 'cost_sensitive',
  name: 'Cost-sensitive — fast models, panel only on critical',
  planner: { provider: 'anthropic', model: 'claude-sonnet-4-6' },
  judge: { provider: 'anthropic', model: 'claude-sonnet-4-6' },
  reporter: { provider: 'anthropic', model: 'claude-sonnet-4-6' },
  counterPlannerTriggers: [],
  panelTriggers: ['severity_critical'],
  synthesizerTriggers: [],
  budgetCeiling: 3,
};

export const PRODUCTION_PROFILE: PortfolioProfile = {
  id: 'production',
  name: 'Production — Sonnet routine, Opus+GPT-5.4 frontier on critical',
  planner: { provider: 'anthropic', model: 'claude-sonnet-4-6' },
  counterPlanner: { provider: 'openai', model: 'gpt-5.4' },
  judge: { provider: 'anthropic', model: 'claude-sonnet-4-6' },
  judgePanel: [
    { provider: 'openai', model: 'gpt-5.4' },
    { provider: 'anthropic', model: 'claude-opus-4-6' },
  ],
  synthesizer: { provider: 'anthropic', model: 'claude-opus-4-6' },
  reporter: { provider: 'anthropic', model: 'claude-opus-4-6' },
  counterPlannerTriggers: ['consecutive_dead_ends', 'high_novelty_hypothesis', 'chain_depth_exceeds_3'],
  panelTriggers: ['severity_critical', 'severity_high', 'planner_judge_disagree', 'chain_involves_dormant_reactivation', 'finding_crosses_trust_boundary'],
  synthesizerTriggers: ['panel_disagreement', 'contested_finding', 'multi_surface_chain'],
  budgetCeiling: 20,
};

export const LOCAL_QWEN_PROFILE: PortfolioProfile = {
  id: 'local_qwen',
  name: 'Local Qwen — all roles via local llama-server, zero API cost',
  planner: {
    provider: 'openai',
    model: 'qwen3.6-27b',
    baseUrl: 'http://127.0.0.1:8080/v1',
    maxTokens: 16384,
    requestTimeoutMs: 900_000,
  },
  judge: {
    provider: 'openai',
    model: 'qwen3.6-27b',
    baseUrl: 'http://127.0.0.1:8080/v1',
    maxTokens: 16384,
    requestTimeoutMs: 900_000,
  },
  reporter: {
    provider: 'openai',
    model: 'qwen3.6-27b',
    baseUrl: 'http://127.0.0.1:8080/v1',
    maxTokens: 16384,
    requestTimeoutMs: 900_000,
  },
  counterPlannerTriggers: [],
  panelTriggers: ['severity_critical'],
  synthesizerTriggers: [],
  budgetCeiling: 0,
};

export const LOCAL_QWEN_CODEX_PROFILE: PortfolioProfile = {
  id: 'local_qwen_codex',
  name: 'Local Qwen 3.6 27B Codex — Codex/Ollama planner + local Qwen judge, zero API cost',
  planner: {
    provider: 'codex_cli',
    model: LOCAL_QWEN_CODEX_MODEL,
    localInference: true,
    cliLocalProvider: 'ollama',
    effort: 'high',
    requestTimeoutMs: 900_000,
  },
  judge: {
    provider: 'openai',
    model: 'qwen3.6-27b',
    baseUrl: 'http://127.0.0.1:8080/v1',
    maxTokens: 16384,
    requestTimeoutMs: 900_000,
  },
  reporter: {
    provider: 'codex_cli',
    model: LOCAL_QWEN_CODEX_MODEL,
    localInference: true,
    cliLocalProvider: 'ollama',
    effort: 'high',
    requestTimeoutMs: 900_000,
  },
  counterPlannerTriggers: [],
  panelTriggers: ['severity_critical'],
  synthesizerTriggers: [],
  budgetCeiling: 0,
  briefModeRoles: ['planner'],
};

export const LOCAL_QWEN_BOUNDED_PROFILE: PortfolioProfile = {
  id: 'local_qwen_bounded',
  name: 'Local Qwen 3.6 27B Bounded — sandboxed file access, mechanical budget limits',
  planner: {
    provider: 'bounded_local',
    model: 'qwen3.6-27b',
    baseUrl: 'http://127.0.0.1:8080/v1',
    maxTokens: 16384,
    localInference: true,
    requestTimeoutMs: 900_000,
    boundedConfig: { maxTurns: 8, readBudget: 8, toolMaxTokens: 1_024, synthesisMaxTokens: 2_048, maxReadChars: 6_000, maxContextChars: 60_000 },
  },
  judge: {
    provider: 'openai',
    model: 'qwen3.6-27b',
    baseUrl: 'http://127.0.0.1:8080/v1',
    maxTokens: 16384,
    requestTimeoutMs: 900_000,
  },
  reporter: {
    provider: 'bounded_local',
    model: 'qwen3.6-27b',
    baseUrl: 'http://127.0.0.1:8080/v1',
    maxTokens: 16384,
    localInference: true,
    requestTimeoutMs: 900_000,
    boundedConfig: { maxTurns: 5, readBudget: 4, toolMaxTokens: 1_024, synthesisMaxTokens: 4_096, maxReadChars: 6_000, maxContextChars: 60_000 },
  },
  counterPlannerTriggers: [],
  panelTriggers: ['severity_critical'],
  synthesizerTriggers: [],
  budgetCeiling: 0,
};

export const LOCAL_QWEN_PI_PROFILE: PortfolioProfile = {
  id: 'local_qwen_pi',
  name: 'Local Qwen Pi — Pi planner/reporter + local Qwen judge, zero API cost',
  planner: {
    provider: 'pi_cli',
    model: 'qwen3.6-27b',
    baseUrl: 'http://127.0.0.1:8080/v1',
    localInference: true,
    requestTimeoutMs: 900_000,
  },
  judge: {
    provider: 'openai',
    model: 'qwen3.6-27b',
    baseUrl: 'http://127.0.0.1:8080/v1',
    maxTokens: 16384,
    requestTimeoutMs: 900_000,
  },
  reporter: {
    provider: 'pi_cli',
    model: 'qwen3.6-27b',
    baseUrl: 'http://127.0.0.1:8080/v1',
    localInference: true,
    requestTimeoutMs: 900_000,
  },
  counterPlannerTriggers: [],
  panelTriggers: ['severity_critical'],
  synthesizerTriggers: [],
  budgetCeiling: 0,
};

export const SERIOUS_LOCAL_PROFILE: PortfolioProfile = {
  id: 'serious_local',
  name: 'Serious Local — Claude Code static, Codex local-live, mixed judge panel',
  // Workers with file/runtime access (claude_code, codex_cli) take
  // planner/counter-planner/synthesizer/reporter roles because those roles
  // need to read source, follow chains, and cite file:line references.
  // Judges use API models because arbitration is bounded reasoning and does
  // not need filesystem access. See docs/PORTFOLIO-PROFILES.md.
  planner: {
    provider: 'claude_code',
    model: 'claude-opus-4-6',
    effort: 'high',
  },
  counterPlanner: { provider: 'codex_cli', model: 'gpt-5.4', effort: 'high' },
  localLivePlanner: { provider: 'codex_cli', model: 'gpt-5.4', effort: 'max' },
  localLiveCounterPlanner: {
    provider: 'claude_code',
    model: 'claude-opus-4-6',
    effort: 'high',
  },
  judge: { provider: 'openai', model: 'gpt-5.4' },
  // Panel second member downgraded 2026-04-16 after the ollama + vllm
  // audits burnt $4.70 / $7.31 on the claude_code/opus panel member while
  // openai's side was $0.13 / $0.20 — a 36× cost asymmetry for verdict-
  // level agreement. Sonnet at medium effort preserves the cross-provider
  // dissent signal (same reason we keep two panel members) while dropping
  // the per-call cost ~4-8× vs opus/high. The synthesizer (still opus) is
  // the escalation path for genuinely contested findings, so the panel
  // doesn't need to be two opus-class reasoners in parallel.
  judgePanel: [
    { provider: 'openai', model: 'gpt-5.4' },
    { provider: 'claude_code', model: 'claude-sonnet-4-6', effort: 'medium' },
  ],
  synthesizer: {
    provider: 'claude_code',
    model: 'claude-opus-4-6',
    effort: 'high',
  },
  reporter: {
    provider: 'claude_code',
    model: 'claude-opus-4-6',
    effort: 'high',
  },
  counterPlannerTriggers: ['consecutive_dead_ends', 'high_novelty_hypothesis', 'chain_depth_exceeds_3'],
  // Panel triggers tightened 2026-04-15 after the fixture-target audit campaign
  // (inv-1776170280103) observed 8/8 panel escalations with unanimous
  // dead_end verdicts and zero confidence spread — the second panel member
  // (claude_code/opus at ~$0.69/call) added no verdict-level value because
  // the synthesizer (also opus, always-on) was re-verifying the judges'
  // work anyway. The previous trigger list escalated on
  // `severity_high` + `finding_crosses_trust_boundary`, which fires on
  // essentially every auth-adjacent hypothesis — effectively making the
  // panel the default path rather than the escalation path.
  //
  // The current list escalates only when:
  //   - severity is critical (highest-impact findings warrant a panel), OR
  //   - the single judge disagrees with the planner (true dissent signal).
  //
  // This should drop panel invocations from "every hypothesis" to "true
  // exceptional cases" while keeping the dissent-detection safety net.
  // See docs/PORTFOLIO-PROFILES.md for the full rationale.
  panelTriggers: ['severity_critical', 'planner_judge_disagree'],
  // Synthesizer triggers tightened 2026-04-15 alongside the panel
  // triggers. The previous `['always']` setting fired the synthesizer on
  // every panel invocation, and when the panel was unanimous (which was
  // 8/8 on the fixture-target audit) the synthesizer re-did the Opus panel
  // member's code-verification work for a second Opus-grade cost. Two
  // Opus passes on the same code is the textbook duplication this trigger
  // was meant to avoid.
  //
  // The current list only invokes the synthesizer when there is real
  // uncertainty that the panel members did not already resolve:
  //   - panel_disagreement: panel split on the verdict
  //   - contested_finding:  judges disagree on the shape of the finding
  //   - multi_surface_chain: hypothesis spans multiple trust surfaces and
  //     the synthesizer's cross-cutting reasoning is uniquely useful
  //
  // On unanimous-simple-chain panel verdicts, the single judge's output
  // stands and the synthesizer is skipped.
  synthesizerTriggers: ['panel_disagreement', 'contested_finding', 'multi_surface_chain'],
  budgetCeiling: 60,
  // Heavy reasoning stages use persistent worker sessions + brief manifests
  // so the worker reads context from disk instead of receiving a 30 KB
  // monolith. Only applies to roles whose adapter supports native session
  // resume (claude_code, codex_cli); API-only members of the judge panel
  // still take the legacy full-context path. See the recovery plan.
  briefModeRoles: ['planner', 'counter_planner', 'judge', 'judge_panel', 'synthesizer', 'test_synthesis', 'local_live_planner', 'local_live_counter_planner'],
};

export const SERIOUS_END_TO_END_PROFILE: PortfolioProfile = {
  ...SERIOUS_LOCAL_PROFILE,
  id: 'serious_end_to_end',
  name: 'Serious End-to-End — hybrid workers plus full panel and synthesis',
  budgetCeiling: 100,
};

// ---------------------------------------------------------------------------
// Profile resolution
// ---------------------------------------------------------------------------

const PROFILES: Record<string, PortfolioProfile> = {
  balanced: BALANCED_PROFILE,
  ultimate: ULTIMATE_PROFILE,
  cost_sensitive: COST_SENSITIVE_PROFILE,
  production: PRODUCTION_PROFILE,
  local_qwen: LOCAL_QWEN_PROFILE,
  local_qwen_codex: LOCAL_QWEN_CODEX_PROFILE,
  local_qwen_bounded: LOCAL_QWEN_BOUNDED_PROFILE,
  local_qwen_pi: LOCAL_QWEN_PI_PROFILE,
  serious_local: SERIOUS_LOCAL_PROFILE,
  serious_end_to_end: SERIOUS_END_TO_END_PROFILE,
};

export function getProfile(id: string): PortfolioProfile | undefined {
  return PROFILES[id];
}

export function getDefaultProfile(): PortfolioProfile {
  return PRODUCTION_PROFILE;
}

export function listProfiles(): PortfolioProfile[] {
  return Object.values(PROFILES);
}

export function getSeriousVerificationProfile(): PortfolioProfile {
  return SERIOUS_LOCAL_PROFILE;
}

export function isLowRigorProfile(profile: PortfolioProfile): boolean {
  return profile.id === 'balanced' || profile.id === 'cost_sensitive' || profile.id === 'local_qwen' || profile.id === 'local_qwen_codex' || profile.id === 'local_qwen_bounded' || profile.id === 'local_qwen_pi';
}

// ---------------------------------------------------------------------------
// Trigger evaluation
// ---------------------------------------------------------------------------

export function shouldUseCounterPlanner(
  profile: PortfolioProfile,
  context: {
    consecutiveDeadEnds: number;
    noveltyScore?: number;
    chainDepth?: number;
    budgetUsedPercent?: number;
  },
): boolean {
  if (!profile.counterPlanner) return false;

  for (const trigger of profile.counterPlannerTriggers) {
    switch (trigger) {
      case 'consecutive_dead_ends':
        if (context.consecutiveDeadEnds >= 3) return true;
        break;
      case 'high_novelty_hypothesis':
        if (context.noveltyScore && context.noveltyScore > 0.8) return true;
        break;
      case 'chain_depth_exceeds_3':
        if (context.chainDepth && context.chainDepth > 3) return true;
        break;
      case 'budget_above_50_percent':
        if (context.budgetUsedPercent && context.budgetUsedPercent > 0.5) return true;
        break;
    }
  }
  return false;
}

export function shouldUseJudgePanel(
  profile: PortfolioProfile,
  context: {
    severity?: string;
    plannerJudgeDisagree?: boolean;
    involvesDormant?: boolean;
    crossesBoundary?: boolean;
  },
): boolean {
  if (!profile.judgePanel || profile.judgePanel.length === 0) return false;

  for (const trigger of profile.panelTriggers) {
    switch (trigger) {
      case 'severity_critical':
        if (context.severity === 'critical') return true;
        break;
      case 'severity_high':
        if (context.severity === 'high') return true;
        break;
      case 'planner_judge_disagree':
        if (context.plannerJudgeDisagree) return true;
        break;
      case 'chain_involves_dormant_reactivation':
        if (context.involvesDormant) return true;
        break;
      case 'finding_crosses_trust_boundary':
        if (context.crossesBoundary) return true;
        break;
    }
  }
  return false;
}

export function shouldUseSynthesizer(
  profile: PortfolioProfile,
  context: {
    panelDisagreement?: boolean;
    contested?: boolean;
    multiSurface?: boolean;
  },
): boolean {
  if (!profile.synthesizer) return false;

  for (const trigger of profile.synthesizerTriggers) {
    switch (trigger) {
      case 'panel_disagreement':
        if (context.panelDisagreement) return true;
        break;
      case 'contested_finding':
        if (context.contested) return true;
        break;
      case 'multi_surface_chain':
        if (context.multiSurface) return true;
        break;
      case 'always':
        return true;
    }
  }
  return false;
}
