import test from 'node:test';
import assert from 'node:assert/strict';
import {
  getDefaultProfile,
  getProfile,
  getSeriousVerificationProfile,
  isLowRigorProfile,
  LOCAL_QWEN_CODEX_MODEL,
  listProfiles,
  shouldUseCounterPlanner,
  shouldUseJudgePanel,
  shouldUseSynthesizer,
} from './portfolio-profiles.js';

test('portfolio profiles expose the expected ultimate model topology and triggers', () => {
  const profile = getProfile('ultimate');
  assert.ok(profile);
  assert.equal(profile?.planner.model, 'gpt-5.4');
  assert.equal(profile?.counterPlanner?.model, 'gemini-3.1-pro-preview');
  assert.equal(profile?.synthesizer?.model, 'claude-opus-4-6');
  assert.equal(profile?.judgePanel?.length, 3);

  assert.equal(
    shouldUseCounterPlanner(profile!, {
      consecutiveDeadEnds: 3,
      chainDepth: 4,
      noveltyScore: 0.9,
      budgetUsedPercent: 0.3,
    }),
    true,
  );
  assert.equal(
    shouldUseJudgePanel(profile!, {
      severity: 'critical',
      involvesDormant: false,
      crossesBoundary: false,
      plannerJudgeDisagree: false,
    }),
    true,
  );
  assert.equal(
    shouldUseSynthesizer(profile!, {
      panelDisagreement: true,
      contested: true,
      multiSurface: true,
    }),
    true,
  );
  assert.equal(getDefaultProfile().id, 'production');
});

test('portfolio profiles expose serious verification defaults and low-rigor classification', () => {
  const production = getDefaultProfile();
  assert.equal(production.id, 'production');
  assert.equal(production.judgePanel?.length, 2);

  const serious = getSeriousVerificationProfile();
  assert.equal(serious.id, 'serious_local');
  assert.equal(serious.planner.provider, 'claude_code');
  assert.equal(serious.planner.model, 'claude-opus-4-6');
  assert.equal(serious.counterPlanner?.provider, 'codex_cli');
  assert.equal(serious.counterPlanner?.model, 'gpt-5.4');
  assert.equal(serious.localLivePlanner?.provider, 'codex_cli');
  assert.equal(serious.localLivePlanner?.model, 'gpt-5.4');
  assert.equal(serious.localLivePlanner?.effort, 'max');
  assert.equal(serious.localLiveCounterPlanner?.provider, 'claude_code');
  assert.equal(serious.localLiveCounterPlanner?.model, 'claude-opus-4-6');
  // Primary judge stays API-based; the second panel seat uses Claude Code so
  // serious runs do not depend on an Anthropic API key for Anthropic coverage.
  assert.equal(serious.judge.provider, 'openai');
  assert.equal(serious.judgePanel?.length, 2);
  assert.equal(serious.judgePanel?.[0]?.provider, 'openai');
  assert.equal(serious.judgePanel?.[0]?.model, 'gpt-5.4');
  assert.equal(serious.judgePanel?.[1]?.provider, 'claude_code');
  // Downgraded from opus/high to sonnet/medium on 2026-04-16 after the
  // ollama + vllm audits surfaced a 36x cost asymmetry between the opus
  // panel member and the openai primary. Sonnet at medium effort preserves
  // cross-provider dissent signal while dropping per-call cost ~4-8x.
  assert.equal(serious.judgePanel?.[1]?.model, 'claude-sonnet-4-6');
  assert.equal(serious.judgePanel?.[1]?.effort, 'medium');
  // Synthesizer and reporter read cited evidence files, so they run on claude_code.
  assert.equal(serious.synthesizer?.provider, 'claude_code');
  assert.equal(serious.reporter?.provider, 'claude_code');
  // (shouldUseSynthesizer assertions are in the "Synthesizer triggers" block below —
  //  the previous `always` behaviour was demoted on 2026-04-15.)

  // Panel triggers — tightened 2026-04-15 (see portfolio-profiles.ts
  // comment for rationale). serious_local must escalate to panel ONLY on
  // critical severity OR true planner/judge disagreement. Escalation on
  // severity_high / finding_crosses_trust_boundary / dormant_reactivation
  // is intentionally NOT allowed because those triggered on essentially
  // every hypothesis in the fixture-target audit, producing 8/8 unanimous panel
  // verdicts with zero confidence spread for $5.54 of no-value work.
  assert.deepEqual(serious.panelTriggers, ['severity_critical', 'planner_judge_disagree']);
  // severity_critical alone → panel
  assert.equal(shouldUseJudgePanel(serious, { severity: 'critical' }), true);
  // severity_high alone → NO panel (this was the regression)
  assert.equal(shouldUseJudgePanel(serious, { severity: 'high' }), false, 'severity_high must not trigger the panel on its own');
  // finding_crosses_trust_boundary alone → NO panel (this was the regression)
  assert.equal(shouldUseJudgePanel(serious, { crossesBoundary: true }), false, 'crossing a trust boundary must not trigger the panel on its own');
  // planner_judge_disagree alone → panel
  assert.equal(shouldUseJudgePanel(serious, { plannerJudgeDisagree: true }), true);
  // dormant reactivation alone → NO panel (removed trigger)
  assert.equal(shouldUseJudgePanel(serious, { involvesDormant: true }), false, 'dormant reactivation must not trigger the panel on its own');

  // Synthesizer triggers — demoted 2026-04-15 from ['always'] to the
  // panel-disagreement / contested / multi-surface set. Running the
  // synthesizer on every hypothesis re-does the opus panel member's
  // code-verification work. It should only fire when there is genuine
  // uncertainty the panel members did not resolve.
  assert.deepEqual(serious.synthesizerTriggers, ['panel_disagreement', 'contested_finding', 'multi_surface_chain']);
  // Unanimous panel verdict on a single-surface chain → NO synthesizer.
  assert.equal(shouldUseSynthesizer(serious, {}), false, 'empty context (no disagreement, no contested, no multi-surface) must not invoke the synthesizer');
  // Panel disagreement → synthesizer fires.
  assert.equal(shouldUseSynthesizer(serious, { panelDisagreement: true }), true);
  // Contested finding → synthesizer fires.
  assert.equal(shouldUseSynthesizer(serious, { contested: true }), true);
  // Multi-surface chain → synthesizer fires (cross-cutting reasoning).
  assert.equal(shouldUseSynthesizer(serious, { multiSurface: true }), true);

  const endToEndRoles = getProfile('serious_end_to_end');
  assert.ok(endToEndRoles);
  assert.equal(endToEndRoles?.planner.provider, 'claude_code');
  assert.equal(endToEndRoles?.counterPlanner?.provider, 'codex_cli');
  assert.equal(endToEndRoles?.localLivePlanner?.provider, 'codex_cli');
  assert.equal(endToEndRoles?.localLiveCounterPlanner?.provider, 'claude_code');
  assert.equal(endToEndRoles?.judgePanel?.[0]?.provider, 'openai');
  assert.equal(endToEndRoles?.judgePanel?.[1]?.provider, 'claude_code');
  assert.equal(endToEndRoles?.synthesizer?.provider, 'claude_code');
  assert.equal(endToEndRoles?.reporter?.provider, 'claude_code');

  const endToEnd = getProfile('serious_end_to_end');
  assert.ok(endToEnd);
  assert.equal(endToEnd?.budgetCeiling, 100);

  const profiles = listProfiles()
    .map((profile) => profile.id)
    .sort();
  assert.deepEqual(profiles, ['balanced', 'cost_sensitive', 'local_qwen', 'local_qwen_bounded', 'local_qwen_codex', 'local_qwen_pi', 'production', 'serious_end_to_end', 'serious_local', 'ultimate']);

  assert.equal(isLowRigorProfile(getProfile('balanced')!), true);
  assert.equal(isLowRigorProfile(getProfile('cost_sensitive')!), true);
  assert.equal(isLowRigorProfile(getProfile('local_qwen')!), true);
  assert.equal(getProfile('local_qwen')?.planner.requestTimeoutMs, 900_000);
  assert.equal(getProfile('local_qwen')?.judge.requestTimeoutMs, 900_000);
  assert.equal(getProfile('local_qwen')?.reporter?.requestTimeoutMs, 900_000);
  const localCodex = getProfile('local_qwen_codex');
  assert.ok(localCodex);
  assert.equal(isLowRigorProfile(localCodex!), true);
  assert.equal(localCodex?.planner.provider, 'codex_cli');
  assert.equal(localCodex?.planner.model, LOCAL_QWEN_CODEX_MODEL);
  assert.equal(localCodex?.planner.localInference, true);
  assert.equal(localCodex?.planner.cliLocalProvider, 'ollama');
  assert.equal(localCodex?.planner.requestTimeoutMs, 900_000);
  assert.deepEqual(localCodex?.briefModeRoles, ['planner']);
  assert.equal(localCodex?.judge.provider, 'openai');
  assert.equal(localCodex?.judge.baseUrl, 'http://127.0.0.1:8080/v1');
  assert.equal(localCodex?.reporter?.provider, 'codex_cli');
  assert.equal(localCodex?.reporter?.localInference, true);
  assert.equal(localCodex?.reporter?.cliLocalProvider, 'ollama');
  const bounded = getProfile('local_qwen_bounded');
  assert.ok(bounded);
  assert.equal(isLowRigorProfile(bounded!), true);
  assert.equal(bounded?.planner.provider, 'bounded_local');
  assert.equal(bounded?.planner.model, 'qwen3.6-27b');
  assert.equal(bounded?.planner.localInference, true);
  assert.equal(bounded?.planner.requestTimeoutMs, 900_000);
  assert.ok(bounded?.planner.boundedConfig);
  assert.equal(bounded?.planner.boundedConfig?.maxTurns, 8);
  assert.equal(bounded?.planner.boundedConfig?.readBudget, 8);
  assert.equal(bounded?.planner.boundedConfig?.toolMaxTokens, 1_024);
  assert.equal(bounded?.planner.boundedConfig?.synthesisMaxTokens, 2_048);
  assert.equal(bounded?.planner.boundedConfig?.maxReadChars, 6_000);
  assert.equal(bounded?.planner.boundedConfig?.maxContextChars, 60_000);
  assert.equal(bounded?.judge.provider, 'openai');
  assert.equal(bounded?.judge.baseUrl, 'http://127.0.0.1:8080/v1');
  assert.equal(bounded?.reporter?.provider, 'bounded_local');
  assert.equal(bounded?.reporter?.localInference, true);
  assert.equal(bounded?.reporter?.boundedConfig?.maxTurns, 5);
  assert.equal(bounded?.reporter?.boundedConfig?.readBudget, 4);
  assert.equal(bounded?.reporter?.boundedConfig?.toolMaxTokens, 1_024);
  assert.equal(bounded?.reporter?.boundedConfig?.synthesisMaxTokens, 4_096);
  assert.equal(bounded?.reporter?.boundedConfig?.maxReadChars, 6_000);
  assert.equal(bounded?.reporter?.boundedConfig?.maxContextChars, 60_000);
  assert.equal(bounded?.budgetCeiling, 0);
  const piProfile = getProfile('local_qwen_pi');
  assert.ok(piProfile);
  assert.equal(isLowRigorProfile(piProfile!), true);
  assert.equal(piProfile?.planner.provider, 'pi_cli');
  assert.equal(piProfile?.planner.model, 'qwen3.6-27b');
  assert.equal(piProfile?.planner.localInference, true);
  assert.equal(piProfile?.planner.requestTimeoutMs, 900_000);
  assert.equal(piProfile?.judge.provider, 'openai');
  assert.equal(piProfile?.judge.baseUrl, 'http://127.0.0.1:8080/v1');
  assert.equal(piProfile?.reporter?.provider, 'pi_cli');
  assert.equal(piProfile?.reporter?.localInference, true);
  assert.equal(piProfile?.budgetCeiling, 0);
  assert.equal(isLowRigorProfile(serious), false);
});
