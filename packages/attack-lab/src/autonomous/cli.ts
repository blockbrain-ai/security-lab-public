/**
 * CLI entry point for autonomous investigation.
 *
 * Usage:
 *   npm run investigate -- --target /path/to/repo
 *   npm run investigate -- --target targets/example-http.yaml
 */

import { resolve } from 'node:path';
import { loadSecurityLabEnvironment } from '../bootstrap/env-loader.js';
import { runDoctor } from '../doctor/runner.js';
import { createAdapter } from '../providers/adapter-factory.js';
import type { ModelConfig } from '../providers/contracts.js';
import { UnavailableAdapter } from '../providers/unavailable-adapter.js';
import { InvestigationRunner } from './investigation-runner.js';
import { STAGES, type Stage } from './contracts.js';
import { resolveRoleConfig } from './cli-role-config.js';
import { assertOptionalSafeIdentifier } from './identifiers.js';
import { HOST_EXECUTION_ENV_VAR } from '../providers/execution-policy.js';
import { DEFAULT_CAMPAIGN_DIR, DEFAULT_MAX_COST_USD, DEFAULT_MAX_ITERATIONS } from './cli-defaults.js';
import { DEFAULT_RUN_MODE, RUN_MODES, describeRunMode, inferModeFromPreset, isRunMode, type RunMode } from './mode.js';
import {
  getDefaultProfile,
  getProfile,
  getSeriousVerificationProfile,
  isLowRigorProfile,
  listProfiles,
  SERIOUS_END_TO_END_PROFILE,
  SERIOUS_LOCAL_PROFILE,
} from '../orchestration/portfolio-profiles.js';
import type { PanelMember } from '../orchestration/judge-panel.js';
import { loadInvestigationTarget } from './target-profile.js';

type SeriousPreset = 'serious-local' | 'serious-end-to-end' | 'smoke' | 'diagnostic';
type LinuxRuntimeMode = 'container' | 'fail' | 'skip';
type ResumeAt = 'auto' | 'verification' | 'assessment';

interface CliOptions {
  target: string;
  targetId: string;
  envFile?: string;
  mode: 'declared' | 'blind';
  portfolio?: string;
  preset?: SeriousPreset;
  listPortfolios: boolean;
  runMode: RunMode;
  runModeExplicit: boolean;
  exitZeroOnIncomplete: boolean;
  allowDegraded: boolean;
  strictVerification: boolean;
  linuxRuntime: LinuxRuntimeMode;
  testTimeoutMs?: number;
  requestTimeoutMs?: number;
  resumeAt: ResumeAt;
  judgeLimit?: number;
  testSynthesisLimit?: number;
  verificationHypothesisLimit?: number;
  liveProbesPerHypothesis?: number;
  localLiveRounds?: number;
  runtimeSignalsPerRound?: number;
  focusedClosureReads?: number;
  workerPrimary?: 'claude_code' | 'codex_cli';
  workerCounter?: 'claude_code' | 'codex_cli';
  plannerProvider: string;
  plannerModel: string;
  plannerBaseUrl?: string;
  plannerMaxTokens?: number;
  plannerLocalInference?: boolean;
  plannerCliLocalProvider?: 'ollama' | 'lmstudio';
  plannerCliProfile?: string;
  judgeProvider: string;
  judgeModel: string;
  judgeBaseUrl?: string;
  judgeMaxTokens?: number;
  judgeLocalInference?: boolean;
  judgeCliLocalProvider?: 'ollama' | 'lmstudio';
  judgeCliProfile?: string;
  tribunalProvider?: string;
  tribunalModel?: string;
  maxIterations: number;
  maxCost: number;
  resume?: string;
  campaignDir: string;
  knowledgeBasePath?: string;
  confirmLive: boolean;
  liveTarget?: string;
  liveTargetId?: string;
  // Verification lanes
  verifyVia: string[];
  hostedTarget?: string;
  authorizeHosted: boolean;
  allowLocalMutations: boolean;
  allowHostedMutations: boolean;
  identityLadder?: string;
  baselinePath?: string;
  quarantineDir?: string;
  monitoringStress: boolean;
  pairedModes: boolean;
  contextBand?: string;
  /** Named stage to resume into (Section 1.1 durable stages). */
  resumeAtStage?: Stage;
  /** Skip preflight doctor check. */
  skipPreflight: boolean;
  /** Force dry-run mode for all mutation probes. */
  dryRunMutations: boolean;
  /** Revert to pre-3.1 hard rejection behavior for probes. */
  strictProbes: boolean;
  /** Section 6.1 — disable response-driven adaptive exploration in local-live. */
  disableAdaptiveExploration: boolean;
  /** Section 6.2 — force-enable the Mythos creativity sub-lane. */
  mythosEnabled?: boolean;
  /** Section 6.2 — override the Mythos time budget in ms. */
  mythosTimeMs?: number;
  /** Section 6.2 — override the Mythos probe budget. */
  mythosProbes?: number;
}

function parseArgs(argv: string[]): CliOptions {
  const args = argv.slice(2);

  if (args.includes('--help') || args.includes('-h')) {
    printHelp();
    process.exit(0);
  }

  // Host execution is opt-in (see providers/execution-policy.ts). The flag is
  // applied process-wide so every adapter construction path observes it.
  if (args.includes('--allow-host-execution')) {
    process.env[HOST_EXECUTION_ENV_VAR] = '1';
  }

  const rawRunMode = getArg(args, '--run-mode');
  const envRunMode = process.env['RUN_MODE'];
  const preset = (getArg(args, '--preset') as SeriousPreset | null) ?? undefined;
  let runMode: RunMode;
  let runModeExplicit = false;
  if (rawRunMode !== null) {
    if (!isRunMode(rawRunMode)) {
      throw new Error(`Invalid --run-mode value "${rawRunMode}". Valid values: ${RUN_MODES.join(', ')}`);
    }
    runMode = rawRunMode;
    runModeExplicit = true;
  } else {
    const inferred = inferModeFromPreset(preset);
    if (inferred) {
      runMode = inferred;
    } else if (envRunMode && isRunMode(envRunMode)) {
      runMode = envRunMode;
    } else {
      runMode = DEFAULT_RUN_MODE;
    }
  }

  if (args.includes('--strict-verification')) {
    console.warn('[security-lab] --strict-verification is deprecated; use --run-mode serious-local instead.');
  }
  if (args.includes('--allow-degraded')) {
    console.warn('[security-lab] --allow-degraded is deprecated; use --run-mode smoke instead.');
  }

  return {
    target: getArg(args, '--target') ?? '.',
    targetId: getArg(args, '--target-id') ?? 'default',
    envFile: getArg(args, '--env-file') ?? undefined,
    mode: (getArg(args, '--mode') as 'declared' | 'blind') ?? 'declared',
    portfolio: getArg(args, '--portfolio') ?? undefined,
    preset,
    listPortfolios: args.includes('--list-portfolios'),
    runMode,
    runModeExplicit,
    exitZeroOnIncomplete: args.includes('--exit-zero-on-incomplete'),
    allowDegraded: args.includes('--allow-degraded'),
    strictVerification: args.includes('--strict-verification'),
    linuxRuntime: (getArg(args, '--linux-runtime') as LinuxRuntimeMode | null) ?? 'container',
    testTimeoutMs: getOptionalNumberArg(args, '--test-timeout-ms'),
    requestTimeoutMs: getOptionalNumberArg(args, '--request-timeout-ms'),
    resumeAt: (getArg(args, '--resume-at') as ResumeAt | null) ?? 'auto',
    judgeLimit: getOptionalNumberArg(args, '--judge-limit'),
    testSynthesisLimit: getOptionalNumberArg(args, '--test-synthesis-limit'),
    verificationHypothesisLimit: getOptionalNumberArg(args, '--verification-hypotheses'),
    liveProbesPerHypothesis: getOptionalNumberArg(args, '--live-probes-per-hypothesis'),
    localLiveRounds: getOptionalNumberArg(args, '--local-live-rounds'),
    runtimeSignalsPerRound: getOptionalNumberArg(args, '--runtime-signals-per-round'),
    focusedClosureReads: getOptionalNumberArg(args, '--focused-closure-reads'),
    workerPrimary: (getArg(args, '--worker-primary') as 'claude_code' | 'codex_cli' | null) ?? undefined,
    workerCounter: (getArg(args, '--worker-counter') as 'claude_code' | 'codex_cli' | null) ?? undefined,
    plannerProvider: getArg(args, '--planner-provider') ?? '',
    plannerModel: getArg(args, '--planner-model') ?? '',
    plannerBaseUrl: getArg(args, '--planner-base-url') ?? undefined,
    plannerMaxTokens: getOptionalNumberArg(args, '--planner-max-tokens'),
    plannerLocalInference: args.includes('--planner-local-inference'),
    plannerCliLocalProvider: (getArg(args, '--planner-cli-local-provider') as 'ollama' | 'lmstudio' | null) ?? undefined,
    plannerCliProfile: getArg(args, '--planner-cli-profile') ?? undefined,
    judgeProvider: getArg(args, '--judge-provider') ?? '',
    judgeModel: getArg(args, '--judge-model') ?? '',
    judgeBaseUrl: getArg(args, '--judge-base-url') ?? undefined,
    judgeMaxTokens: getOptionalNumberArg(args, '--judge-max-tokens'),
    judgeLocalInference: args.includes('--judge-local-inference'),
    judgeCliLocalProvider: (getArg(args, '--judge-cli-local-provider') as 'ollama' | 'lmstudio' | null) ?? undefined,
    judgeCliProfile: getArg(args, '--judge-cli-profile') ?? undefined,
    tribunalProvider: getArg(args, '--tribunal-provider') ?? undefined,
    tribunalModel: getArg(args, '--tribunal-model') ?? undefined,
    maxIterations: Number(getArg(args, '--max-iterations') ?? String(DEFAULT_MAX_ITERATIONS)),
    // Default matches the documented value in --help (10.00 USD).
    maxCost: Number(getArg(args, '--max-cost') ?? DEFAULT_MAX_COST_USD.toFixed(2)),
    // A campaign id becomes a path segment under the campaign dir and is read
    // back from state.json on resume: reject traversal at the boundary.
    resume: assertOptionalSafeIdentifier(getArg(args, '--resume'), '--resume campaign id'),
    campaignDir: getArg(args, '--campaign-dir') ?? resolve(DEFAULT_CAMPAIGN_DIR),
    knowledgeBasePath: getArg(args, '--knowledge-base') ?? undefined,
    confirmLive: args.includes('--confirm-live'),
    liveTarget: getArg(args, '--live-target') ?? undefined,
    liveTargetId: getArg(args, '--live-target-id') ?? undefined,
    verifyVia: (getArg(args, '--verify-via') ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    hostedTarget: getArg(args, '--hosted-target') ?? undefined,
    authorizeHosted: args.includes('--authorize-hosted'),
    allowLocalMutations: args.includes('--allow-local-mutations'),
    allowHostedMutations: args.includes('--allow-hosted-mutations'),
    identityLadder: getArg(args, '--identity-ladder') ?? undefined,
    baselinePath: getArg(args, '--baseline-path') ?? undefined,
    quarantineDir: getArg(args, '--quarantine-dir') ?? undefined,
    monitoringStress: args.includes('--monitoring-stress'),
    pairedModes: args.includes('--paired-modes'),
    contextBand: getArg(args, '--context-band') ?? undefined,
    resumeAtStage: parseResumeAtStage(getArg(args, '--resume-at-stage')),
    skipPreflight: args.includes('--skip-preflight'),
    dryRunMutations: args.includes('--dry-run-mutations'),
    strictProbes: args.includes('--strict-probes'),
    disableAdaptiveExploration: args.includes('--no-adaptive-exploration'),
    mythosEnabled: args.includes('--mythos-enabled') ? true : args.includes('--no-mythos') ? false : undefined,
    mythosTimeMs: getOptionalNumberArg(args, '--mythos-time-ms'),
    mythosProbes: getOptionalNumberArg(args, '--mythos-probes'),
  };
}

function getArg(args: string[], flag: string): string | null {
  const idx = args.indexOf(flag);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1]! : null;
}

function parseResumeAtStage(value: string | null): Stage | undefined {
  if (!value) return undefined;
  if ((STAGES as readonly string[]).includes(value)) {
    return value as Stage;
  }
  throw new Error(`Invalid --resume-at-stage value "${value}". Valid stages: ${STAGES.join(', ')}`);
}

function getOptionalNumberArg(args: string[], flag: string): number | undefined {
  const value = getArg(args, flag);
  if (!value) {
    return undefined;
  }
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function printHelp(): void {
  console.log(`Usage: npm run investigate -- [options]

Use Security Lab only against systems you own or have explicit written
authorisation to test, and only within the scope that authorisation covers.
See README.md (Authorised use only) for the full notice.

Options:
  --target <path>           Target repository path or YAML target profile (default: .)
  --target-id <id>          Target identifier (default: default)
  --env-file <path>         Security Lab env file (highest file-based precedence)
  --mode <mode>             declared or blind (default: declared)
  --portfolio <id>          Portfolio profile (see --list-portfolios)
  --preset <name>           serious-local, serious-end-to-end, smoke, or diagnostic
  --list-portfolios         Show available model portfolios and exit
  --allow-host-execution    Permit providers that run code on this host (CLI coding
                            agents, bounded-local shell). Off by default: a scanned
                            repository could otherwise execute commands as your user.
  --run-mode <mode>         Run rigor: smoke (default), serious-local, serious-end-to-end.
                            smoke degrades honestly; serious modes fail closed on
                            missing required verification coverage.
  --exit-zero-on-incomplete Force exit code 0 even when a serious run is incomplete
                            (parse the report instead of exit code).
  --allow-degraded          DEPRECATED — use --run-mode smoke
  --strict-verification     DEPRECATED — use --run-mode serious-local
  --linux-runtime <mode>    container, fail, or skip (default: container)
  --test-timeout-ms <ms>    Override synthesized test timeout (default: 120000)
  --request-timeout-ms <ms> Override provider request timeout (default: 180000)
  --resume-at <phase>       auto, verification, or assessment (default: auto)
  --resume-at-stage <stage> Resume into a named stage: ${STAGES.join(', ')}
  --skip-preflight          Skip preflight doctor check (serious modes reject this unless --allow-degraded)
  --judge-limit <n>         Max hypotheses judged per static iteration (default: 5)
  --test-synthesis-limit <n>  Max synthesized verification tests per run (default: 3)
  --verification-hypotheses <n> Max static hypotheses translated into live verification (default: 15)
  --live-probes-per-hypothesis <n> Max live probes generated per hypothesis (default: 3)
  --local-live-rounds <n>   Max iterative local-live rounds per packet (default from target policy)
  --runtime-signals-per-round <n> Max runtime weak signals to surface per round
  --focused-closure-reads <n> Mandatory focused closure file reads before final assessment
  --worker-primary <kind>   Primary serious worker transport: claude_code or codex_cli
  --worker-counter <kind>   Counter-investigator worker transport: claude_code or codex_cli
  --planner-provider <p>    Optional planner override
  --planner-model <m>       Optional planner model override
  --planner-base-url <url>  Optional planner OpenAI-compatible base URL override
  --planner-max-tokens <n>  Optional planner max-tokens override
  --planner-local-inference Treat planner as zero-cost local inference
  --planner-cli-local-provider <p> Codex local provider override: ollama or lmstudio
  --planner-cli-profile <id> Codex config profile override for planner
  --judge-provider <p>      Optional judge override
  --judge-model <m>         Optional judge model override
  --judge-base-url <url>    Optional judge OpenAI-compatible base URL override
  --judge-max-tokens <n>    Optional judge max-tokens override
  --judge-local-inference   Treat judge as zero-cost local inference
  --judge-cli-local-provider <p> Codex local provider override: ollama or lmstudio
  --judge-cli-profile <id>  Codex config profile override for judge
  --tribunal-provider <p>   Optional tribunal provider for critical findings
  --tribunal-model <m>      Optional tribunal model for critical findings
  --max-iterations <n>      Maximum iterations (default: ${DEFAULT_MAX_ITERATIONS})
  --max-cost <n>            Maximum cost in USD (default: ${DEFAULT_MAX_COST_USD.toFixed(2)})
  --resume <campaign-id>    Resume a previous campaign
  --campaign-dir <path>     Campaign data directory (default: data/campaigns)
  --knowledge-base <path>   Override knowledge base path
  --confirm-live            Run the integrated local-live confirmation lane after static analysis
  --live-target <path>      YAML target profile for live confirmation
  --live-target-id <id>     Optional live target identifier override

Verification lanes (post-assessment):
  --verify-via <list>       Comma-separated lanes: test-synthesis,local-live,hosted,supply-chain
  --hosted-target <path>    YAML target profile for hosted verification
  --authorize-hosted        Required to permit any hosted lane probe
  --allow-local-mutations   Permit POST/PUT/DELETE during local-live lane
  --dry-run-mutations       Force dry-run mode for all mutations (headers built, URL resolved, no request sent)
  --strict-probes           Revert to pre-3.1 hard rejection for missing identities and unauthorized mutations
  --allow-hosted-mutations  Permit POST/PUT/DELETE during hosted lane
  --no-adaptive-exploration Disable response-driven adaptive exploration in the local-live lane
                            (Section 6.1). Use for diagnostic replay-only runs.
  --mythos-enabled          Force-enable the Mythos creativity sub-lane (Section 6.2).
                            Off by default in smoke mode; on by default in serious modes.
  --no-mythos               Force-disable the Mythos creativity sub-lane.
  --mythos-time-ms <ms>     Override the Mythos time budget (default 300000).
  --mythos-probes <n>       Override the Mythos probe budget (default 20).
  --identity-ladder <id>    Identity ladder ID to load from the live target
  --baseline-path <path>    Supply-chain baseline JSON to compare against
  --quarantine-dir <path>   Directory to unpack quarantined artifacts
  --monitoring-stress       Enable monitoring stress mode in the local-live lane
                            (Section 8.2: detection hooks run alongside probes)
  --paired-modes            Run paired declared/blind monitoring stress
  --context-band <band>     Context band: baseline, 50k, 100k, 200k, 400k

  -h, --help                Show this help
`);
}

function needsSeriousVerification(options: CliOptions): boolean {
  return (
    options.runMode === 'serious-local' ||
    options.runMode === 'serious-end-to-end' ||
    options.strictVerification ||
    options.preset === 'serious-local' ||
    options.preset === 'serious-end-to-end' ||
    options.confirmLive ||
    options.verifyVia.includes('local-live') ||
    options.verifyVia.includes('hosted')
  );
}

function resolvePortfolio(options: CliOptions) {
  const serious = needsSeriousVerification(options);
  if (options.preset === 'serious-local') {
    return SERIOUS_LOCAL_PROFILE;
  }
  if (options.preset === 'serious-end-to-end') {
    return SERIOUS_END_TO_END_PROFILE;
  }
  if (options.preset === 'smoke') {
    return getProfile('balanced') ?? getDefaultProfile();
  }
  if (options.preset === 'diagnostic') {
    return getDefaultProfile();
  }
  if (options.portfolio) {
    return getProfile(options.portfolio) ?? getDefaultProfile();
  }
  return serious ? getSeriousVerificationProfile() : getDefaultProfile();
}

function withRequestTimeout<T extends { requestTimeoutMs?: number }>(config: T, requestTimeoutMs?: number): T {
  if (!requestTimeoutMs) {
    return config;
  }
  return {
    ...config,
    requestTimeoutMs,
  };
}

function withTransportContext<
  T extends {
    workingDirectory?: string;
    additionalDirectories?: string[];
    effort?: 'low' | 'medium' | 'high' | 'max';
  },
>(config: T, workingDirectory: string, additionalDirectories: string[]): T {
  return {
    ...config,
    workingDirectory,
    additionalDirectories,
  };
}

function canFallbackToUnavailable(options: CliOptions): boolean {
  return Boolean(options.resume && (options.resumeAt === 'verification' || options.resumeAt === 'assessment'));
}

function createRequiredAdapter(role: string, config: ModelConfig, allowUnavailable: boolean) {
  try {
    return createAdapter(config);
  } catch (error) {
    if (!allowUnavailable) {
      throw error;
    }
    const reason = error instanceof Error ? error.message : String(error);
    console.warn(`[security-lab] ${role} adapter unavailable; verification will fall back where possible: ${reason}`);
    return new UnavailableAdapter(`${config.provider}/${config.model}`, `${role}: ${reason}`);
  }
}

function createOptionalAdapter(role: string, config: ModelConfig | undefined) {
  if (!config) {
    return undefined;
  }
  try {
    return createAdapter(config);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    console.warn(`[security-lab] ${role} adapter unavailable; role will be omitted or downgraded: ${reason}`);
    return undefined;
  }
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv);
  await loadSecurityLabEnvironment({ envFile: options.envFile });
  if (options.listPortfolios) {
    console.log('Available portfolios:');
    for (const profile of listProfiles()) {
      console.log(`- ${profile.id}: ${profile.name}`);
      console.log(`  planner=${profile.planner.provider}/${profile.planner.model}`);
      console.log(`  judge=${profile.judge.provider}/${profile.judge.model}`);
      if (profile.judgePanel?.length) {
        console.log(`  panel=${profile.judgePanel.map((member) => `${member.provider}/${member.model}`).join(', ')}`);
      }
      if (profile.synthesizer) {
        console.log(`  synthesizer=${profile.synthesizer.provider}/${profile.synthesizer.model}`);
      }
      if (profile.reporter) {
        console.log(`  reporter=${profile.reporter.provider}/${profile.reporter.model}`);
      }
    }
    return;
  }

  const profile = resolvePortfolio(options);
  const seriousVerification = needsSeriousVerification(options);
  const strictVerification = seriousVerification || options.strictVerification;
  if (seriousVerification && isLowRigorProfile(profile) && !options.allowDegraded) {
    throw new Error(
      `Portfolio "${profile.id}" is too low-rigor for serious verification. ` + 'Use --preset serious-local, --preset serious-end-to-end, --portfolio ultimate, or add --allow-degraded explicitly.',
    );
  }
  if ((options.preset === 'serious-local' || options.preset === 'serious-end-to-end') && options.allowDegraded) {
    throw new Error('--allow-degraded is not valid for serious presets');
  }
  if (options.skipPreflight && seriousVerification && !options.allowDegraded) {
    throw new Error('--skip-preflight is not valid for serious verification runs unless --allow-degraded is also set');
  }

  const target = await loadInvestigationTarget(options.target, options.targetId === 'default' ? undefined : options.targetId);
  const workerRoot = target.repoRoot ?? target.cwd ?? process.cwd();
  const additionalDirectories = [resolve(options.campaignDir), target.repoRoot, target.cwd].filter((value): value is string => Boolean(value) && value !== workerRoot);

  if (seriousVerification) {
    const doctor = await runDoctor({
      targetRef: options.target,
      targetId: options.targetId === 'default' ? undefined : options.targetId,
      liveTargetRef: options.liveTarget,
      liveTargetId: options.liveTargetId,
      hostedTargetRef: options.hostedTarget,
      preset: options.preset,
      linuxRuntime: options.linuxRuntime,
    });
    if (!doctor.ok) {
      const messages = doctor.checks.filter((check) => check.status === 'fail').map((check) => `${check.id}: ${check.message}${check.details ? ` (${check.details})` : ''}`);
      throw new Error(`Security Lab doctor failed for serious run:\n- ${messages.join('\n- ')}`);
    }
  }
  const plannerConfig = resolveRoleConfig(profile.planner, {
    providerOverride: (options.plannerProvider as ModelConfig['provider'] | '') || undefined,
    workerProviderOverride: options.workerPrimary,
    modelOverride: options.plannerModel || undefined,
    baseUrlOverride: options.plannerBaseUrl,
    maxTokensOverride: options.plannerMaxTokens,
    localInferenceOverride: options.plannerLocalInference ? true : undefined,
    cliLocalProviderOverride: options.plannerCliLocalProvider,
    cliProfileOverride: options.plannerCliProfile,
    requestTimeoutMs: options.requestTimeoutMs,
    workingDirectory: workerRoot,
    additionalDirectories,
  });
  const judgeConfig = resolveRoleConfig(profile.judge, {
    providerOverride: (options.judgeProvider as ModelConfig['provider'] | '') || undefined,
    modelOverride: options.judgeModel || undefined,
    baseUrlOverride: options.judgeBaseUrl,
    maxTokensOverride: options.judgeMaxTokens,
    localInferenceOverride: options.judgeLocalInference ? true : undefined,
    cliLocalProviderOverride: options.judgeCliLocalProvider,
    cliProfileOverride: options.judgeCliProfile,
    requestTimeoutMs: options.requestTimeoutMs,
    workingDirectory: workerRoot,
    additionalDirectories,
  });
  const allowUnavailable = canFallbackToUnavailable(options);

  console.log('Security Lab — Autonomous Investigation');
  console.log('========================================');
  console.log(`Target: ${options.target}`);
  console.log(`Mode: ${options.mode}`);
  console.log(`Run mode: ${options.runMode} (${describeRunMode(options.runMode)})`);
  console.log(`Portfolio: ${profile.id}`);
  if (options.preset) {
    console.log(`Preset: ${options.preset}`);
  }
  console.log(`Strict verification: ${strictVerification ? 'yes' : 'no'}`);
  console.log(`Allow degraded: ${options.allowDegraded ? 'yes' : 'no'}`);
  console.log(`Linux runtime policy: ${options.linuxRuntime}`);
  console.log(`Resume at: ${options.resumeAt}`);
  console.log(`Provider timeout: ${options.requestTimeoutMs ?? 180000}ms`);
  console.log(`Judge limit: ${options.judgeLimit ?? 5}`);
  console.log(`Test synthesis limit: ${options.testSynthesisLimit ?? 3}`);
  console.log(`Verification hypotheses: ${options.verificationHypothesisLimit ?? 15}`);
  console.log(`Live probes / hypothesis: ${options.liveProbesPerHypothesis ?? 3}`);
  console.log(`Planner: ${plannerConfig.provider}/${plannerConfig.model}`);
  console.log(`Judge: ${judgeConfig.provider}/${judgeConfig.model}`);
  if (profile.counterPlanner) {
    console.log(`Counter-planner: ${profile.counterPlanner.provider}/${profile.counterPlanner.model}`);
  }
  if (profile.localLivePlanner) {
    console.log(`Local-live planner: ${profile.localLivePlanner.provider}/${profile.localLivePlanner.model}`);
  }
  if (profile.localLiveCounterPlanner) {
    console.log(`Local-live counter: ${profile.localLiveCounterPlanner.provider}/${profile.localLiveCounterPlanner.model}`);
  }
  if (profile.judgePanel?.length) {
    console.log(`Judge panel: ${profile.judgePanel.map((member) => `${member.provider}/${member.model}`).join(', ')}`);
  }
  if (profile.synthesizer) {
    console.log(`Synthesizer: ${profile.synthesizer.provider}/${profile.synthesizer.model}`);
  }
  if (profile.reporter) {
    console.log(`Reporter: ${profile.reporter.provider}/${profile.reporter.model}`);
  }
  if (options.tribunalProvider && options.tribunalModel) {
    console.log(`Tribunal: ${options.tribunalProvider}/${options.tribunalModel}`);
  }
  console.log(`Max iterations: ${options.maxIterations}`);
  console.log(`Max cost: $${options.maxCost}`);
  if (options.resume) console.log(`Resuming: ${options.resume}`);
  if (options.confirmLive) console.log(`Live confirmation target: ${options.liveTarget ?? '(not set)'}`);
  console.log(`Worker root: ${workerRoot}`);
  console.log('');

  const plannerAdapter = createRequiredAdapter('planner', plannerConfig, allowUnavailable);

  const counterPlannerAdapter = createOptionalAdapter(
    'counter-planner',
    profile.counterPlanner
      ? withTransportContext(
          withRequestTimeout(
            {
              ...profile.counterPlanner,
              provider: options.workerCounter ?? profile.counterPlanner.provider,
            },
            options.requestTimeoutMs,
          ),
          workerRoot,
          additionalDirectories,
        )
      : undefined,
  );
  const localLivePlannerAdapter = createOptionalAdapter(
    'local-live-planner',
    profile.localLivePlanner
      ? withTransportContext(
          withRequestTimeout(
            {
              ...profile.localLivePlanner,
              provider: options.workerCounter ?? profile.localLivePlanner.provider,
            },
            options.requestTimeoutMs,
          ),
          workerRoot,
          additionalDirectories,
        )
      : undefined,
  );
  const localLiveCounterPlannerAdapter = createOptionalAdapter(
    'local-live-counter',
    profile.localLiveCounterPlanner
      ? withTransportContext(
          withRequestTimeout(
            {
              ...profile.localLiveCounterPlanner,
              provider: options.workerPrimary ?? profile.localLiveCounterPlanner.provider,
            },
            options.requestTimeoutMs,
          ),
          workerRoot,
          additionalDirectories,
        )
      : undefined,
  );
  const judgeAdapter = createRequiredAdapter('judge', judgeConfig, allowUnavailable);
  const tribunalAdapter =
    options.tribunalProvider && options.tribunalModel
      ? createOptionalAdapter('tribunal', {
          provider: options.tribunalProvider as 'anthropic' | 'openai' | 'gemini',
          model: options.tribunalModel,
          requestTimeoutMs: options.requestTimeoutMs,
          workingDirectory: workerRoot,
          additionalDirectories,
        })
      : undefined;
  const judgePanelMembers: PanelMember[] | undefined = profile.judgePanel
    ?.map((config, index) => {
      const adapter = createOptionalAdapter(`judge-panel:${index + 1}`, withTransportContext(withRequestTimeout(config, options.requestTimeoutMs), workerRoot, additionalDirectories));
      return adapter
        ? {
            label: `${index + 1}-${config.provider}-${config.model}`,
            adapter,
          }
        : null;
    })
    .filter((member): member is PanelMember => member !== null);
  const synthesizerAdapter = createOptionalAdapter(
    'synthesizer',
    profile.synthesizer ? withTransportContext(withRequestTimeout(profile.synthesizer, options.requestTimeoutMs), workerRoot, additionalDirectories) : undefined,
  );
  const reporterAdapter = createOptionalAdapter(
    'reporter',
    profile.reporter ? withTransportContext(withRequestTimeout(profile.reporter, options.requestTimeoutMs), workerRoot, additionalDirectories) : undefined,
  );

  const runner = new InvestigationRunner({
    targetRef: options.target,
    targetId: options.targetId === 'default' ? undefined : options.targetId,
    mode: options.mode,
    runMode: options.runMode,
    plannerAdapter,
    counterPlannerAdapter,
    localLivePlannerAdapter,
    localLiveCounterPlannerAdapter,
    judgeAdapter,
    tribunalAdapter,
    judgePanelMembers,
    synthesizerAdapter,
    reporterAdapter,
    portfolioProfile: profile,
    preset: options.preset === 'serious-local' || options.preset === 'serious-end-to-end' ? options.preset : undefined,
    resumeAt: options.resumeAt,
    maxIterations: options.maxIterations,
    maxCostUsd: options.maxCost,
    campaignDir: resolve(options.campaignDir),
    knowledgeBasePath: options.knowledgeBasePath ? resolve(options.knowledgeBasePath) : undefined,
    confirmLive: options.confirmLive,
    liveTargetRef: options.liveTarget,
    liveTargetId: options.liveTargetId,
    resumeCampaignId: options.resume,
    verifyVia: options.verifyVia,
    hostedTargetRef: options.hostedTarget,
    authorizeHosted: options.authorizeHosted,
    allowLocalMutations: options.allowLocalMutations,
    identityLadderId: options.identityLadder,
    allowHostedMutations: options.allowHostedMutations,
    baselinePath: options.baselinePath,
    quarantineDir: options.quarantineDir,
    monitoringStress: options.monitoringStress,
    pairedModes: options.pairedModes,
    contextBand: options.contextBand,
    strictVerification,
    allowDegraded: options.allowDegraded,
    linuxRuntime: options.linuxRuntime,
    testTimeoutMs: options.testTimeoutMs,
    requestTimeoutMs: options.requestTimeoutMs,
    judgeHypothesisLimit: options.judgeLimit,
    testSynthesisLimit: options.testSynthesisLimit,
    verificationHypothesisLimit: options.verificationHypothesisLimit,
    liveProbesPerHypothesis: options.liveProbesPerHypothesis,
    localLiveRounds: options.localLiveRounds,
    runtimeSignalsPerRound: options.runtimeSignalsPerRound,
    focusedClosureReads: options.focusedClosureReads,
    resumeAtStage: options.resumeAtStage,
    skipPreflight: options.skipPreflight,
    dryRunMutations: options.dryRunMutations,
    strictProbes: options.strictProbes,
    disableAdaptiveExploration: options.disableAdaptiveExploration,
    mythosEnabled: options.mythosEnabled,
    mythosTimeBudgetMs: options.mythosTimeMs,
    mythosProbeBudget: options.mythosProbes,
    // A typo in these env vars must not produce NaN: `age > NaN` is false
    // (locks never expire) and setInterval(fn, NaN) fires continuously.
    staleLockMs: finiteOrDefault(process.env['STALE_LOCK_MS'], 1_800_000),
    heartbeatIntervalMs: finiteOrDefault(process.env['HEARTBEAT_INTERVAL_MS'], 30_000),
  });

  const result = await runner.run();

  console.log('\n========================================');
  console.log(`Campaign: ${result.campaignId}`);
  console.log(`Status: ${result.status}`);
  if (result.executionStatus) {
    console.log(`Execution status: ${result.executionStatus}`);
  }
  console.log(`Iterations: ${result.iterations}`);
  console.log(`Findings: ${result.findings.length}`);
  console.log(`Run dir: ${result.runDir}`);
  if (result.liveConfirmation) {
    console.log(`Live confirmation: ${result.liveConfirmation.status} (${result.liveConfirmation.confirmedFindings} findings)`);
  }
  if (result.executiveAssessment) {
    console.log(`Executive verdict: ${result.executiveAssessment.overallVerdict}`);
    console.log(`Assessment source: ${result.executiveAssessment.source}`);
    console.log(`Assessment confidence: ${result.executiveAssessment.confidence.toFixed(2)}`);
  }
  if (result.coverageGaps?.length) {
    console.log('Coverage gaps:');
    for (const gap of result.coverageGaps) {
      console.log(`  [${gap.severity}] ${gap.lane}: ${gap.message}`);
    }
  }

  if (result.findings.length > 0) {
    console.log('\nFindings:');
    for (const f of result.findings) {
      console.log(`  [${f.severity}] ${f.description}`);
    }
  }

  if (result.findings.length > 0) {
    process.exitCode = 1;
  }
  // Serious run modes fail closed on non-complete execution status unless the
  // operator opts out via --exit-zero-on-incomplete or legacy --allow-degraded.
  const serious = options.runMode === 'serious-local' || options.runMode === 'serious-end-to-end';
  const incomplete = result.executionStatus === 'incomplete' || result.executionStatus === 'blocked';
  if (serious && incomplete && !options.exitZeroOnIncomplete && !options.allowDegraded) {
    process.exitCode = 1;
  } else if (strictVerification && result.executionStatus && result.executionStatus !== 'complete' && !options.allowDegraded && !options.exitZeroOnIncomplete) {
    // Legacy --strict-verification path (deprecated) — still fail-closed.
    process.exitCode = 1;
  }
}

/**
 * Parse a numeric environment override, falling back when it is missing or not
 * a finite number. `Number('abc')` is NaN, and NaN silently disables lock
 * expiry and turns timers into busy loops.
 */
function finiteOrDefault(raw: string | undefined, fallback: number): number {
  if (raw === undefined || raw.trim() === '') {
    return fallback;
  }
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
