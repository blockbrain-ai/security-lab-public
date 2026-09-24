/**
 * Verification Agent CLI — replaces the structured local-live framework.
 *
 * Instead of probe families, assertion classifiers, identity ladders, and
 * mutation journals (which produced 0 confirmed findings across 8 targets
 * at $4-8/run), this launches a verification session that reads the static
 * report FROM DISK and does what the operator has been doing manually:
 *
 * 1. Read the architectural-risks + suppressed-claims sections from the report file
 * 2. Dedup against prior advisories (gh api — repo slug derived from target metadata or git remote)
 * 3. Source-verify each candidate finding (read the actual code)
 * 4. Runtime-verify via Docker where it strengthens the finding
 * 5. Narrow finding scope (route-by-route boundary check)
 * 6. Draft PVR files for filable findings
 * 7. Write SECURITY-REPORT.md with full audit trail
 *
 * The prompt is brief-mode: it points the agent at file paths on disk rather
 * than embedding the report inline. This keeps the initial prompt small and
 * leverages the agent's native file-reading capability.
 *
 * Usage:
 *   npm run verify -- --report <path-to-report.md> --target <target.yaml>
 *   npm run verify -- --campaign <campaign-id> --target <target.yaml>
 */

import { resolve } from 'node:path';
import { existsSync, readFileSync } from 'node:fs';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { execSync } from 'node:child_process';
import { createAdapter } from '../providers/adapter-factory.js';
import { assertOptionalSafeIdentifier } from './identifiers.js';
import { HOST_EXECUTION_ENV_VAR } from '../providers/execution-policy.js';
import { deriveRepoSlug } from './repo-slug.js';
import { loadInvestigationTarget } from './target-profile.js';
import { runSourceVerification } from './source-verify-runner.js';
import { runBoundedRuntimeVerification, ensureDockerRunning } from './runtime-verify-runner.js';
import type { SourceVerificationArtifact } from './source-verify-schemas.js';
import type { RuntimeVerificationArtifact } from './runtime-verify-schemas.js';
import type { ModelConfig } from '../providers/contracts.js';
import { createManifest, finalizeManifest, writeManifest, type LaneConfig } from './verification-manifest.js';
import { RunMonitor } from './run-monitor.js';
import {
  listVerificationProfiles,
  listLocalModelDescriptors,
  getVerificationProfile,
  resolveVerificationProfile,
  type ResolvedVerificationProfile,
  type ProfileOverrides,
} from './verification-profiles.js';
import { runPreflight, formatPreflightReport } from './verification-preflight.js';
import { computeScorecard, writeScorecard, readScorecard } from './parity-scorecard.js';
import { BenchmarkRegistry } from './benchmark-registry.js';
import { generateRecommendations, writeRecommendations } from './recommendation-engine.js';
import {
  createDegradationState,
  type DegradationThresholds,
  DEFAULT_THRESHOLDS,
} from './degradation-ladder.js';

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

function getArg(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : undefined;
}

type VerificationMode = 'source' | 'runtime' | 'full';
type ProviderName = 'claude_code' | 'codex_cli' | 'pi_cli' | 'bounded_local';

function printUsage(): void {
  console.log(`
Security Lab — Verification Agent
==================================

Launches verification sessions against a static report. Supports source-only
(local/zero-cost), runtime-only (hosted), or full (source then runtime).

Usage:
  npm run verify -- --report <report.md> --target <target.yaml> [options]
  npm run verify -- --campaign <campaign-id> --target <target.yaml> [options]

Options:
  --report <path>             Path to the static report (report.md)
  --campaign <id>             Campaign ID (resolves to data/campaigns/runs/<id>/report.md)
  --target <path>             Path to the target YAML (for repoRoot + hints)
  --output <dir>              Output directory (default: <repoRoot>/pvr-submissions/)
  --repo-slug <o/r>           GitHub owner/repo for dedup (auto-derived if omitted)

Verification mode:
  --verification-mode <mode>  source | runtime | full (default: runtime)

Source provider (used in source and full modes):
  --source-provider <name>    bounded_local | pi_cli | claude_code | codex_cli (default: bounded_local)
  --source-model <model>      Model for source verification (default: qwen3.6-27b)

Runtime provider (used in runtime and full modes):
  --runtime-provider <name>   bounded_local | claude_code | codex_cli (default: bounded_local)
  --runtime-model <model>     Model for runtime verification
                              (default: qwen3.6-27b for bounded_local, claude-opus-4-6 for claude_code,
                               gpt-5.5 for codex_cli)

Backward-compatible aliases (single-lane modes only):
  --provider <name>           Alias for source or runtime provider (fails in full mode)
  --model <model>             Alias for source or runtime model (fails in full mode)

Verification profiles:
  --verification-profile <id> Use a built-in verification profile
  --list-verification-profiles List available verification profiles
  --list-local-models         List first-wave local model descriptors
  --preflight-only            Run preflight checks and exit

Stage-specific overrides (win over profile values):
  --source-base-url <url>     Base URL for source verification
  --runtime-base-url <url>    Base URL for runtime verification
  --source-critic-provider <n> Provider for defense critic
  --source-critic-model <m>   Model for defense critic
  --source-critic-base-url <u> Base URL for defense critic
  --runtime-setup-provider <n> Provider for runtime Docker setup
  --runtime-setup-model <m>   Model for runtime Docker setup
  --runtime-setup-base-url <u> Base URL for runtime Docker setup
  --runtime-probe-provider <n> Provider for runtime candidate probing
  --runtime-probe-model <m>   Model for runtime candidate probing
  --runtime-probe-base-url <u> Base URL for runtime candidate probing

Benchmarking:
  --benchmark-label <label>   Record this run as a candidate benchmark
  --promote-benchmark-baseline Promote this run to baseline after completion
  --reference-scorecard <path> Path to a Frontier reference scorecard for comparison

Source smoke controls:
  --candidate-limit <n>       Limit source verification to first N candidates
  --skip-audit                Skip the generic bug-class audit pass

Recommendations:
  --skip-recommendations      Skip recommendation generation

Degradation:
  --degradation-thresholds <json>  Override default degradation thresholds
  --disable-degradation            Disable the safe-mode degradation ladder

Serialized hybrid:
  --source-artifact <path>    Path to a source-verification.json artifact for runtime-only mode.
                              Allows serialized hybrid runs: source with one model, runtime with another.

Other:
  --dry-run                   Print the prompt(s) without launching sessions
  --help                      Show this help
`);
}

// ---------------------------------------------------------------------------
// Repository slug resolution
// ---------------------------------------------------------------------------

/**
 * Derive the GitHub owner/repo slug from the target's repoRoot by reading
 * the git remote origin URL. Falls back to a placeholder if resolution fails
 * (the agent can still resolve it at runtime via `gh repo view`).
 */
// ---------------------------------------------------------------------------
// Brief-mode verification prompt (file pointers, not inline content)
// ---------------------------------------------------------------------------

function buildVerificationPrompt(
  reportPath: string,
  targetId: string,
  repoRoot: string,
  outputDir: string,
  repoSlug: string,
): string {
  return `You are a security verification agent. Turn the static report into filable security advisories.

## Inputs — READ THESE FILES FROM DISK

1. **Static report**: \`${reportPath}\`
   Read this file first. It contains the candidate findings and suppressed claims.
2. **Target repository**: \`${repoRoot}\`
3. **Target ID**: ${targetId}
4. **GitHub repo**: ${repoSlug}
5. **Output directory**: \`${outputDir}\`

Do NOT ask for the report contents. Read the file at the path above.

## Workflow — ORDER MATTERS

### 1. Source-verify every candidate

- Resolve scoping gaps by reading the omitted files.
- For configuration-sensitive claims, read defaults, env docs, and nearby tests to decide: default issue, intentional hardening note, or real exploitable condition.
- Re-read each claimed route individually before asserting scope. Narrow affected routes if handler-local auth or guards exist.

### 2. Dedup only after you understand the code path

\`\`\`bash
# 1. GitHub Security Advisories (repo-level)
gh api "repos/${repoSlug}/security-advisories?per_page=100" \\
  --jq '.[] | [.ghsa_id, .severity, .published_at[:10], .summary] | @tsv'

# 2. NVD / CVE database
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=PACKAGE_NAME&resultsPerPage=50" | \\
  python3 -c "import sys,json; d=json.load(sys.stdin); [print(f\\"{v['cve']['id']}: {v['cve']['descriptions'][0]['value']}\\") for v in d.get('vulnerabilities',[])]"

# 3. GitHub global advisory search
gh api "/advisories?ecosystem=pip&affects=${repoSlug.split('/')[1]}&per_page=50" \\
  --jq '.[] | [.ghsa_id, .cve_id, .severity, .summary] | @tsv' 2>/dev/null || true
\`\`\`

\`\`\`bash
# For each GHSA — fetch the full description, not just the summary
gh api "/advisories/GHSA-xxxx-xxxx-xxxx" --jq '{ghsa: .ghsa_id, cve: .cve_id, severity: .severity, summary: .summary, description: .description, vulnerabilities: [.vulnerabilities[] | {package: .package.name, vulnerable_range: .vulnerable_version_range, patched: .patched_versions}]}'

# For each NVD CVE — fetch the full description + references
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-XXXX-XXXXX" | \\
  python3 -c "import sys,json; d=json.load(sys.stdin); v=d['vulnerabilities'][0]['cve']; print(f\\"ID: {v['id']}\\"); print(f\\"Description: {v['descriptions'][0]['value']}\\"); [print(f\\"Ref: {r['url']}\\") for r in v.get('references',[])]"
\`\`\`

- Read the FULL description for every candidate advisory before deciding overlap.
- **Duplicate** = same root cause, vulnerable function, or bypass technique.
- **Distinct** = different code path, precondition, surface, or a fix-bypass.
- Record dedup reasoning in SECURITY-REPORT.md for every relevant advisory.

### 3. Runtime-verify every remaining finding

For every candidate:
1. Ensure Docker is running (\`docker info\`; if needed, \`open -a Docker && until docker info >/dev/null 2>&1; do sleep 2; done\`).
2. Build the target from the cloned HEAD and install what it needs.
3. Start the app in a config that exposes the surface.
4. Run the minimal reproducer and capture commands + output.
5. If it cannot be reproduced locally, document the exact blocker and required environment under **Unverified — Requires Further Investigation**.

Anything not reproduced at runtime is not filable.

### 4. Keep going past the first pass

- Bring up missing local infrastructure yourself (Compose, DBs, queues, env vars) when it is locally feasible.
- Repeat until every lead is confirmed, ruled out, or genuinely blocked by unavailable infrastructure.
- Combine confirmed findings into chains when the combination raises severity.
- Investigate meaningful runtime surfaces that appear while the app is running.

## Output files

1. \`${outputDir}/pvr-NN-<slug>.md\`
   Include: title, severity/CVSS, CWE, affected products, description with code snippets, runtime reproducer, impact, suggested fix, regression test, credit.
2. \`${resolve(outputDir, '..', 'SECURITY-REPORT.md')}\`
   Include: filed PVRs, dedup table, hardening notes, suppressed claims, operational notes, and every unverified lead with its blocker.

Credit line for all files: Security Lab — Chris Walker <admin@blockbrain.au>

## Filing bar

Only file if ALL are true:
- HIGH or CRITICAL severity
- Distinct from prior advisories
- Runtime-reproduced with captured evidence
- Not documented-as-intentional behavior
- Scope is narrowed precisely

Everything else belongs in SECURITY-REPORT.md, not a PVR.

## Begin

Start by reading \`${reportPath}\`, then work through each finding methodically. After the first pass, revisit anything unverified and keep digging.
`;
}

// ---------------------------------------------------------------------------
// Source-enriched runtime prompt
// ---------------------------------------------------------------------------

function buildEnrichedRuntimePrompt(
  basePrompt: string,
  artifact: SourceVerificationArtifact,
): string {
  const supported = [...artifact.candidates, ...(artifact.auditFindings ?? [])].filter(r => r.status === 'supported');
  const needsRuntime = [...artifact.candidates, ...(artifact.auditFindings ?? [])].filter(r => r.status === 'needs_runtime');
  const weakened = [...artifact.candidates, ...(artifact.auditFindings ?? [])].filter(r => r.status === 'weakened');
  const refuted = artifact.candidates.filter(r => r.status === 'refuted');

  const sections: string[] = [];

  sections.push(`## Source Verification Results\n`);
  sections.push(`A prior source-verification pass has already analyzed the codebase. Use these results to prioritize your work.\n`);

  if (refuted.length > 0) {
    sections.push(`### Refuted (skip these — source evidence disproves them)`);
    for (const r of refuted) {
      sections.push(`- **${r.candidateId}**: ${r.rootCause}`);
    }
    sections.push('');
  }

  if (supported.length > 0) {
    sections.push(`### Source-Supported (highest priority — verify at runtime first)`);
    const sorted = [...supported].sort((a, b) => b.confidence - a.confidence);
    for (const r of sorted) {
      sections.push(`- **${r.candidateId}** (confidence: ${r.confidence})`);
      sections.push(`  Root cause: ${r.rootCause}`);
      for (const ref of r.sourceRefs.slice(0, 3)) {
        sections.push(`  Source: \`${ref.file}${ref.line ? `:${ref.line}` : ''}\` — ${ref.snippet.slice(0, 120)}`);
      }
      if (r.exploitPath) sections.push(`  Exploit path: ${r.exploitPath}`);
      if (r.preconditions.length > 0) sections.push(`  Preconditions: ${r.preconditions.join('; ')}`);
    }
    sections.push('');
  }

  if (needsRuntime.length > 0) {
    sections.push(`### Needs Runtime (source was inconclusive — investigate these)`);
    for (const r of needsRuntime) {
      sections.push(`- **${r.candidateId}**: ${r.claim}`);
      if (r.runtimePlan) sections.push(`  Suggested test: ${r.runtimePlan}`);
    }
    sections.push('');
  }

  if (weakened.length > 0) {
    sections.push(`### Weakened (lower priority — source evidence is partial)`);
    for (const r of weakened) {
      sections.push(`- **${r.candidateId}**: ${r.rootCause}`);
    }
    sections.push('');
  }

  const enrichment = sections.join('\n');

  // Insert the source verification context before the "## Begin" section
  const beginIdx = basePrompt.indexOf('## Begin');
  if (beginIdx >= 0) {
    return basePrompt.slice(0, beginIdx) + enrichment + '\n' + basePrompt.slice(beginIdx);
  }
  return basePrompt + '\n\n' + enrichment;
}

// ---------------------------------------------------------------------------
// Flag resolution helpers
// ---------------------------------------------------------------------------

function resolveVerificationMode(args: string[]): VerificationMode {
  const raw = getArg(args, '--verification-mode');
  if (!raw) return 'runtime';
  if (raw === 'source' || raw === 'runtime' || raw === 'full') return raw;
  console.error(`Error: invalid --verification-mode "${raw}". Must be source, runtime, or full.`);
  process.exit(1);
}

function resolveAllLanes(
  args: string[],
  mode: VerificationMode,
): ResolvedVerificationProfile {
  const legacyProvider = getArg(args, '--provider') as ProviderName | undefined;
  const legacyModel = getArg(args, '--model');

  if (mode === 'full' && (legacyProvider || legacyModel)) {
    console.error(
      'Error: --provider and --model are ambiguous in full mode. ' +
      'Use --source-provider/--source-model and --runtime-provider/--runtime-model instead.',
    );
    process.exit(1);
  }

  // Load profile if specified
  const profileId = getArg(args, '--verification-profile');
  const profile = profileId ? getVerificationProfile(profileId) : null;
  if (profileId && !profile) {
    console.error(`Error: unknown verification profile "${profileId}". Use --list-verification-profiles to see available profiles.`);
    process.exit(1);
  }

  // Resolve runtime model default based on provider
  const runtimeProviderRaw = getArg(args, '--runtime-provider') ?? (mode === 'runtime' ? legacyProvider : undefined);
  const effectiveRuntimeProvider = runtimeProviderRaw ?? profile?.runtime.provider ?? 'bounded_local';
  const defaultRuntimeModel = effectiveRuntimeProvider === 'codex_cli' ? 'gpt-5.5'
    : effectiveRuntimeProvider === 'bounded_local' ? 'qwen3.6-27b'
    : 'claude-opus-4-6';

  const overrides: ProfileOverrides = {
    sourceProvider: getArg(args, '--source-provider') ?? (mode === 'source' ? legacyProvider : undefined),
    sourceModel: getArg(args, '--source-model') ?? (mode === 'source' ? legacyModel : undefined),
    sourceBaseUrl: getArg(args, '--source-base-url'),
    sourceCriticProvider: getArg(args, '--source-critic-provider'),
    sourceCriticModel: getArg(args, '--source-critic-model'),
    sourceCriticBaseUrl: getArg(args, '--source-critic-base-url'),
    runtimeProvider: runtimeProviderRaw,
    runtimeModel: getArg(args, '--runtime-model') ?? (mode === 'runtime' ? legacyModel : undefined) ?? (runtimeProviderRaw ? defaultRuntimeModel : undefined),
    runtimeBaseUrl: getArg(args, '--runtime-base-url'),
    runtimeSetupProvider: getArg(args, '--runtime-setup-provider'),
    runtimeSetupModel: getArg(args, '--runtime-setup-model'),
    runtimeSetupBaseUrl: getArg(args, '--runtime-setup-base-url'),
    runtimeProbeProvider: getArg(args, '--runtime-probe-provider'),
    runtimeProbeModel: getArg(args, '--runtime-probe-model'),
    runtimeProbeBaseUrl: getArg(args, '--runtime-probe-base-url'),
  };

  // Strip undefined values so they don't override profile defaults
  for (const key of Object.keys(overrides) as Array<keyof ProfileOverrides>) {
    if (overrides[key] === undefined) delete overrides[key];
  }

  return resolveVerificationProfile(profile, overrides);
}

function validateResolvedLanes(
  resolved: ResolvedVerificationProfile,
  mode: VerificationMode,
): void {
  if (mode === 'runtime' || mode === 'full') {
    const runtimeProvider = resolved.runtime.provider;
    const setupProvider = resolved.runtimeSetup.provider;
    const probeProvider = resolved.runtimeProbe.provider;

    if (setupProvider !== runtimeProvider || probeProvider !== runtimeProvider) {
      console.error(
        'Error: runtime setup/probe provider splits are not implemented. ' +
        'Phase 2 only supports setup/probe model/baseUrl overrides within the same runtime provider.',
      );
      process.exit(1);
    }

    if (
      runtimeProvider !== 'bounded_local' &&
      (
        resolved.runtimeSetup.model !== resolved.runtime.model ||
        resolved.runtimeSetup.baseUrl !== resolved.runtime.baseUrl ||
        resolved.runtimeProbe.model !== resolved.runtime.model ||
        resolved.runtimeProbe.baseUrl !== resolved.runtime.baseUrl
      )
    ) {
      console.error(
        'Error: runtime setup/probe model splits are currently only supported for bounded_local runtime verification.',
      );
      process.exit(1);
    }
  }
}

// ---------------------------------------------------------------------------
// Runtime verification (existing behavior, extracted)
// ---------------------------------------------------------------------------

async function runRuntimeVerification(opts: {
  reportPath: string;
  campaignId?: string;
  target: { id: string; repoRoot?: string };
  repoRoot: string;
  outputDir: string;
  repoSlug: string;
  provider: ProviderName;
  model: string;
  baseUrl?: string;
  dryRun: boolean;
  sourceArtifactPath?: string;
  candidateLimit?: number;
  monitor?: RunMonitor;
  setupModel?: string;
  setupBaseUrl?: string;
  probeModel?: string;
  probeBaseUrl?: string;
  degradationState?: import('./degradation-ladder.js').DegradationState;
  degradationThresholds?: import('./degradation-ladder.js').DegradationThresholds;
}): Promise<{ costUsd: number }> {
  if (!opts.dryRun) {
    await ensureDockerRunning();
  }

  if (opts.provider === 'bounded_local') {
    const result = await runBoundedRuntimeVerification({
      reportPath: opts.reportPath,
      campaignId: opts.campaignId,
      targetId: opts.target.id,
      repoRoot: opts.repoRoot,
      outputDir: opts.outputDir,
      model: opts.model,
      baseUrl: opts.baseUrl,
      dryRun: opts.dryRun,
      sourceArtifactPath: opts.sourceArtifactPath,
      candidateLimit: opts.candidateLimit,
      monitor: opts.monitor,
      setupModel: opts.setupModel,
      setupBaseUrl: opts.setupBaseUrl,
      probeModel: opts.probeModel,
      probeBaseUrl: opts.probeBaseUrl,
      degradationState: opts.degradationState,
      degradationThresholds: opts.degradationThresholds,
    });
    return { costUsd: result.costUsd };
  }

  let prompt = buildVerificationPrompt(
    resolve(opts.reportPath),
    opts.target.id,
    opts.repoRoot,
    opts.outputDir,
    opts.repoSlug,
  );

  // Enrich with source-verification results if available
  if (opts.sourceArtifactPath) {
    try {
      const raw = await readFile(opts.sourceArtifactPath, 'utf8');
      const artifact = JSON.parse(raw) as SourceVerificationArtifact;
      const hasCandidates = artifact.candidates.length > 0 || (artifact.auditFindings?.length ?? 0) > 0;
      if (hasCandidates) {
        prompt = buildEnrichedRuntimePrompt(prompt, artifact);
        console.log(`Enriched runtime prompt with ${artifact.candidates.length} source-verified candidates`);
      }
    } catch (err) {
      console.log(`Warning: could not load source artifact at ${opts.sourceArtifactPath}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  if (opts.dryRun) {
    console.log('=== DRY RUN — Runtime verification prompt ===\n');
    console.log(prompt);
    console.log(`\n=== Prompt length: ${prompt.length} chars ===`);
    console.log(`=== Repo slug: ${opts.repoSlug} ===`);
    if (opts.sourceArtifactPath) {
      console.log(`=== Source artifact: ${opts.sourceArtifactPath} ===`);
    }
    return { costUsd: 0 };
  }

  const config: ModelConfig = {
    provider: opts.provider,
    model: opts.model,
    effort: 'high',
  };

  const adapter = createAdapter(config);

  console.log('Launching runtime verification session...\n');

  const response = await adapter.invoke({
    systemPrompt: 'You are a security verification agent. Follow the instructions in the user message precisely. You have full access to the filesystem, Docker, and gh CLI. Read the static report from the file path given — do not ask for it to be pasted. Work methodically through each finding. EVERY finding must be runtime-verified — build the project, run it, and prove the vulnerability with a live reproducer. Do not file anything you have not reproduced at runtime. After your first verification pass, DO NOT STOP — review what you could not verify, figure out what runtime infrastructure you need (Docker Compose, databases, full app stack), set it up, and verify those leads too. Keep going until every lead is either confirmed, ruled out, or genuinely requires infrastructure you cannot provision locally.',
    prompt,
    requestTimeoutMs: 2700_000, // 45 minutes
    workingDirectory: opts.repoRoot,
    effort: 'high',
  });

  console.log(`\nRuntime verification cost: $${response.usage.costUsd.toFixed(4)}`);

  const sessionLogPath = resolve(opts.outputDir, '..', '.verification-session.log');
  await writeFile(sessionLogPath, response.content, 'utf8');
  console.log(`Session log: ${sessionLogPath}`);

  return { costUsd: response.usage.costUsd };
}

// ---------------------------------------------------------------------------
// Source verification stub (Phase 2 will implement the full runner)
// ---------------------------------------------------------------------------

async function runSourceVerificationPass(opts: {
  reportPath: string;
  campaignId?: string;
  target: { id: string; repoRoot?: string };
  repoRoot: string;
  outputDir: string;
  provider: ProviderName;
  model: string;
  baseUrl?: string;
  dryRun: boolean;
  candidateLimit?: number;
  skipAudit: boolean;
  monitor?: RunMonitor;
  criticProvider?: string;
  criticModel?: string;
  criticBaseUrl?: string;
  degradationState?: import('./degradation-ladder.js').DegradationState;
  degradationThresholds?: import('./degradation-ladder.js').DegradationThresholds;
}): Promise<{ costUsd: number; artifactPath?: string }> {
  const result = await runSourceVerification({
    reportPath: opts.reportPath,
    campaignId: opts.campaignId,
    targetId: opts.target.id,
    repoRoot: opts.repoRoot,
    outputDir: opts.outputDir,
    provider: opts.provider,
    model: opts.model,
    baseUrl: opts.baseUrl,
    dryRun: opts.dryRun,
    candidateLimit: opts.candidateLimit,
    skipAudit: opts.skipAudit,
    monitor: opts.monitor,
    criticProvider: opts.criticProvider,
    criticModel: opts.criticModel,
    criticBaseUrl: opts.criticBaseUrl,
    degradationState: opts.degradationState,
    degradationThresholds: opts.degradationThresholds,
  });
  return { costUsd: result.costUsd, artifactPath: result.artifactPath || undefined };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

// Last-resort diagnostic. Individual evidence writes are awaited or caught at
// their call sites; this only ensures a rejection that escapes still becomes
// visible and fails the run instead of disappearing.
process.on('unhandledRejection', (reason) => {
  console.error(
    '[security-lab] unhandled rejection:',
    reason instanceof Error ? (reason.stack ?? reason.message) : reason,
  );
  process.exitCode = 1;
});

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.length === 0) {
    printUsage();
    process.exit(0);
  }

  // Early exits: listing commands
  if (args.includes('--list-verification-profiles')) {
    const profiles = listVerificationProfiles();
    console.log('Available verification profiles:\n');
    for (const p of profiles) {
      console.log(`  ${p.id}`);
      console.log(`    ${p.description}`);
      console.log(`    source: ${p.source.provider}/${p.source.model}${p.sourceCritic ? `  critic: ${p.sourceCritic.provider}/${p.sourceCritic.model}` : ''}`);
      console.log(`    runtime: ${p.runtime.provider}/${p.runtime.model}`);
      console.log(`    tags: ${p.tags.join(', ')}`);
      console.log();
    }
    process.exit(0);
  }

  if (args.includes('--list-local-models')) {
    const models = listLocalModelDescriptors();
    console.log('First-wave local model catalog:\n');
    for (const m of models) {
      console.log(`  ${m.id} — ${m.provider}/${m.model}`);
      console.log(`    baseUrl: ${m.baseUrl}`);
      console.log(`    json: ${m.capabilities.structuredJson}  tools: ${m.capabilities.readOnlyTools}  runtime: ${m.capabilities.runtimeTools}`);
      console.log(`    stages: ${m.recommendedStages.join(', ')}`);
      if (m.notes) console.log(`    notes: ${m.notes}`);
      console.log();
    }
    process.exit(0);
  }

  // Resolve report path
  let reportPath = getArg(args, '--report');
  // The campaign id becomes a path segment under data/campaigns/runs.
  const campaignId = assertOptionalSafeIdentifier(getArg(args, '--campaign'), '--campaign id');
  const targetPath = getArg(args, '--target');
  const dryRun = args.includes('--dry-run');
  if (args.includes('--allow-host-execution')) {
    process.env[HOST_EXECUTION_ENV_VAR] = '1';
  }
  const explicitSlug = getArg(args, '--repo-slug');
  const skipAudit = args.includes('--skip-audit');
  const candidateLimit = getArg(args, '--candidate-limit') ? parseInt(getArg(args, '--candidate-limit')!, 10) : undefined;
  const benchmarkLabel = getArg(args, '--benchmark-label');
  const promoteBaseline = args.includes('--promote-benchmark-baseline');
  const referenceScorePath = getArg(args, '--reference-scorecard');
  const explicitSourceArtifact = getArg(args, '--source-artifact');
  const skipRecommendations = args.includes('--skip-recommendations');
  const disableDegradation = args.includes('--disable-degradation');
  const degradationThresholdsRaw = getArg(args, '--degradation-thresholds');
  let degradationThresholds: DegradationThresholds = DEFAULT_THRESHOLDS;
  if (degradationThresholdsRaw) {
    try {
      degradationThresholds = { ...DEFAULT_THRESHOLDS, ...JSON.parse(degradationThresholdsRaw) };
    } catch {
      console.error('Error: --degradation-thresholds must be valid JSON.');
      process.exit(1);
    }
  }

  const mode = resolveVerificationMode(args);
  const resolved = resolveAllLanes(args, mode);
  validateResolvedLanes(resolved, mode);

  if (promoteBaseline && !benchmarkLabel) {
    console.error('Error: --promote-benchmark-baseline requires --benchmark-label <label>.');
    process.exit(1);
  }

  // Preflight-only exit
  if (args.includes('--preflight-only')) {
    console.log('Running preflight checks...\n');
    const report = await runPreflight(resolved);
    console.log(formatPreflightReport(report));
    process.exit(report.passed ? 0 : 1);
  }

  if (!reportPath && campaignId) {
    reportPath = resolve('data', 'campaigns', 'runs', campaignId, 'report.md');
  }

  if (!reportPath) {
    console.error('Error: --report <path> or --campaign <id> is required.');
    process.exit(1);
  }

  if (!targetPath) {
    console.error('Error: --target <path> is required.');
    process.exit(1);
  }

  if (!existsSync(reportPath)) {
    console.error(`Error: report not found at ${reportPath}`);
    process.exit(1);
  }

  // Load target for repoRoot
  const target = await loadInvestigationTarget(resolve(targetPath));
  const repoRoot = target.repoRoot ?? process.cwd();

  // Derive the GitHub owner/repo slug for dedup commands
  const repoSlug = deriveRepoSlug(repoRoot, explicitSlug);

  // Resolve output directory
  const outputDir = getArg(args, '--output') ?? resolve(repoRoot, 'pvr-submissions');
  await mkdir(outputDir, { recursive: true });

  // Build lane configs for manifest from resolved profile
  const lanes: Record<string, LaneConfig> = {};
  if (mode === 'source' || mode === 'full') {
    lanes.source = { provider: resolved.source.provider, model: resolved.source.model, baseUrl: resolved.source.baseUrl };
    lanes.sourceCritic = { provider: resolved.sourceCritic.provider, model: resolved.sourceCritic.model, baseUrl: resolved.sourceCritic.baseUrl };
  }
  if (mode === 'runtime' || mode === 'full') {
    lanes.runtime = { provider: resolved.runtime.provider, model: resolved.runtime.model, baseUrl: resolved.runtime.baseUrl };
    lanes.runtimeSetup = { provider: resolved.runtimeSetup.provider, model: resolved.runtimeSetup.model, baseUrl: resolved.runtimeSetup.baseUrl };
    lanes.runtimeProbe = { provider: resolved.runtimeProbe.provider, model: resolved.runtimeProbe.model, baseUrl: resolved.runtimeProbe.baseUrl };
  }

  // Create manifest and monitor
  const manifest = createManifest({
    campaignId: campaignId ?? undefined,
    targetId: target.id,
    mode,
    repoRoot,
    lanes,
    cliOptions: {
      reportPath,
      candidateLimit,
      skipAudit,
      dryRun,
    },
    profileId: resolved.id,
    candidateLimit,
    skipAudit,
  });

  const monitor = new RunMonitor(outputDir);
  if (!dryRun) {
    await monitor.prepare();
    await writeManifest(outputDir, manifest);
    await monitor.emitRunStart();
  }

  // Print header
  console.log('Security Lab — Verification Agent');
  console.log('=================================');
  console.log(`Run ID:    ${manifest.runId}`);
  console.log(`Mode:      ${mode}`);
  console.log(`Report:    ${reportPath}`);
  console.log(`Target:    ${target.id}`);
  console.log(`Repo:      ${repoRoot}`);
  console.log(`Slug:      ${repoSlug}`);
  console.log(`Output:    ${outputDir}`);
  if (resolved.id) {
    console.log(`Profile:   ${resolved.id}`);
  }
  if (mode === 'source' || mode === 'full') {
    console.log(`Source:    ${resolved.source.provider} / ${resolved.source.model}`);
    if (
      resolved.sourceCritic.provider !== resolved.source.provider ||
      resolved.sourceCritic.model !== resolved.source.model ||
      resolved.sourceCritic.baseUrl !== resolved.source.baseUrl
    ) {
      console.log(`Critic:    ${resolved.sourceCritic.provider} / ${resolved.sourceCritic.model}`);
    }
  }
  if (mode === 'runtime' || mode === 'full') {
    console.log(`Runtime:   ${resolved.runtime.provider} / ${resolved.runtime.model}`);
    if (
      resolved.runtimeSetup.provider !== resolved.runtime.provider ||
      resolved.runtimeSetup.model !== resolved.runtime.model ||
      resolved.runtimeSetup.baseUrl !== resolved.runtime.baseUrl
    ) {
      console.log(`Setup:     ${resolved.runtimeSetup.provider} / ${resolved.runtimeSetup.model}`);
    }
    if (
      resolved.runtimeProbe.provider !== resolved.runtime.provider ||
      resolved.runtimeProbe.model !== resolved.runtime.model ||
      resolved.runtimeProbe.baseUrl !== resolved.runtime.baseUrl
    ) {
      console.log(`Probe:     ${resolved.runtimeProbe.provider} / ${resolved.runtimeProbe.model}`);
    }
  }
  console.log(`Config:    ${manifest.configHash}`);
  console.log();

  let totalCost = 0;
  let sourceArtifactPath: string | undefined;
  let exitStatus: 'success' | 'failure' | 'partial' = 'success';
  let mainError: unknown;
  const degradationState = disableDegradation ? undefined : createDegradationState();

  try {
    // Source verification pass
    if (mode === 'source' || mode === 'full') {
      const sourceStart = Date.now();
      if (!dryRun) await monitor.emitStageEnter('source');
      try {
        const sourceResult = await runSourceVerificationPass({
          reportPath: resolve(reportPath),
          campaignId,
          target,
          repoRoot,
          outputDir,
          provider: resolved.source.provider as ProviderName,
          model: resolved.source.model,
          baseUrl: resolved.source.baseUrl,
          dryRun,
          candidateLimit,
          skipAudit,
          monitor: dryRun ? undefined : monitor,
          criticProvider: resolved.sourceCritic.provider,
          criticModel: resolved.sourceCritic.model,
          criticBaseUrl: resolved.sourceCritic.baseUrl,
          degradationState: dryRun ? undefined : degradationState,
          degradationThresholds,
        });
        totalCost += sourceResult.costUsd;
        sourceArtifactPath = sourceResult.artifactPath;
      } finally {
        if (!dryRun) await monitor.emitStageExit('source', Date.now() - sourceStart);
      }
    }

    // Load explicit source artifact for serialized hybrid runs
    if (explicitSourceArtifact && !sourceArtifactPath) {
      const resolvedPath = resolve(explicitSourceArtifact);
      if (!existsSync(resolvedPath)) {
        throw new Error(`--source-artifact path does not exist: ${resolvedPath}`);
      }
      sourceArtifactPath = resolvedPath;
      console.log(`Using external source artifact: ${resolvedPath}`);
    }

    // A verification run that processed no candidates must not report success:
    // downstream scoring defaults missing rates to 1, which would otherwise be
    // indistinguishable from a clean run.
    if (!dryRun && sourceArtifactPath !== undefined) {
      const candidateCount = readCandidateCount(sourceArtifactPath);
      if (candidateCount === 0) {
        exitStatus = 'failure';
        console.error(
          'Source verification processed 0 candidates — recording this run as failed (nothing was verified).',
        );
      }
    }

    // Runtime verification pass
    if (mode === 'runtime' || mode === 'full') {
      const runtimeStart = Date.now();
      if (!dryRun) await monitor.emitStageEnter('runtime');
      try {
        const runtimeResult = await runRuntimeVerification({
          reportPath: resolve(reportPath),
          campaignId,
          target,
          repoRoot,
          outputDir,
          repoSlug,
          provider: resolved.runtime.provider as ProviderName,
          model: resolved.runtime.model,
          baseUrl: resolved.runtime.baseUrl,
          dryRun,
          sourceArtifactPath,
          candidateLimit,
          monitor: dryRun ? undefined : monitor,
          setupModel: resolved.runtimeSetup.model,
          setupBaseUrl: resolved.runtimeSetup.baseUrl,
          probeModel: resolved.runtimeProbe.model,
          probeBaseUrl: resolved.runtimeProbe.baseUrl,
          degradationState: dryRun ? undefined : degradationState,
          degradationThresholds,
        });
        totalCost += runtimeResult.costUsd;
      } finally {
        if (!dryRun) await monitor.emitStageExit('runtime', Date.now() - runtimeStart);
      }
    }
  } catch (err) {
    mainError = err;
    exitStatus = sourceArtifactPath ? 'partial' : 'failure';
    if (!dryRun) {
      await monitor.recordAnomaly({
        at: new Date().toISOString(),
        kind: 'run_failure',
        severity: 'error',
        detail: err instanceof Error ? err.message : String(err),
      });
    }
  } finally {
    if (!dryRun) {
      // Finalize manifest and monitor even when the run fails mid-stage.
      const artifactPaths: Record<string, string> = {};
      if (sourceArtifactPath) artifactPaths.source = sourceArtifactPath;
      const runtimeArtifactPath = resolve(outputDir, 'runtime-verification.json');
      if (existsSync(runtimeArtifactPath)) {
        artifactPaths.runtime = runtimeArtifactPath;
        if (exitStatus === 'failure') exitStatus = 'partial';
      }

      const finalized = finalizeManifest(manifest, {
        exitStatus,
        artifactPaths,
        telemetrySummary: {
          totalCostUsd: totalCost,
          totalInputTokens: 0,
          totalOutputTokens: 0,
          invocationCount: 0,
        },
      });
      await writeManifest(outputDir, finalized);
      await monitor.emitRunEnd(exitStatus);

      if (degradationState) {
        await writeFile(resolve(outputDir, 'degradation-state.json'), JSON.stringify(degradationState, null, 2), 'utf8');
        if (degradationState.currentLevel > 0) {
          console.log(`Degradation: final level ${degradationState.currentLevel} (${degradationState.levelHistory.length - 1} escalation(s))`);
        }
      }

      // Scorecard + benchmark integration (runs even on partial success)
      if (exitStatus !== 'failure') {
        try {
          let sourceArtifactData: SourceVerificationArtifact | undefined;
          let runtimeArtifactData: RuntimeVerificationArtifact | undefined;

          if (sourceArtifactPath && existsSync(sourceArtifactPath)) {
            sourceArtifactData = JSON.parse(await readFile(sourceArtifactPath, 'utf8'));
          }
          if (artifactPaths.runtime && existsSync(artifactPaths.runtime) && (mode === 'runtime' || mode === 'full')) {
            runtimeArtifactData = JSON.parse(await readFile(artifactPaths.runtime, 'utf8'));
          }

          let frontierRef = null;
          if (referenceScorePath && existsSync(referenceScorePath)) {
            try { frontierRef = await readScorecard(referenceScorePath); } catch { /* ignore bad ref */ }
          }

          let baseline = null;
          let registry: BenchmarkRegistry | undefined;
          if (benchmarkLabel) {
            registry = new BenchmarkRegistry(target.id);
            await registry.prepare();
            baseline = await registry.getBaseline(finalized.configHash);
          }

          const scorecard = computeScorecard({
            runId: finalized.runId,
            profileId: finalized.profileId ?? null,
            configHash: finalized.configHash,
            targetId: finalized.targetId,
            manifest: finalized,
            monitor,
            sourceArtifact: sourceArtifactData,
            runtimeArtifact: runtimeArtifactData,
            baseline,
            frontierReference: frontierRef,
          });

          const { jsonPath: scorecardJsonPath } = await writeScorecard(outputDir, scorecard);

          if (benchmarkLabel && registry) {
            await registry.recordRun({
              runId: finalized.runId,
              label: benchmarkLabel,
              profileId: finalized.profileId ?? null,
              configHash: finalized.configHash,
              targetId: finalized.targetId,
              timestamp: finalized.startedAt,
              manifestPath: resolve(outputDir, 'manifest.json'),
              scorecardPath: scorecardJsonPath,
            }, scorecard);

            if (promoteBaseline) {
              await registry.promoteBaseline(finalized.runId);
              console.log(`Baseline promoted: ${finalized.configHash}`);
            }

            const matrixMd = await registry.renderMatrixSummary();
            if (matrixMd) {
              const matrixPath = resolve(registry.getTargetDir(), 'matrix-summary.md');
              await writeFile(matrixPath, matrixMd, 'utf8');
            }
          }

          console.log(`\nScorecard: ${scorecard.recommendation.toUpperCase()} — ${scorecard.recommendationReason}`);
          if (benchmarkLabel) {
            console.log(`Benchmark: ${benchmarkLabel} recorded`);
          }

          if (!skipRecommendations) {
            const recommendations = generateRecommendations({
              targetId: target.id,
              campaignId: campaignId ?? undefined,
              monitor,
              sourceArtifact: sourceArtifactData,
              runtimeArtifact: runtimeArtifactData,
              scorecard,
              baseline,
            });
            await writeRecommendations(outputDir, recommendations);
            const critical = recommendations.recommendations.filter(r => r.priority === 'critical').length;
            const high = recommendations.recommendations.filter(r => r.priority === 'high').length;
            console.log(`Recommendations: ${recommendations.recommendations.length} (${critical} critical, ${high} high)`);
          }
        } catch (scorecardErr) {
          console.log(`Warning: scorecard/recommendations failed: ${scorecardErr instanceof Error ? scorecardErr.message : String(scorecardErr)}`);
        }
      }

      if (!mainError) {
        console.log('\n=== Verification complete ===');
        console.log(`Run ID:    ${manifest.runId}`);
        console.log(`Total cost: $${totalCost.toFixed(4)}`);
        console.log(`Output directory: ${outputDir}`);
        console.log(`Manifest:  ${outputDir}/manifest.json`);
        console.log(`Monitoring: ${outputDir}/monitoring/`);

        const anomalies = monitor.getAnomalies();
        if (anomalies.length > 0) {
          console.log(`Anomalies: ${anomalies.length}`);
          for (const a of anomalies) {
            console.log(`  [${a.severity}] ${a.kind}: ${a.detail}`);
          }
        }
      }
    }
  }

  if (mainError) {
    throw mainError;
  }
}

main().catch((err) => {
  console.error('Verification agent failed:', err);
  process.exit(1);
});

/**
 * Number of candidates in a source-verification artifact. An unreadable or
 * missing artifact counts as zero so the run is never treated as successful.
 */
function readCandidateCount(artifactPath: string): number {
  if (!existsSync(artifactPath)) {
    return 0;
  }
  try {
    const parsed = JSON.parse(readFileSync(artifactPath, 'utf8')) as { candidates?: unknown[] };
    return Array.isArray(parsed.candidates) ? parsed.candidates.length : 0;
  } catch {
    return 0;
  }
}
