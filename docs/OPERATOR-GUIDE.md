# Security Lab — Operator Guide

> **Audience**: operators running Security Lab as a standalone project.
> **Scope**: installation, bootstrap, doctor, mode selection, campaign lifecycle, artifacts, resume, and repair.
> Security Lab is a standalone security investigation tool. It is not a submodule of any target project.

---

## 1. What Security Lab Is

Security Lab is a generic, autonomous security investigator. It scans any codebase the operator points it at, runs static analysis and model-driven hypothesis generation, verifies hypotheses through local-live HTTP probes and synthesised test cases, and produces auditable findings backed by replayable evidence.

**What it is not:**

- Not a SAST/DAST scanner, compliance auditor, or SaaS product.
- Not integrated into any target project's build pipeline — it runs independently.
- Not a replacement for manual penetration testing — it augments it with automated, evidence-backed investigation.

---

## 2. Prerequisites

### Required

| Dependency | Minimum Version | How to Check |
|---|---|---|
| Node.js | 20+ | `node --version` |
| npm | 10+ (ships with Node 20) | `npm --version` |
| TypeScript | 5.x (installed via npm) | `npx tsc --version` |

### Required for Serious Runs

| Dependency | Purpose | How to Check |
|---|---|---|
| `claude` CLI | Claude Code worker adapter | `claude --version` |
| `codex` CLI | Codex CLI worker adapter | `codex --version` |
| OpenAI API key | Judge models (GPT-5.4) and Codex workers | `echo $OPENAI_API_KEY` |
| Gemini API key | Counter-planner models | `echo $GEMINI_API_KEY` or `echo $GOOGLE_AI_API_KEY` |

### Optional

| Dependency | When Needed | How to Check |
|---|---|---|
| Docker | Linux-backed serious-local targets with sidecar containers | `docker info` |

---

## 3. Installation

```bash
# Clone the repository
git clone <repo-url> security-lab
cd security-lab

# Install dependencies (all workspace packages)
npm install

# Verify the build
npm run build

# Run the test suite
npm test
```

---

## 4. Environment and Bootstrap

### 4.1 Environment File Loading

Security Lab loads environment variables from files in this precedence order (last wins for overlapping keys):

1. `<repoRoot>/.env.local`
2. `<repoRoot>/.env.security-lab.local`
3. Path specified in `SECURITY_LAB_ENV_FILE` environment variable
4. Path passed via `--env-file` CLI flag (highest precedence)

Create `.env.security-lab.local` in the repository root for local configuration:

```bash
# .env.security-lab.local
OPENAI_API_KEY=sk-...
GEMINI_API_KEY=AIza...

# Target workspace paths (if not using defaults)
TARGET_REPO_ROOT=/path/to/fixture-workspace
```

> **Note**: `.env.security-lab.local` is gitignored. Never commit API keys.
> The canonical serious path uses `claude auth login` rather than
> `ANTHROPIC_API_KEY`. An Anthropic API key is only needed for non-canonical
> API-backed flows.

### 4.2 Provider Key Aliases

Security Lab normalizes Gemini/Google AI key aliases automatically:

- If only `GEMINI_API_KEY` is set, `GOOGLE_AI_API_KEY` is populated with the same value.
- If only `GOOGLE_AI_API_KEY` is set, `GEMINI_API_KEY` is populated with the same value.
- If both are set, both are left as-is.

You only need to set one of the two.

### 4.3 CLI Worker Authentication

Before running serious campaigns, authenticate the CLI workers:

```bash
# Claude Code
claude auth login

# Codex CLI
codex login
```

---

## 5. Doctor

The `doctor` command validates that prerequisites are in place before a campaign starts. Run it before every serious campaign.

```bash
npm run doctor
```

With options:

```bash
npm run doctor -- --preset serious-local --env-file .env.security-lab.local \
  --target packages/attack-lab/targets/my-target-static.yaml \
  --live-target packages/attack-lab/targets/my-target-local-live.yaml
```

### What Doctor Validates

| Check | Condition |
|---|---|
| `claude_binary` | `claude` CLI is on PATH |
| `codex_binary` | `codex` CLI is on PATH |
| `claude_auth` | `claude auth status` succeeds |
| `codex_auth` | `codex login status` succeeds |
| `openai_api_key` | `OPENAI_API_KEY` is set (serious presets only) |
| `google_ai_api_key` | `GOOGLE_AI_API_KEY` or `GEMINI_API_KEY` is set (serious presets only) |
| `target_profile` | Target YAML loads and validates |
| `live_target_profile` | Live target YAML loads and validates (if provided) |
| `hosted_target_profile` | Hosted target YAML loads and validates (if provided) |
| `docker_daemon` | Docker is running (if live target requires a Linux sidecar) |
| `local_auth_bootstrap` | Auth bootstrap can mint canary identities (if declared in target) |

Doctor runs automatically as a preflight check when starting an investigation (unless `--skip-preflight` is passed).

---

## 6. Run Modes

Security Lab has three run modes that control ceremony level and failure behavior.

### 6.1 Smoke (default)

```bash
npm run investigate -- --target packages/attack-lab/targets/my-target.yaml --run-mode smoke
```

- **Intent**: Low-ceremony, best-effort. Suitable for quick checks, CI integration, and exploratory runs.
- **Failure behavior**: Degrades honestly when prerequisites are missing. A missing credential or unavailable worker does not abort the run — the affected lane is recorded as a coverage gap.
- **Coverage gaps**: Recorded in the evidence stream but do not change `executionStatus` from `complete` to `incomplete`.
- **Default portfolio**: `balanced` ($10 budget ceiling).

### 6.2 Serious-Local

```bash
npm run investigate -- --target packages/attack-lab/targets/my-target.yaml --run-mode serious-local \
  --live-target packages/attack-lab/targets/my-target-local-live.yaml
```

- **Intent**: High-ceremony local verification. Suitable for pre-release security audits.
- **Failure behavior**: Fails closed. Missing credentials, unavailable workers, or skipped required lanes cause `incomplete` status and non-zero exit.
- **Coverage gaps**: Every skipped lane is recorded; `executionStatus` reflects the gaps.
- **Worker scope**: CLI workers (Claude Code, Codex CLI) fill planner, counter-planner, synthesizer, and reporter roles. API models serve as judges.
- **Default portfolio**: `serious_local` ($60 budget ceiling).

### 6.3 Serious-End-to-End

```bash
npm run investigate -- --target packages/attack-lab/targets/my-target.yaml --run-mode serious-end-to-end \
  --hosted-target packages/attack-lab/targets/my-target-hosted.yaml --authorize-hosted
```

- **Intent**: Full-ceremony verification including hosted probes against a real environment.
- **Failure behavior**: Same as serious-local — fails closed.
- **Worker scope**: Same as serious-local, plus remote verification endpoints.
- **Default portfolio**: `serious_end_to_end` ($100 budget ceiling).

> **Note**: Hosted verification is documented separately in
> [HOSTED-TARGET-CHECKLIST.md](HOSTED-TARGET-CHECKLIST.md) and
> [HOSTED-VERIFICATION-PLAYBOOK.md](HOSTED-VERIFICATION-PLAYBOOK.md). It is the
> next technical phase, not the default operator path.

### 6.4 Choosing a Mode

| Situation | Recommended Mode |
|---|---|
| First scan of a new target | `smoke` |
| Iterating on target profile | `smoke` |
| CI pipeline integration | `smoke` with `--exit-zero-on-incomplete` |
| Pre-release security audit | `serious-local` |
| Full security sign-off | `serious-end-to-end` (when hosted target is available) |

### 6.5 Presets

The `--preset` flag is a shorthand that sets the run mode and selects the matching portfolio profile:

| Preset | Run Mode | Portfolio |
|---|---|---|
| `smoke` | `smoke` | `balanced` |
| `serious-local` | `serious-local` | `serious_local` |
| `serious-end-to-end` | `serious-end-to-end` | `serious_end_to_end` |
| `diagnostic` | (default) | `production` |

---

## 7. Campaign Stages

An investigation flows through eight durable stages in order:

| # | Stage | Purpose |
|---|---|---|
| 1 | `static` | Scan the target codebase, map attack surface, synthesize hypotheses |
| 2 | `verification_packet_build` | Package hypotheses for verification lanes |
| 3 | `focused_lead_confirmation` | (Section 11.5) Rank top leads and run focused worker sessions to pre-confirm / refute before expensive lanes. Default-on; see [FOCUSED-LEAD-CONFIRMATION.md](./FOCUSED-LEAD-CONFIRMATION.md) |
| 4 | `local_live` | Local live-replay verification (HTTP probes against a running target) |
| 5 | `test_synthesis` | Synthesize and execute verification tests |
| 6 | `focused_closure` | Apply evidence-ref citation rules to classify hypotheses |
| 7 | `assessment` | Executive campaign assessment (judge panel + synthesizer) |
| 8 | `reporting` | Final report rendering (merged into the assessment module) |

Each stage produces a `StageResult` with an outcome:

| Outcome | Meaning |
|---|---|
| `complete` | Stage ran fully with no gaps |
| `degraded` | Stage ran but some optional work was skipped |
| `incomplete` | Stage could not complete a required task |
| `blocked` | Stage could not start or was terminated early |

---

## 8. Execution Status

`executionStatus` describes whether the investigation process completed successfully. It is **independent from the security verdict**.

| Status | Meaning |
|---|---|
| `complete` | Every required lane ran; no gaps in required lanes |
| `degraded` | Required lanes ran but some optional lanes were skipped |
| `incomplete` | At least one required lane could not run (missing prerequisites, timeout, unrecoverable error) |
| `blocked` | Run could not start or terminated early (kill switch, lock contention, catastrophic error) |

The security verdict (`overallVerdict`) is a separate axis:

| Verdict | Meaning |
|---|---|
| `confirmed_vulnerabilities` | Confirmed, evidence-backed vulnerabilities found |
| `validated_risks_only` | Architectural risks identified, no confirmed exploits |
| `no_material_findings` | No material security findings |
| `unconfirmed_leads_only` | Leads exist but none met the confirmation bar |

**These two axes are never collapsed into a single status.** A campaign can be `complete` with `no_material_findings`, or `incomplete` with `confirmed_vulnerabilities`.

---

## 9. Campaign Directory Structure

Campaign data is stored under `data/campaigns/` (configurable via `--campaign-dir`). Each campaign creates two directory trees:

### Campaign State (`data/campaigns/<campaign-id>/`)

| File | Purpose |
|---|---|
| `state.json` | Campaign state machine: phase, iteration, cost, stage boundaries, session IDs |
| `memory.json` | Campaign memory: signals, hypotheses, findings, probe fingerprints, attack graph |
| `last-results.txt` | Last iteration observation bundle |
| `.writer.lock` | Single-writer lock (PID, hostname, timestamp) — prevents concurrent access |

### Evidence Run (`data/campaigns/runs/<campaign-id>/`)

| File | Purpose |
|---|---|
| `events.jsonl` | Append-only event stream with hash chain — every stage boundary, probe, provider call |
| `summary.json` | Investigation summary: findings, assessment, verification lanes, costs |
| `report.md` | Rendered markdown investigation report |
| `manifest.json` | File manifest of the run directory |
| `campaign-assessment.json` | Executive assessment artifact (when present) |

> **Note**: Campaign data is gitignored. Do not commit campaign directories.

---

## 10. Resume and Recovery

### 10.1 Resuming a Campaign

If a campaign is interrupted (process killed, network failure, timeout), resume it:

```bash
npm run investigate -- --resume <campaign-id> --target packages/attack-lab/targets/my-target.yaml
```

Resume behavior:

- Reloads `state.json` and `memory.json` from the campaign directory.
- Skips stages that already completed successfully.
- Continues from the last incomplete stage.
- Evidence IDs and refs are stable across resume — no duplicate IDs.

### 10.2 Resuming at a Specific Stage

To re-run from a specific stage (discarding results from that stage onward):

```bash
npm run investigate -- --resume <campaign-id> --resume-at-stage <stage> \
  --target packages/attack-lab/targets/my-target.yaml
```

Valid stage names: `static`, `verification_packet_build`, `focused_lead_confirmation`, `local_live`, `test_synthesis`, `focused_closure`, `assessment`, `reporting`.

### 10.3 Resume-at Phase

The `--resume-at` flag provides a coarser-grained resume point:

| Value | Behavior |
|---|---|
| `auto` (default) | Resume from the last incomplete stage |
| `verification` | Skip static analysis, resume from verification |
| `assessment` | Skip static + verification, resume from assessment |

When resuming at `verification` or `assessment`, the planner/judge adapters are allowed to be unavailable since those roles are not needed in the later phases.

### 10.4 Concurrent Resume Prevention

Security Lab enforces a single-writer lock per campaign. If another process holds the lock, the resume attempt fails immediately with a `WriterLockContentionError`. Stale locks (dead PID or older than 30 minutes) are reclaimed automatically.

### 10.5 When to Rerun vs Resume

| Situation | Action |
|---|---|
| Process crashed mid-stage | `--resume <id>` — pick up where it left off |
| Stage produced bad results (e.g., bad hypotheses) | `--resume <id> --resume-at-stage <earlier-stage>` — rerun from that stage |
| Target code changed significantly | Start a fresh campaign — do not resume |
| Credentials rotated | `--resume <id>` — the new credentials will be used on the next provider call |

---

## 11. Artifact Repair

Campaigns from earlier versions of Security Lab may have incomplete or denormalized `summary.json` artifacts. The repair command reconciles and backfills missing fields:

```bash
npm run repair:campaign-artifacts -- <campaign-id> --campaign-dir data/campaigns
```

### What Repair Does

1. Opens the evidence store for the specified campaign.
2. Reads `summary.json` and `campaign-assessment.json`.
3. Merges nested `verificationLanes` sub-objects into top-level fields.
4. Backfills missing executive assessment fields from the assessment JSON.
5. Backfills `executionStatus`, `requiredCoverageSatisfied`, `meaningfulAttempts`, and `laneCosts` from verification lane data.
6. Writes the repaired summary back.

### When to Repair

- After upgrading Security Lab, if older campaigns have missing fields in `summary.json`.
- If the assessment stage completed but `summary.json` lacks executive assessment data.
- If report rendering fails due to missing summary fields.

Repair is idempotent — running it multiple times on the same campaign is safe.

---

## 12. Key CLI Flags Reference

### Essential Flags

| Flag | Description |
|---|---|
| `--target <path>` | Target YAML profile (required) |
| `--run-mode <mode>` | `smoke`, `serious-local`, or `serious-end-to-end` |
| `--preset <name>` | Shorthand for run-mode + portfolio (`smoke`, `serious-local`, `serious-end-to-end`, `diagnostic`) |
| `--live-target <path>` | Live target YAML profile (for local-live verification) |
| `--resume <id>` | Resume a previous campaign |
| `--resume-at-stage <stage>` | Resume at a specific pipeline stage |
| `--env-file <path>` | Override environment file path |
| `--campaign-dir <path>` | Campaign data directory (default: `data/campaigns`) |

### Verification Control

| Flag | Description |
|---|---|
| `--confirm-live` | Run integrated local-live confirmation |
| `--verify-via <lanes>` | Comma-separated lanes: `test-synthesis`, `local-live`, `hosted`, `supply-chain` |
| `--authorize-hosted` | Required to permit hosted probes |
| `--allow-local-mutations` | Permit POST/PUT/DELETE in local-live |
| `--linux-runtime <mode>` | `container`, `fail`, or `skip` (for Linux sidecar targets) |

### Budget and Limits

| Flag | Description |
|---|---|
| `--max-iterations <n>` | Maximum iterations (default: 20) |
| `--max-cost <n>` | Maximum cost in USD (default: from portfolio) |
| `--judge-limit <n>` | Max hypotheses judged per static iteration (default: 5) |
| `--test-synthesis-limit <n>` | Max synthesized tests per run (default: 3) |
| `--verification-hypotheses <n>` | Max hypotheses for live verification (default: 15) |
| `--live-probes-per-hypothesis <n>` | Max live probes per hypothesis (default: 3) |

### Provider Overrides

| Flag | Description |
|---|---|
| `--portfolio <id>` | Portfolio profile override |
| `--planner-provider <p>` | Planner provider override |
| `--planner-model <m>` | Planner model override |
| `--judge-provider <p>` | Judge provider override |
| `--judge-model <m>` | Judge model override |
| `--worker-primary <kind>` | `claude_code` or `codex_cli` |
| `--worker-counter <kind>` | `claude_code` or `codex_cli` |

---

## 13. Portfolio Profiles

Security Lab ships with six portfolio profiles that configure which models fill each role:

| Profile | Budget | Use Case |
|---|---|---|
| `balanced` | $10 | Default smoke runs |
| `cost_sensitive` | $3 | Budget-constrained quick scans |
| `production` | $20 | Default profile, multi-model panels |
| `ultimate` | $50 | Maximum model diversity |
| `serious_local` | $60 | Serious-local with CLI workers |
| `serious_end_to_end` | $100 | Serious end-to-end with hosted |

List available portfolios:

```bash
npm run investigate -- --list-portfolios
```

In serious profiles (`serious_local`, `serious_end_to_end`), CLI workers (Claude Code, Codex CLI) fill the planner, counter-planner, synthesizer, and reporter roles. These workers have full filesystem access within the bounded campaign workspace. API models serve as judges because arbitration does not need filesystem access.

---

## 14. Target Profiles

Target profiles are YAML files in `packages/attack-lab/targets/` that declare everything about a scan target. See [TARGET-ONBOARDING.md](TARGET-ONBOARDING.md) for the full specification.

### Quick Reference

| Field | Required | Description |
|---|---|---|
| `id` | Yes | Unique kebab-case identifier |
| `name` | Yes | Human-readable label |
| `description` | Yes | One-paragraph explanation |
| `kind` | Yes | `http`, `code`, or `dependency` |
| `environment` | Yes | `sandbox`, `local_live`, `staging`, `hosted_authorized`, `production_shadow`, `fixture` |
| `repoRoot` | Yes | Absolute path to source (or `repoRootEnv` for env var) |
| `baseUrl` | HTTP only | URL of the running target instance |

Starter templates:
- `targets/example-http.yaml` — HTTP live probing + code scanning
- `targets/example-code.yaml` — Static scanning only
- `targets/example-dependency.yaml` — Dependency scanning only
