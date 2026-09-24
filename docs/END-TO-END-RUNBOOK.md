# Security Lab — End-to-End Runbook

> **Audience**: operators executing Security Lab campaigns.
> **Scope**: step-by-step serious-local execution, the target application as reference example, failure modes, and recovery.
> For prerequisites and concepts, see the [Operator Guide](OPERATOR-GUIDE.md).

---

## 1. Serious-Local Run Sequence

A serious-local campaign follows this sequence:

```
1. Prepare target profiles
2. Set up environment
3. Run doctor
4. Execute the investigation
5. Inspect artifacts
6. Repair artifacts if needed
```

Each step is detailed below.

---

## 2. Step 1 — Prepare Target Profiles

A serious-local campaign requires at least two target profiles:

| Profile | Kind | Environment | Purpose |
|---|---|---|---|
| Static target | `code` | `sandbox` | Source code analysis and hypothesis generation |
| Local-live target | `http` | `local_live` | HTTP probe verification against a running instance |

The local-live target extends the static target with:

- `baseUrl` — the URL of the running target instance
- `environment: local_live` — enables live probing
- Identity ladder — test identities for privilege escalation testing
- Canary specifications — pre-probe validation requests
- Live probing rules — rate limits, mutation policy, auto-stop conditions

See [TARGET-ONBOARDING.md](TARGET-ONBOARDING.md) for the full target profile specification.

---

## 3. Step 2 — Set Up Environment

Create `.env.security-lab.local` in the repository root:

```bash
# Provider API keys (required for serious runs)
OPENAI_API_KEY=sk-...
GEMINI_API_KEY=AIza...

# Target workspace (if the target uses repoRootEnv)
TARGET_REPO_ROOT=/path/to/fixture-workspace

# Identity tokens (if the target declares required identities)
the target application_USER_A_TOKEN=...
the target application_USER_B_TOKEN=...
```

Authenticate CLI workers:

```bash
claude auth login
codex login
```

The canonical serious path uses CLI authentication for Anthropic. Add
`ANTHROPIC_API_KEY` only if you are intentionally using a non-canonical
API-backed Anthropic flow.

---

## 4. Step 3 — Run Doctor

Validate all prerequisites before starting:

```bash
npm run doctor -- --preset serious-local \
  --env-file .env.security-lab.local \
  --target packages/attack-lab/targets/my-target-static.yaml \
  --live-target packages/attack-lab/targets/my-target-local-live.yaml
```

Doctor checks (all must pass for serious runs):

- CLI binaries (`claude`, `codex`) on PATH and authenticated
- API keys (`OPENAI_API_KEY`, `GOOGLE_AI_API_KEY`/`GEMINI_API_KEY`) present
- Target profiles load and validate
- Docker running (if the target requires a Linux sidecar)
- Auth bootstrap functional (if the target declares it)

**Do not proceed if doctor reports failures.** In serious mode, missing prerequisites cause the campaign to fail closed.

---

## 5. Step 4 — Execute the Investigation

### 5.1 Smoke Run (Quick Check)

```bash
npm run investigate -- \
  --target packages/attack-lab/targets/my-target-static.yaml \
  --run-mode smoke
```

Smoke runs degrade honestly when prerequisites are missing. Use them for first scans, target profile iteration, and CI.

### 5.2 Serious-Local Run

```bash
npm run investigate -- \
  --target packages/attack-lab/targets/my-target-static.yaml \
  --live-target packages/attack-lab/targets/my-target-local-live.yaml \
  --run-mode serious-local \
  --confirm-live \
  --env-file .env.security-lab.local
```

The investigation proceeds through eight stages:

1. **Static** — Scans the target codebase, maps the attack surface, generates hypotheses.
2. **Verification Packet Build** — Packages hypotheses into verification packets for live and test lanes.
3. **Focused Lead Confirmation** — (Section 11.5) Ranks top leads and runs focused CLI worker sessions to pre-confirm / refute hypotheses before expensive local-live or test-synthesis budget is spent. Default-on at runner level. See [FOCUSED-LEAD-CONFIRMATION.md](./FOCUSED-LEAD-CONFIRMATION.md).
4. **Local Live** — Probes the running target with HTTP requests to verify hypotheses. CLI workers (Claude Code, Codex CLI) plan and execute probes.
5. **Test Synthesis** — Synthesizes and runs verification test cases against the target.
6. **Focused Closure** — Applies evidence-ref citation rules to classify each hypothesis as confirmed, unconfirmed, or refuted.
7. **Assessment** — Judge panel evaluates findings. Synthesizer produces the executive campaign assessment.
8. **Reporting** — Renders the final `report.md` (merged into the assessment module).

### 5.3 CI Integration

For CI pipelines that prefer to parse the report rather than checking exit codes:

```bash
npm run investigate -- \
  --target packages/attack-lab/targets/my-target-static.yaml \
  --run-mode smoke \
  --exit-zero-on-incomplete
```

---

## 6. Step 5 — Inspect Artifacts

After the campaign completes, inspect the output:

```bash
# Find the campaign ID (most recent directory)
ls -lt data/campaigns/ | head -5

# Read the report
cat data/campaigns/runs/<campaign-id>/report.md

# Check execution status and verdict
cat data/campaigns/runs/<campaign-id>/summary.json | jq '{executionStatus, overallVerdict}'

# Check the executive assessment
cat data/campaigns/runs/<campaign-id>/campaign-assessment.json | jq '.verdict'

# Review the event stream (last 20 events)
tail -20 data/campaigns/runs/<campaign-id>/events.jsonl
```

### Key Artifacts to Check

| Artifact | What to Look For |
|---|---|
| `report.md` | Confirmed findings, unconfirmed leads, coverage gaps, executive summary |
| `summary.json` | `executionStatus` (complete/degraded/incomplete/blocked), `overallVerdict`, lane costs |
| `campaign-assessment.json` | Executive verdict, confidence level, assessment summary |
| `events.jsonl` | Stage boundaries, probe results, coverage gaps, errors |
| `state.json` | Final phase, cost, iteration count |

---

## 7. Step 6 — Repair Artifacts If Needed

If `summary.json` has missing or denormalized fields (common after Security Lab upgrades):

```bash
npm run repair:campaign-artifacts -- <campaign-id> --campaign-dir data/campaigns
```

Repair is idempotent. Run it whenever:

- Report rendering fails due to missing summary fields.
- `summary.json` lacks executive assessment data despite the assessment stage having completed.
- Fields like `executionStatus` or `laneCosts` are missing at the top level.

---

## 8. Resume and Recovery

### 8.1 Resume After Interruption

```bash
npm run investigate -- --resume <campaign-id> \
  --target packages/attack-lab/targets/my-target-static.yaml \
  --live-target packages/attack-lab/targets/my-target-local-live.yaml \
  --run-mode serious-local \
  --confirm-live
```

### 8.2 Resume at a Specific Stage

To re-run from a specific stage (e.g., after fixing a target profile issue):

```bash
npm run investigate -- --resume <campaign-id> \
  --resume-at-stage local_live \
  --target packages/attack-lab/targets/my-target-static.yaml \
  --live-target packages/attack-lab/targets/my-target-local-live.yaml \
  --run-mode serious-local \
  --confirm-live
```

### 8.3 Resume at Assessment Only

If static + verification are done and you only need to re-run assessment:

```bash
npm run investigate -- --resume <campaign-id> \
  --resume-at assessment \
  --target packages/attack-lab/targets/my-target-static.yaml \
  --run-mode serious-local
```

---

## 9. the target application Serious-Local — Reference Example

The the target application (Business Operating System) serious-local campaign is the reference example for this runbook. The same workflow applies to any target.

### 9.1 the target application Target Profiles

the target application uses four target profiles for the serious-local path:

| Profile | File | Purpose |
|---|---|---|
| Static | `targets/fixture-static.yaml` | Code scanning in sandbox environment |
| Local | `targets/fixture-local.yaml` | HTTP probing at `localhost:4000` (sandbox) |
| Local-live | `targets/fixture-local-live.yaml` | Live verification at `localhost:4000` with identity ladder |
| Local-live Linux | `targets/fixture-local-live-linux.yaml` | Docker-based isolated verification at `localhost:4019` |

### 9.2 the target application Local-Live Target Shape

The `fixture-local-live.yaml` profile declares:

- **Base URL**: `http://localhost:4000`
- **Required identities**: `user_a_low`, `user_b_low` (token env vars must be set)
- **Identity ladder**: 5 identities (guest, user_a_low, user_b_low, service_canary, admin_canary) with organization IDs and token env vars
- **Canaries**: 4 canary tests (IDOR cross-tenant, auth bypass, tenant header override, guest action execute)
- **Live probing rules**: No mutations, rate limit 10 req/s and 1000/campaign, auto-stop on 5 consecutive 5xx
- **Rollback**: `snapshot_restore`

### 9.3 Linux-Backed Serious-Local

The `fixture-local-live-linux.yaml` profile adds Docker-based isolation:

- **Base URL**: `http://localhost:4019` (Docker-mapped port)
- **Linux sidecar**: Docker Compose builds from `bos-backend.verification.Dockerfile`
- **Auth bootstrap**: JWT minting (`<prefix>_local_jwt` provider)
- **Startup**: `docker compose up -d postgres backend` with 5-minute timeout
- **Shutdown**: `docker compose down` with volume cleanup
- **Verification policy**: Clean startup, max 20 hypotheses, 4 probes per hypothesis, 3 local-live rounds

### 9.4 the target application Serious-Local Commands

```bash
# Doctor
npm run doctor -- --preset serious-local \
  --env-file .env.security-lab.local \
  --target packages/attack-lab/targets/fixture-static.yaml \
  --live-target packages/attack-lab/targets/fixture-local-live-linux.yaml \
  --linux-runtime container

# Run
npm run investigate -- \
  --target packages/attack-lab/targets/fixture-static.yaml \
  --live-target packages/attack-lab/targets/fixture-local-live-linux.yaml \
  --run-mode serious-local \
  --confirm-live \
  --linux-runtime container \
  --env-file .env.security-lab.local

# Resume
npm run investigate -- --resume <campaign-id> \
  --target packages/attack-lab/targets/fixture-static.yaml \
  --live-target packages/attack-lab/targets/fixture-local-live-linux.yaml \
  --run-mode serious-local \
  --confirm-live \
  --linux-runtime container

# Repair artifacts
npm run repair:campaign-artifacts -- <campaign-id> --campaign-dir data/campaigns
```

### 9.5 Non-Linux the target application Local-Live

If Docker is unavailable, use the non-Linux local-live target (requires the the target application dev server running locally):

```bash
# Start the the target application dev server first (in the the target application workspace)
npm run dev

# Then run the investigation
npm run investigate -- \
  --target packages/attack-lab/targets/fixture-static.yaml \
  --live-target packages/attack-lab/targets/fixture-local-live.yaml \
  --run-mode serious-local \
  --confirm-live \
  --linux-runtime skip \
  --env-file .env.security-lab.local
```

---

## 10. Failure Modes and Operator Responses

### 10.1 Execution Status: `blocked`

**Meaning**: The run could not start or terminated early.

| Cause | Operator Response |
|---|---|
| Kill switch triggered | Check kill-switch configuration; do not bypass |
| Lock contention (another campaign running) | Wait for the other process to finish, or check for stale locks (auto-reclaimed after 30 min) |
| Catastrophic provider error | Check API key validity and provider status |

### 10.2 Execution Status: `incomplete`

**Meaning**: At least one required lane could not run.

| Cause | Operator Response |
|---|---|
| Missing API credentials | Set the required keys in `.env.security-lab.local` and resume |
| CLI worker not authenticated | Run `claude auth login` / `codex login` and resume |
| Target unreachable | Verify the target is running at the declared `baseUrl` and resume |
| Provider timeout | Check network connectivity; increase `--request-timeout-ms` and resume |
| Docker unavailable (Linux target) | Start Docker or use `--linux-runtime skip` with a non-Linux target |

In serious mode, `incomplete` always results in a non-zero exit code. Use `--exit-zero-on-incomplete` only in CI pipelines that parse the report.

### 10.3 Execution Status: `degraded`

**Meaning**: Required lanes ran but optional lanes were skipped.

| Cause | Operator Response |
|---|---|
| Optional counter-planner unavailable | Acceptable — the primary planner carried the run |
| Optional judge panel member unavailable | Review findings with awareness that panel diversity was reduced |
| Non-required lane skipped | Check coverage gaps in `summary.json` to understand what was missed |

Degraded status in smoke mode is normal and expected. In serious mode, review the coverage gaps before accepting the results.

### 10.4 Container/Runtime Failures

| Symptom | Operator Response |
|---|---|
| Docker Compose fails to start | Check `docker info`, verify the Dockerfile exists, check port conflicts |
| Container starts but target is unreachable | Check port mapping matches `baseUrl` in the target profile |
| Container health check times out | Increase startup timeout in target profile or investigate container logs |
| Auth bootstrap fails to mint tokens | Check JWT configuration and signing keys in the target profile |

### 10.5 Missing Credentials/Bootstrap

| Symptom | Operator Response |
|---|---|
| Doctor fails on `openai_api_key` | Set `OPENAI_API_KEY` in `.env.security-lab.local` |
| Doctor fails on `google_ai_api_key` | Set `GEMINI_API_KEY` or `GOOGLE_AI_API_KEY` |
| Doctor fails on `claude_auth` | Run `claude auth login` |
| Doctor fails on `codex_auth` | Run `codex login` |
| Doctor fails on `target_profile` | Check target YAML syntax and required fields |
| Doctor fails on `required_identities` | Set the required identity token env vars |

---

## 11. Hosted Verification — Next Step

Hosted verification (probing a real staging or production-shadow environment over the network) is **not covered by this runbook**. It is the next operational step after serious-local campaigns are proven.

What is required before hosted verification:

- A reachable staging environment with known auth mechanism
- A `hosted_authorized` target profile with identity ladder and rate limits
- The `--authorize-hosted` flag (explicit operator consent)
- The hosted readiness documents:
  - [HOSTED-TARGET-CHECKLIST.md](HOSTED-TARGET-CHECKLIST.md)
  - [HOSTED-VERIFICATION-PLAYBOOK.md](HOSTED-VERIFICATION-PLAYBOOK.md)

Do not attempt hosted verification using this runbook. The target profile shape, auth expectations, and guard rails are different from local-live.

---

## 12. Command Quick Reference

```bash
# Doctor (serious-local)
npm run doctor -- --preset serious-local --env-file .env.security-lab.local \
  --target packages/attack-lab/targets/<target>.yaml \
  --live-target packages/attack-lab/targets/<live-target>.yaml

# Smoke run
npm run investigate -- --target packages/attack-lab/targets/<target>.yaml

# Serious-local run
npm run investigate -- \
  --target packages/attack-lab/targets/<target>.yaml \
  --live-target packages/attack-lab/targets/<live-target>.yaml \
  --run-mode serious-local --confirm-live \
  --env-file .env.security-lab.local

# Resume a campaign
npm run investigate -- --resume <campaign-id> \
  --target packages/attack-lab/targets/<target>.yaml \
  --run-mode serious-local

# Resume at a specific stage
npm run investigate -- --resume <campaign-id> \
  --resume-at-stage <stage> \
  --target packages/attack-lab/targets/<target>.yaml

# Repair campaign artifacts
npm run repair:campaign-artifacts -- <campaign-id> --campaign-dir data/campaigns

# List portfolio profiles
npm run investigate -- --list-portfolios
```
