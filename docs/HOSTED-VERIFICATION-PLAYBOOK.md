# Hosted Verification Playbook

> Status: this playbook documents the **planned** execution path for the first hosted
> campaign. Hosted verification is the next technical phase of the Security Lab
> programme. As of this writing, no hosted campaign has been executed through the
> standalone project as the canonical path. Serious-local verification is the proven
> baseline.

This document is the step-by-step operational guide for running the first hosted
verification campaign. It assumes the operator has completed the
[HOSTED-TARGET-CHECKLIST.md](HOSTED-TARGET-CHECKLIST.md) and every item is satisfied.

---

## 1. How Hosted Verification Differs From Serious-Local

Serious-local and hosted verification share the same 7-stage investigation pipeline,
the same evidence contracts, and the same finding classification system. The differences
are in where probes execute and what additional constraints apply.

| Dimension | Serious-Local | Hosted (Serious-End-to-End) |
|-----------|---------------|----------------------------|
| **Target** | Local clone, local HTTP server, Docker | Staging or authorized remote environment |
| **Network** | Loopback / local Docker network | Public or VPN-accessible HTTPS |
| **Auth** | Local test credentials or none | Real auth tokens for canary identities |
| **Rate limits** | No practical limit (local) | Hard-capped per profile (`rateLimit`) |
| **Mutation risk** | Contained to disposable local state | Affects shared staging state — rollback required |
| **Failure mode** | Fails closed on missing local coverage | Fails closed on missing hosted coverage |
| **Run mode flag** | `--run-mode serious-local` | `--run-mode serious-end-to-end` |
| **Portfolio profile** | `serious_local` | `serious_end_to_end` |
| **Approval gate** | `--confirm-live` for local HTTP probes | `--authorize-hosted` for hosted probes; write probes need `--allow-hosted-mutations` |
| **Evidence classification** | `confirmed_exploitable_local`, `confirmed_in_isolation_only` | `confirmed_exploitable_hosted` (strongest evidence tier) |
| **Budget** | ~$60 default | ~$100 default |

The key operational difference: hosted probes hit real infrastructure with real auth.
Mistakes are harder to undo, rate limits matter, and the evidence produced is stronger.

---

## 2. Choosing the First Hosted Target

The first hosted campaign should maximize learning while minimizing blast radius.
Recommended criteria:

1. **Smallest attack surface** — choose the target with the fewest endpoints and simplest
   auth model. A smaller target means fewer probes, less mutation risk, and faster feedback.

2. **Existing serious-local baseline** — the target should already have a completed
   serious-local campaign. This provides a comparison point: hosted findings that
   differ from local findings are the interesting ones.

3. **Disposable staging environment** — prefer a staging environment that can be torn down
   and rebuilt if something goes wrong. Ephemeral environments (e.g. PR preview deploys)
   are ideal for the first run.

4. **Operator familiarity** — the operator should know the target well enough to distinguish
   genuine findings from infrastructure noise (WAF blocks, CDN caching artifacts, etc.).

Existing hosted target profiles are available for the target application, fixture-app, and fixture-app in
`packages/attack-lab/targets/`. These profiles define the auth, identity, ingress,
and rate-limit structure for each target's staging environment.

---

## 3. Campaign Shape: The Hosted Execution Flow

A hosted campaign follows the same 7-stage pipeline as any investigation, with
hosted-specific behavior in stages that involve network probes.

### 3.1 Preflight

Before the investigation pipeline starts:

1. **Doctor check** — validates prerequisites, API keys, CLI tools
2. **Profile load** — reads the hosted target profile, validates with Zod
3. **Ingress checks** — executes every check in the profile's `ingressChecks` section:
   - Healthcheck must return expected status
   - Auth enforcement must behave as declared (e.g. 401/403 on protected routes)
4. **Auth bootstrap** — acquires tokens for each `authSource`, confirms they work
5. **Approval prompt** — if `--authorize-hosted` is passed, the operator confirms hosted probing

If any preflight step fails, the campaign does not start. The failure is recorded in
the campaign's `events.jsonl` with a `preflight_failure` event.

### 3.2 Identity Ladder

Hosted probes execute across the identity ladder defined in `hostedIdentities`.
The ladder is traversed from lowest privilege to highest:

```
guest (unauthenticated)
  → user canary (basic authenticated)
    → elevated canary (cross-tenant or elevated role)
      → service canary (service account / API key)
```

At each identity tier, the campaign:
- Executes read-only probes first
- Checks `forbiddenBoundaries` — probes that cross a forbidden boundary for this
  identity are the ones that produce findings
- Records whether the boundary held or was violated

### 3.3 Read-Only Default

The default posture for a hosted campaign is **read-only**. Probes that would create,
modify, or delete state in the target are held unless the operator has explicitly
authorized write-capable probes.

Read-only probes include:
- GET requests to API endpoints
- Authentication and authorization boundary checks
- Response header and body inspection
- Error message information disclosure checks

### 3.4 Bounded Mutation (Requires Explicit Approval)

If the operator has authorized write-capable probes:

- Mutations are **bounded** — each probe declares what it will create or modify
- Mutations use **canary data only** — never real user data or production-meaningful state
- Each mutation probe has a corresponding rollback step in the target profile
- The campaign records every mutation in `events.jsonl` with a `hosted_mutation` event type
- After the campaign, the rollback plan executes (automatically or manually, per the profile)

If write probes are not authorized, the campaign skips them and records this as a
`degraded` outcome for coverage completeness — not as a failure.

---

## 4. Running the First Hosted Campaign

### 4.1 Environment Setup

```bash
# Ensure credentials are in the environment file
cat .env.security-lab.local
# Should contain entries like:
#   TARGET_USER_A_TOKEN=ey...
#   TARGET_USER_B_TOKEN=ey...
#   TARGET_SERVICE_TOKEN=ey...
#   OPENAI_API_KEY=sk-...
#   GEMINI_API_KEY=AIza...
#   (plus any target-specific auth credentials)

# Verify the hosted target profile exists
ls packages/attack-lab/targets/<target>-staging-hosted.yaml
```

### 4.2 Doctor Check

```bash
npm run doctor -- --preset serious-end-to-end \
  --target packages/attack-lab/targets/<target>-static.yaml \
  --hosted-target packages/attack-lab/targets/<target>-staging-hosted.yaml
```

All checks must pass. Pay particular attention to:
- API key availability for the configured provider
- CLI tool availability if the serious profile uses CLI workers

### 4.3 Manual Ingress Verification

Before launching the campaign, manually verify the target is reachable:

```bash
# Healthcheck
curl -s -o /dev/null -w "%{http_code}" https://staging.example.com/health
# Expected: 200

# Auth enforcement (should reject unauthenticated access)
curl -s -o /dev/null -w "%{http_code}" https://staging.example.com/api/protected
# Expected: 401 or 403

# Authenticated access (should succeed)
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TARGET_USER_A_TOKEN" \
  https://staging.example.com/api/protected
# Expected: 200
```

### 4.4 Campaign Launch

```bash
# Read-only hosted campaign (recommended for the first run)
npm run investigate -- \
  --target packages/attack-lab/targets/<target>-static.yaml \
  --hosted-target packages/attack-lab/targets/<target>-staging-hosted.yaml \
  --run-mode serious-end-to-end \
  --authorize-hosted

# With write-capable probes (only after read-only baseline exists)
npm run investigate -- \
  --target packages/attack-lab/targets/<target>-static.yaml \
  --hosted-target packages/attack-lab/targets/<target>-staging-hosted.yaml \
  --run-mode serious-end-to-end \
  --authorize-hosted \
  --allow-hosted-mutations
```

The `--authorize-hosted` flag is mandatory for hosted probes. Without it, the campaign
will not execute hosted probes. Add `--confirm-live` only when the same run also includes
an explicit local-live target that should be exercised before or alongside hosted probing.

### 4.5 Monitoring During Execution

The campaign emits evidence events to `events.jsonl` in real time. During the first
hosted campaign, the operator should monitor:

- **Preflight events** — confirm all ingress checks pass
- **Auth bootstrap events** — confirm all identities authenticate
- **Rate limit compliance** — confirm requests stay within the configured cap
- **Error events** — watch for unexpected 5xx responses or connection failures
- **Mutation events** — if write probes are authorized, confirm each records its rollback

If the healthcheck fails mid-campaign (checked between stages), the campaign halts
automatically with a `blocked` outcome.

---

## 5. Post-Campaign Review

### 5.1 Locate Artifacts

```bash
# Find the most recent campaign
ls -lt data/campaigns/

# Campaign directory contains:
#   state.json     — campaign state and stage outcomes
#   memory.json    — model reasoning trace
#   .writer.lock   — removed after campaign completes

# Evidence run directory contains:
#   events.jsonl   — every evidence event
#   summary.json   — structured findings summary
#   report.md      — human-readable report
```

### 5.2 Inspect the Evidence Run

```bash
# Check overall campaign outcome
cat data/campaigns/<id>/state.json | jq '.status, .stages'

# Count evidence events by type
cat data/campaigns/runs/<id>/events.jsonl | jq -r '.type' | sort | uniq -c | sort -rn

# Review findings
cat data/campaigns/runs/<id>/summary.json | jq '.findings'

# Read the report
cat data/campaigns/runs/<id>/report.md
```

### 5.3 Interpret Hosted Findings

Hosted findings follow the same classification system as local findings (see
[FINDINGS-AND-TRIAGE.md](FINDINGS-AND-TRIAGE.md)), with one important addition:

- **`confirmed_exploitable_hosted`** — the strongest evidence classification. This means
  a vulnerability was demonstrated against real infrastructure with real auth, not just
  in a local clone or test harness. These findings have the highest confidence and
  priority.

Compare hosted findings against the serious-local baseline:
- Findings present in both: confirmed across environments (high confidence)
- Findings only in hosted: may indicate environment-specific configuration (investigate)
- Findings only in local: may indicate local-only conditions or hosted mitigations (note)

For remediation decisions, follow [REMEDIATION-PLAYBOOK.md](REMEDIATION-PLAYBOOK.md).

### 5.4 Execute Rollback

If write-capable probes were authorized:

1. Check the target profile's `rollback` section for the strategy
2. If `api_cleanup` — verify the cleanup commands executed (check `events.jsonl` for
   `rollback_executed` events)
3. If `manual` — execute the documented cleanup steps now
4. Verify the target is in a clean state by re-running the healthcheck and spot-checking
   canary data

### 5.5 What Counts as a Blocker vs an Acceptable Gap

| Observation | Classification |
|-------------|---------------|
| Ingress checks fail before campaign starts | **Blocker** — do not proceed |
| Auth bootstrap fails for one identity | **Blocker** — fix credentials before re-running |
| Rate limit exceeded and target returned 429s | **Blocker** — reduce rate limit in profile |
| A few probes timed out due to slow responses | **Acceptable gap** — record as `degraded`, investigate later |
| Write probes skipped because operator chose read-only | **Acceptable gap** — expected for first run |
| One stage completed with `incomplete` due to model error | **Acceptable gap** — resume from that stage |
| Healthcheck failed mid-campaign | **Blocker** — campaign halted correctly, re-run when stable |

---

## 6. Guard Rails and Safety

### 6.1 Rate Limiting

The target profile's `rateLimit` configuration is enforced by the investigation runner.
There is no override flag — the rate limit is a hard constraint. If the operator needs
a higher rate limit, the target profile must be edited and the change committed.

### 6.2 Stop Conditions

The campaign halts automatically if:
- The healthcheck fails between stages
- The rate limit budget is exhausted
- An auth token is rejected after initially succeeding (possible revocation)
- The operator sends a kill signal (Ctrl+C / SIGINT)

### 6.3 No Production by Default

The `hosted_authorized` environment type in the target profile signals a staging or
explicitly authorized environment. There is no `production` environment type. If
production targeting is ever considered, it requires governance beyond what this
playbook covers (see [HOSTED-TARGET-CHECKLIST.md](HOSTED-TARGET-CHECKLIST.md), Section 6).

### 6.4 Evidence Integrity

Every hosted probe emits a structured evidence event. The campaign's `events.jsonl`
is the source of truth. Findings that lack a corresponding evidence event are
classified as `unconfirmed_lead`, not as confirmed findings — regardless of model
confidence.

---

## 7. Troubleshooting the First Run

| Problem | Likely Cause | Resolution |
|---------|-------------|------------|
| Doctor fails on API key | Key not in `.env.security-lab.local` | Add the key and re-run doctor |
| Ingress check returns unexpected status | Target not deployed, wrong URL, WAF blocking | Verify URL manually with curl |
| Auth bootstrap fails | Expired token, wrong env var name | Refresh credential, check `authSources` mapping |
| Campaign starts but no hosted probes fire | Missing `--authorize-hosted` flag | Re-run with `--authorize-hosted` |
| All probes return 403 | IAP or WAF blocking the Security Lab IP | Allowlist the operator's IP or use a VPN |
| Campaign completes but no hosted findings | Target may be well-secured, or probes too conservative | Review events.jsonl for probe coverage; compare with local baseline |
| Rate limit hit early | `maxRequestsPerCampaign` too low for target size | Increase in target profile, re-run |
| Resume fails after mid-campaign halt | Stale `.writer.lock` | Remove lock file, resume with `--resume <id>` |

---

## 8. What This Playbook Does Not Cover

This playbook prepares the operator for the first hosted campaign. It does not cover:

- **Executing** the first hosted campaign — that is future work
- **Continuous hosted scanning** — recurring hosted campaigns require additional
  scheduling and monitoring infrastructure
- **Production targeting** — see the governance section in HOSTED-TARGET-CHECKLIST.md
- **New target onboarding** — see [TARGET-ONBOARDING.md](TARGET-ONBOARDING.md)
- **Modifying the investigation pipeline** — see [STAGE-CONTRACT.md](STAGE-CONTRACT.md)

The next technical step after this playbook lands is to select a hosted target,
complete the checklist, and execute the first campaign using this playbook as the
operational guide.

---

## Related Documents

- [HOSTED-TARGET-CHECKLIST.md](HOSTED-TARGET-CHECKLIST.md) — pre-flight checklist (must be completed first)
- [OPERATOR-GUIDE.md](OPERATOR-GUIDE.md) — general operator workflow and CLI reference
- [END-TO-END-RUNBOOK.md](END-TO-END-RUNBOOK.md) — serious-local execution guide (proven baseline)
- [FINDINGS-AND-TRIAGE.md](FINDINGS-AND-TRIAGE.md) — finding classification and triage
- [REMEDIATION-PLAYBOOK.md](REMEDIATION-PLAYBOOK.md) — remediation decision framework
- [TARGET-ONBOARDING.md](TARGET-ONBOARDING.md) — target profile creation and structure
