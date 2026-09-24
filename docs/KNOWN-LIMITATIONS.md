# Known Limitations & Operator Workarounds

Recorded 2026-04-14 after a full codebase sweep. These are **operational truths** — the system works around them or the operator does. Update this file when a limitation is fixed or a new one is discovered.

---

## L1 — Best results come from an out-of-programme Claude Code session

**Status:** Primary operator workaround. Not a bug; a recognised current-best workflow.

**Observation.** The most useful Security Lab runs today follow this pattern:

1. Run the `static` stage inside the programme (all the scanner, planner, counter-planner, judge-panel, knowledge-base machinery).
2. Stop there. Do **not** let local-live or test-synthesis spend budget.
3. Open an unrelated Claude Code session outside the programme.
4. Hand it the static campaign outputs (`summary.json`, the hypothesis list, source refs) and let it hand-verify.

**Why this wins.** The static stage is where the Mythos-style cross-domain linking already performs well. Local-live and test-synthesis currently dilute those results — see L2. An outside Claude Code session, free from the runner's stage contracts and without the brittle probe classifier in the path, reproduces the cleanest pattern of "follow the leads the static run surfaced, probe them by hand."

**When to skip this workaround.** If you just want a report and the target has good canary/identity/entity coverage, the full pipeline can produce a complete artifact. For *serious* findings, stop at static and verify outside.

**Do not treat this as permanent.** The `local-live` and `focused_lead_confirmation` stages are being actively improved; the Ouro/LoopLM improvement plan (Tranches 1–7 in [the inspiration library/ouro-looped-models/SECURITY-LAB-IMPROVEMENT-PLAN-2026-04-12.md](./the inspiration library/ouro-looped-models/SECURITY-LAB-IMPROVEMENT-PLAN-2026-04-12.md)) targets the causes.

---

## L2 — Local-live is expensive and format-sensitive

**Status:** Known; actively worked on.

**Cost profile.**
- Default local-live rate limiter: 10 req/s, 1000 req/campaign → ≥100 seconds at saturation.
- CLI workers spawned per packet can run for minutes; no retry layer on CLI timeouts (API models retry `[60s, 120s, 30m, 30m, 30m]`, CLI failures propagate).
- Judge panels run judges **in parallel** (`Promise.all` across 2–3 members) → 3× cost spike per judged batch.
- Campaign assessment panel + synthesizer adds another 4–6× final-stage model calls.

**Format sensitivity.** The automated lane produces false "exploitable" verdicts when the response shape, rather than the response content, drives the classifier. Observed families:

| Failure mode | What happens | Root cause |
|---|---|---|
| SPA fallback read as a data leak | A catch-all route returns the app shell with `200 text/html`; the classifier treats a 2xx as evidence | The `spa_shell` suppression only fires for one shell shape; custom scaffolds slip through |
| Empty collection read as a leak | An empty JSON array for a user with no records is treated as exposed data | Substring assertions with no route-kind awareness |
| Unresolved path parameters sent literally | Placeholder segments are sent verbatim, return 4xx, and are classified as failed exploit attempts | The probe translator does not guarantee entity resolution, and a coverage gap is recorded but the probe still fires |
| Missing anonymous identity | A no-session probe is required to demonstrate the issue, but the lane always used an authenticated session | No out-of-box "no-auth" identity in the default identity ladder |
| Multi-step flows assumed to be one request | Issues that require seeding state and completing a sign-up or invite flow are not exercised | The generator composes single requests; multi-step sequences must be declared |
| No raw protocol probes | Issues that require a raw upgrade handshake with manipulated headers are invisible | No WebSocket probe family |

Consequence: on a real target the lane can report a large majority of its "confirmed" verdicts as false positives on manual review, while missing the small number of genuine issues that need multi-step or raw-protocol probing. Treat automated confirmations as leads, not conclusions.

**Workarounds.**
- Hand-verify before acting on any automated confirmation.
- When running the full pipeline, set a tight `maxFollowupsPerSurprise` and probe budget in the target YAML (`liveProbing` block).
- Use `--run-mode serious-local` to force fail-closed on missing local-live coverage — better a failed run than a confident false positive.
- Declare multi-step flows (bootstrap, sign-up, invite accept) in the target YAML rather than hoping the generator composes them.

---

## L3 — Canary matching is substring-only, no regex or JSONPath

**Status:** Documented limitation; not scheduled.

`CanarySpec.expectedWhenSafe` / `expectedWhenExploitable` support `status`, `statusIn[]`, `bodyContains[]`, `bodyNotContains[]`. No regex. No JSON pointer / JSONPath extraction beyond simple dot paths. No array iteration in Section 11.4 sequences.

**Workaround.** Keep canaries narrow and status-driven where possible. If response-body matching is required, pick a marker string the app is guaranteed to emit only on the exploit path (a structured error code, a table name, a known auth-guard message).

---

## L4 — Silent session-resume fallback in CLI adapters

**Status:** Known behaviour; explicitly preserved.

`claude-code-adapter` and `codex-cli-adapter` catch resume failures (`--resume <stale-id>` fails) and **transparently retry without the session ID**. No warning is logged. If the operator expected continuity and state was silently lost, the run may look successful but actually re-did work.

**Workaround.** If continuity matters (brief-mode role sessions, long focused-confirmation flows), verify session IDs in the role session store after a resume — the store writes JSONL transcripts per role.

---

## L5 — Rollback is best-effort, not compensated

If a mutation probe's rollback HTTP call fails, `MutationJournal` records the failure but the campaign continues. The target may be left in a dirty state and subsequent probes may become unreliable.

**Workaround.** For any target that runs mutation probes, run the local-live lane inside a disposable container (the project's Docker compose setup for fixture-smoke is the model). Tear down and rebuild between campaigns. Never run mutation probes against a target you care about the state of.

---

## L6 — No retry layer on CLI workers

API model adapters (`anthropic`, `openai`, `gemini`) wrap every `invoke()` in `withRetry()` with exponential backoff on 429/503/529/network errors. CLI worker adapters (`claude_code`, `codex_cli`) do **not**. A timeout or crash on a CLI worker aborts the call immediately.

**Workaround.** Pick API models for high-variance roles (planner, counter-planner, synthesizer). Use CLI workers for focused, bounded tasks (confirmation sessions, local-live probe execution).

---

## L7 — Route detection is regex-only, no AST

The static scanner uses regex for route/handler discovery (`/(\w+)\.(get|post|...)\s*\(\s*['"\`]([^'"\`]+)['"\`]/gi`) and hint-based auth detection. Frameworks using decorators, meta-programming, generated routers, Next.js catch-alls, or plugin-based mounting can be partially or fully invisible to the scanner. Auth guards mounted at plugin or middleware level are often missed.

**Workaround.** Declare route roots and auth hints explicitly in the target YAML (`routeRoots`, `hints.authSurfaces`, `hints.governanceSurfaces`). Keep an eye on the scanner's "No local auth markers observed" notes — the scanner knows when it's operating blind.

---

## L8 — Response bodies truncated at 4–8KB before classification

`LiveExecutionResult.responseBody` is truncated (4KB in result, 8KB in audit trail). If an actual exploit dumps a large payload (full DB dump, binary leak, large list), the classifier only sees the head. A verdict can end up inconclusive even when a larger body would have confirmed.

**Workaround.** Use targeted canaries with small, deterministic expected markers. If you expect a large response, verify by hand (L1) rather than through the automated classifier.

---

## L9 — SHADE monitoring-stress scenarios are simulated, not empirically run

`ShadeScenario.executionMode` is `'simulated' | 'sandbox'`. In practice the SHADE scenarios are evaluated via model calls, not actually executed live end-to-end. Stealth scores and detection latencies are model-assessed.

**Workaround.** Treat monitoring-stress output as a **model opinion** about a scenario's likely behaviour, not as empirical evidence of detection gaps.

---

## L10 — `.security-lab-stop` kill switch is the only graceful abort

Creating `.security-lab-stop` in the campaign dir causes the next probe authorization to refuse, which halts probing. The current investigation phase still completes (finalising files, writing events). There is **no mid-stage abort** below probe granularity.

**Workaround.** For hard stops, `SIGTERM` the runner process. The lock handler now drains in-flight evidence writes, releases the lock and exits with code 143 (130 for `SIGINT`); a second signal exits immediately. A lock whose local PID is dead is reclaimed on the next run.

---

## L11 — Host-executing providers are disabled by default

**Status:** deliberate, from the 2026-09-24 safety audit.

`claude_code`, `codex_cli`, `pi_cli` and `bounded_local` do not merely answer prompts: they run a coding agent or shell on the operator's machine with the operator's environment, and the CLI agents are spawned with permission/sandbox bypass flags. A repository that contains prompt injection can therefore cause commands to run as the operator (audit findings B6/B7).

**Default.** `createAdapter()` refuses these providers and returns an `UnavailableAdapter` with the reason; the run degrades honestly and records why. API providers (`anthropic`, `openai`, `gemini`) are unaffected.

**Opt in.** `--allow-host-execution` on `investigate` / `verify`, or `SECURITY_LAB_ALLOW_HOST_EXECUTION=1`. Opting in is an acknowledgement, not a sandbox — run the tool in a container or VM when you do.

**Not yet done (tracked).** The lanes that call these paths have not all been re-tested under the fail-closed default, and the shell-probe allow-list (B7) and browser origin policy (B9) are still to land.

---

## Remediation roadmap

The concrete improvement plan for L1–L6 is the eight-tranche Ouro/LoopLM plan at [the inspiration library/ouro-looped-models/SECURITY-LAB-IMPROVEMENT-PLAN-2026-04-12.md](./the inspiration library/ouro-looped-models/SECURITY-LAB-IMPROVEMENT-PLAN-2026-04-12.md). The most immediately relevant:

- **Tranche 4.5 — probe intelligence layer** — hypothesis-shaped probe families, entity/parameter resolution from real state, multi-step probe plans, assertion-based verdict classification. Directly addresses L2, L3 format-sensitivity and classification brittleness.
- **Tranche 2 — adaptive compute per packet** — spends more budget on high-signal hypotheses, less on repetitive ones. Addresses L2 cost profile.
- **Tranche 3 — formal draft → verify split** — cheaper proposer, stronger verifier. Addresses L2 cost and L6 retry mismatch.
- **Tranche 7 — browser lane** — unlocks cross-site WebSocket hijacking, session/cookie and stored-XSS classes that are currently invisible.
