# Focused Lead Confirmation (Section 11.5)

**Status:** Default-on at runner level as of commit `d32c033` (2026-04-13). Previously opt-in.

A stage that sits between `verification_packet_build` and `local_live`. It takes the top static hypotheses, ranks them, and for each one spins up a persistent CLI worker session bounded by the `FOCUSED_CONFIRMATION_WORKER_CONTRACT`. The worker inspects source and artifacts directly, then requests probes *back through the orchestrator* (not via its own `curl`/`fetch`) so identity ladders, mutation journals, rate limits, and evidence capture all still apply.

The point: pre-confirm or pre-refute high-value leads cheaply before spending local-live / test-synthesis budget on them.

## Flow

```
verification_packet_build
        ↓
rankedLeads = rankLeads(hypotheses, signals, config)
        ↓
briefs = buildLeadBrief(rankedLeads, signals)
writeBriefManifests(briefs, campaignDir)   // briefs land on disk
        ↓
for each brief (up to maxLeads):
    primarySession = runFocusedSession(brief, workerSessionFactory, probeExecutor, role='primary')
    if useCounterWorker && status ∉ {confirmed, refuted}:
        counterSession = runFocusedSession(brief, ..., role='counter')
        session = mergeFocusedSessions(primarySession, counterSession)
    record status: confirmed | refuted | narrowed | needs_browser | needs_human_setup | insufficient_evidence
        ↓
mapConfirmationToHypothesisStatus(status) → hypothesis.status mutation
        ↓
local_live   (with hypotheses already narrowed / refuted)
```

## Configuration

The stage is instantiated in `InvestigationRunnerInternals.ctor` (see `investigation-runner-internals.ts:597`). Key knobs:

| Option | Default | Meaning |
|---|---|---|
| `enabled` | `true` (runner-level) | Master switch; when `false`, stage emits `focused_lead_confirmation_skipped` and returns immediately |
| `maxLeads` | ~5 | Number of top-ranked hypotheses to confirm |
| `maxProbesPerSession` | 10 | Hard cap per worker session; exceeding it emits a coverage gap |
| `useCounterWorker` | true for high-claim-shape leads | Runs a second worker with `role='counter'` if primary was inconclusive |
| `workerSessionFactory` | injected | Builds the CLI worker (Claude Code / Codex) per lead |
| `probeExecutor` | injected | The orchestrator-owned probe execution callback |

Operators typically leave these at defaults; target YAML can override via the `liveProbing.focusedLeadConfirmation` block if present.

## Confirmation outcomes

Every session ends in exactly one of:

| Outcome | Meaning | Hypothesis status after |
|---|---|---|
| `confirmed` | Worker reproduced the exploit via orchestrator-executed probes | `confirmed` |
| `refuted` | Worker has direct evidence the hypothesis is wrong | `refuted` |
| `narrowed` | Hypothesis is partially correct; scope refined | `needs_verification` (narrowed) |
| `needs_browser` | Confirmation requires the browser lane (Section 12.1) | deferred |
| `needs_human_setup` | Requires target-side setup the worker can't perform (seeded DB rows, env vars, OOB token) | deferred |
| `insufficient_evidence` | Session ran out of probe budget without a clear verdict | unchanged |

## Interaction with local-live

By the time `local_live` runs:

- Hypotheses already marked `confirmed` skip the local-live probe generator — local-live just collects additional supporting evidence.
- Hypotheses marked `refuted` are pruned; local-live does not re-attempt them.
- `narrowed` hypotheses carry the refined scope into local-live's probe translation.
- `needs_browser` / `needs_human_setup` are deferred (they appear in the report under "leads requiring human input").

This is why the stage runs *before* local-live: the pruning saves the expensive lane from chasing refuted leads.

## When to disable

- **You explicitly want the raw static → local-live flow** (e.g. benchmarking probe-generator quality). Pass `--disable-focused-lead-confirmation` (or set `enabled: false` in target YAML).
- **CLI workers are unavailable** in the environment. Preflight (`doctor`) will flag this and auto-degrade; no manual action required.
- **You're resuming a prior campaign past this stage.** Use `--resume <id> --resume-at-stage local_live`.

## Events emitted

On the evidence-plane stream:

- `focused_lead_confirmation_started` — stage entry, per-lead brief written
- `focused_lead_session_started` / `focused_lead_session_completed` — per session, with probe count, outcome, cost
- `focused_lead_confirmation_skipped` — when `enabled: false`
- `focused_lead_confirmation_completed` — stage exit; summary used by `AssessmentReportingStage`

## Known failure modes

- **Worker-contract minimality.** The focused contract adds brief-reading + probe-request-routing rules on top of the base 2 rules (no recursion, no live/hosted bypass). Workers still have full workspace freedom; a worker that decides to be creative is correct behaviour, even if you didn't expect the specific probe it asks for.
- **Probe budget vs complexity.** Some hypotheses (multi-step bootstrap → invite accept → privilege change) cannot be confirmed within `maxProbesPerSession: 10`. The outcome will be `insufficient_evidence`; raising the budget helps but increases cost.
- **API models skip brief-mode.** The focused contract relies on persistent-session brief mode; API adapters don't support `supportsNativeSessionResume`, so they always get the full prompt. If you configure an API model for this role, token usage will balloon — use a CLI worker instead.

## Tests

- `packages/attack-lab/src/autonomous/stages/focused-lead-confirmation.test.ts` — stage behaviour + skip path
- `packages/attack-lab/src/providers/focused-worker*.test.ts` — worker contract enforcement and turn schema (the `064ac3e` fix: tolerate JSON `null` on optional turn-schema fields)
