# Security Lab

Security Lab is a standalone adversarial security-testing tool. Point it at a codebase (and optionally at a running instance of it) and it produces auditable, evidence-backed findings: a static investigation, model-driven hypotheses, optional live verification, and a report rendered from a hash-chained event stream.

It is deliberately split into three packages so that no single component is attacker, judge and recorder at once:

| Package | Role |
|---|---|
| `@security-lab/attack-lab` | Scanner, hypothesis generation, planner/judge roles, probe families, verification lanes, campaign orchestration and CLIs |
| `@security-lab/evidence-plane` | Append-only event store with chained hashes, run manifests and report rendering |
| `@security-lab/security-runtime` | Probe authorization gates, kill switch, environment tiers and destructive-command filtering |

## Authorised use only

**Security Lab is for testing systems you own or have explicit written permission to test — nothing else.**

- **Get authorisation in writing first,** and make sure it covers the specific targets, time window, techniques and environments you intend to use. An authorisation that does not mention active probing, credential testing or mutation is not permission to do those things.
- **Own it, or be authorised for it.** "It is publicly reachable", "it is open source", "it is only staging" and "I was curious" are not authorisation.
- **Do not point this at third-party or shared infrastructure** — production systems you do not control, SaaS tenants, cloud metadata endpoints, or anything where you cannot say who authorised you and when.
- **Stay inside the agreed scope while it runs.** Target profiles, identity ladders, rate limits, mutation flags and the hosted tier exist to keep a run inside what was agreed; do not widen them mid-campaign.
- **Unauthorised access is a criminal offence in most jurisdictions** — for example the Computer Fraud and Abuse Act in the United States, the Computer Misuse Act in the United Kingdom, and equivalent legislation elsewhere — and can also create civil liability. "The tool did it" is not a defence.
- **You are responsible for what you configure and run:** the targets, the credentials you supply, the lanes you enable and the probes you authorise.
- **The maintainers do not condone or support unauthorised use** and accept no liability for it.

This notice describes acceptable use of the project. It does not modify, restrict or add conditions to the rights granted under the [Apache-2.0 licence](LICENSE), and it grants no permission to access any system.

If you are not certain you have authorisation, stop and get it in writing before you run anything.

## Safety defaults

- **Host-executing providers are off by default.** The Claude Code / Codex CLI / Pi CLI workers and the bounded-local shell run commands on your machine with your environment, and a scanned repository can influence what they run. They are refused unless you pass `--allow-host-execution` (or set `SECURITY_LAB_ALLOW_HOST_EXECUTION=1`). Prefer running inside a container or VM when you opt in.
- **Probes pass a policy gate.** `security-runtime` enforces environment tiers (sandbox / staging / production-shadow / hosted), a 30-second timeout ceiling, destructive-command filtering and a kill-switch file. Unrecognised probe kinds, invalid timeouts and executable probes with no declared command are denied.
- **Hosted probing needs more than a flag.** Hosted targets require `--authorize-hosted` plus a per-campaign confirmation, canary identities, a rate limiter and an auto-stop monitor.

## Requirements

- Node.js 20+ (`npm 10+`), Linux or macOS
- Optional, for serious runs: API keys for `anthropic` / `openai` / `gemini`, or a local OpenAI-compatible model server (llama.cpp, Ollama), and the `claude` / `codex` CLIs if you enable host execution

## Quick start

```bash
npm ci
npm run build      # tsc --noEmit across all packages
npm test           # native Node test runner (see package.json for the exact command)
```

Run the local fixture smoke pack (no keys, no network):

```bash
npm run fixture:server      # terminal 1
npm run lab:run -- runfiles/fixture-http-smoke.yaml
```

Run an autonomous investigation:

```bash
npm run investigate -- --target /path/to/repo --run-mode smoke
npm run investigate -- --target targets/example-http.yaml --run-mode smoke
```

Check your environment before a serious run:

```bash
npm run doctor -- --target targets/example-http.yaml --preset smoke
```

## Operating modes

- **Runfile mode** (`npm run lab:run -- <runfile>.yaml`) — authored, replayable scenario packs in `declared` (the target may know it is being tested) and `blind` modes, with canaries that declare both safe and exploitable expectations.
- **Autonomous campaigns** (`npm run investigate`) — an eight-stage pipeline (`static → verification_packet_build → focused_lead_confirmation → local_live → test_synthesis → focused_closure → assessment → reporting`) with durable checkpoints, resume-at-stage, a single-writer campaign lock, and three rigor levels: `smoke` (default, degrades honestly), `serious-local` and `serious-end-to-end` (which fail closed when required verification coverage is missing).
- **Post-static verification** (`npm run verify`) — reads a static report from disk, deduplicates against prior advisories, source-verifies candidates and drafts advisories.
- **Supply-chain sentinel** (`npm run sentinel`) — baseline and drift checks for dependency manifests.

## Evidence

Every stage boundary, probe and model call appends a structured event to `events.jsonl`; events are hash-chained, manifests record the chain checkpoint, and reports are rendered from the run's data. `npm run lab:report -- <run-dir>` renders a run, and `npm run lab:report -- <run-dir> --verify` validates the event chain and exits non-zero if it is broken.

Model prompts and responses are archived per run so a result can be traced back to what was asked; treat the run directory as sensitive, since it contains source excerpts and target responses.

## Adding a target

Copy `packages/attack-lab/targets/example-http.yaml` (or `example-code.yaml`, `example-dependency.yaml`) and fill in 6–10 fields — no TypeScript changes are required. See [docs/TARGET-ONBOARDING.md](docs/TARGET-ONBOARDING.md).

Non-Node targets (Python, Go, Rust, Java) are supported with honest coverage reporting: the scanner reports what it cannot do for a given stack rather than guessing.

## Documentation

- [docs/architecture.md](docs/architecture.md) — package split, evidence model, guardrails
- [docs/OPERATOR-GUIDE.md](docs/OPERATOR-GUIDE.md) — installation, bootstrap, campaign lifecycle, resume and repair
- [docs/END-TO-END-RUNBOOK.md](docs/END-TO-END-RUNBOOK.md) — a full serious-local run, step by step
- [docs/STAGE-CONTRACT.md](docs/STAGE-CONTRACT.md) — the investigation stage pipeline contract
- [docs/TARGET-ONBOARDING.md](docs/TARGET-ONBOARDING.md) — writing target profiles
- [docs/KNOWN-LIMITATIONS.md](docs/KNOWN-LIMITATIONS.md) — the honest register of what does not work well yet
- [docs/HOSTED-TARGET-CHECKLIST.md](docs/HOSTED-TARGET-CHECKLIST.md) — pre-flight requirements for hosted probing

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues in the tool itself: see [SECURITY.md](SECURITY.md).

## Licence

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
