# Architecture

## Core Split

Security Lab is intentionally divided into three programmes:

1. `attack-lab`
   Runs authored adversarial scenarios against targets.

2. `evidence-plane`
   Records append-only events, produces reports, and hashes the resulting artifacts.

3. `security-runtime`
   Applies local guardrails before a probe executes. It is the safety layer for the tester itself.

This prevents one component from being attacker, judge, and recorder at the same time.

## the reference architecture Concepts Lifted Into This Repo

The architecture deliberately borrows the structural ideas that make the reference architecture useful:

- planner / executor / judge / reporter roles
- explicit state instead of implied conversational memory
- chained execution rather than single-pass evaluation
- replayable evidence instead of anecdotal findings
- gates before mutation

In this standalone repo, the first version of those roles is scripted rather than model-backed. That keeps the boundary clean while preserving the orchestration shape needed for later model adapters.
That limitation no longer applies to the autonomous investigator path: planner and judge are model-backed, while the scripted runner remains available for authored regression packs.

## Chained Scenario Model

Each scenario can contain multiple steps.

- a step runs a probe
- a step can capture values from the observed output
- later steps can interpolate those values with `${variable_name}`

That allows Security Lab to test composition chains such as:

- public token -> protected endpoint
- public challenge -> private escalation attempt
- allowed probe -> blocked follow-on action

## Evidence Model

Every run writes:

- `events.jsonl`
- `summary.json`
- `report.md`
- `manifest.json`
- `model-responses.jsonl` for autonomous investigations
- optional remediation proposals and regression packs when findings are confirmed

Events are chained with rolling hashes, and the manifest inventories every artifact in the run directory so later audits can detect tampering.

## Guardrail Model

`security-runtime` blocks probe execution when the requested action violates local policy.

Examples:

- shell commands are blocked in `production_shadow`
- destructive command fragments are denied
- timeouts above the configured maximum are denied
- a kill-switch file halts future probes immediately

This does not replace the target application governance. It is the standalone safety floor for the lab itself.

## Known Exploit Lane

Security Lab now carries a curated exploit-intelligence pack alongside the autonomous discovery loop.

- the exploit pack provides prior knowledge about known exploit families, chain templates, CWE/OWASP mappings, and probe goals
- the discovery loop collects weak signals and composes novel chains that are not explicitly listed in the exploit pack

That separation is deliberate: known exploits guide the search, but they do not bound it.

## Environment Ladder

- `fixture`
  Validate the engine against known-safe local targets.

- `sandbox`
  Run bounded adversarial chains against isolated local environments.

- `staging`
  Probe real pre-production targets you control.

- `production_shadow`
  Read-only or minimally invasive verification only.

## Blind vs Declared

Declared mode is for debugging and regression. Blind mode is for surprise-resistance.

The repo supports both because a target that always knows it is under test is not a realistic security signal.
