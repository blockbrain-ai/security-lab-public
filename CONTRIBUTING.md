# Contributing to Security Lab

Thanks for helping improve Security Lab. This is an adversarial testing tool:
only run it against systems you own or have explicit written authorisation to
test. Never commit real credentials, customer data, or campaign output.

## Prerequisites

- Node.js 20 or newer (`.nvmrc` pins `20`; CI runs 20.x)
- npm with workspace support (the repo is an npm-workspaces monorepo)

## Build and test

```bash
npm ci             # clean install from the lockfile
npm run build      # tsc --noEmit across every workspace package
npm test           # every *.test.ts in every package
```

Target a single package while iterating:

```bash
npm test --workspace @security-lab/attack-lab
```

`npm run verify:full` is the full gate (build, test, integration, fixture smoke,
campaign soak, coverage). It currently fails on a known coverage threshold:
attack-lab requires 90% line coverage, evidence-plane and security-runtime 95%
(see `scripts/check-coverage.mjs`). A coverage-only failure is a known gap, not a
reason to skip the build and test gates — do not commit a red build or failing
tests.

Tests named `*.live.test.ts` need network, model, or CLI access and are excluded
from the default gate. Do not add them to CI.

## Commit format

```
<type>(<section>): <description>
```

Example: `feat(1.1): add single-writer campaign lock`. Keep one section per
commit, and never commit secrets, `.pipeline/`, or campaign data.

## Conventions

### Contract-first

- Types live in `contracts.ts` at the root of each module. Import them; never
  duplicate a contract in a consumer.
- No magic strings for verdicts, events, or findings.
- Validate at trust boundaries with Zod — target YAML, model responses, and
  saved campaign state are all validated before use.
- No `any` and no unchecked casts at module boundaries.

### No hardcoded target names

Core code must stay framework- and programme-agnostic. Branching on
`target.id.includes('bos')`, adding `isBosTarget()`, or assuming routes or
stacks in core code is a contract violation. Programme-specific logic belongs in
target profiles under `packages/attack-lab/targets/`.

### Tests

- Co-locate tests as `*.test.ts` next to the code they cover.
- Add or update a test with every behaviour change.
- Live tests use the `*.live.test.ts` suffix and stay out of the default gate.

### Autonomous pipeline changes

Before changing anything under `packages/attack-lab/src/autonomous/`, read
`docs/STAGE-CONTRACT.md`. `investigation-runner.ts` is a thin coordinator under a
500-line budget (enforced by a test): stage logic belongs in
`autonomous/stages/<name>.ts`, and runner helpers belong on
`InvestigationRunnerInternals`.

## Reporting problems

- Security vulnerabilities in Security Lab: see [SECURITY.md](SECURITY.md).
- Anything else: open an issue with a minimal reproduction.
