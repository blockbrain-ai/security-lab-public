# Stage Contract (Section 5.2, seam-only)

This document is the canonical reference for the investigation stage
pipeline. Every change that adds, removes, or reorders a stage must
update this doc in the same commit. If you are adding logic to
`investigation-runner.ts`, stop and read this first — nine times out of
ten the change belongs in a stage module, not the runner.

> **Scope note (2026-04-11 amendment).** Sections 5.1 and 5.2 land the
> seam structure — named stage modules, the class-inheritance file
> split, the runtime invocation of each stage at its canonical
> boundary, and the 500-line coordinator budget on
> `investigation-runner.ts` — but the physical body moves of the
> assessment, focused-closure, and reporting code paths are deferred
> to Section 5.3 behind the fixture-campaign equivalence harness. The
> `FocusedClosureStage` actively applies the evidence-ref citation
> rule at runtime during 5.2; the `AssessmentReportingStage` is an
> active named seam that emits an `assessment_stage_seam` event. See
> the governance amendment in
> `sl-5.2-extract-stages-b-and-coordinator/spec.md`.

## The eight durable stages

The investigation runner walks a fixed pipeline of **eight** durable
stages, in this canonical order:

1. `static` — static investigation (scan, map, synthesize hypotheses)
2. `verification_packet_build` — packaging hypotheses for verification
3. `focused_lead_confirmation` — (Section 11.5) rank top leads, run
   persistent focused-worker sessions to pre-confirm or refute them
   before spending local-live / test-synthesis budget. Default-on at
   the runner level (commit `d32c033`); operator can disable via the
   stage's `enabled` constructor flag or skip it at resume time.
   Workers request probes through the orchestrator (identity ladder,
   mutation journal, rate limiting preserved). See
   [FOCUSED-LEAD-CONFIRMATION.md](./FOCUSED-LEAD-CONFIRMATION.md).
4. `local_live` — local live-replay verification lane
5. `test_synthesis` — test-synthesis verification lane
6. `focused_closure` — apply the evidence-ref citation rule to classify
   hypotheses into the `focused_list` (cites ≥1 source / probe / event
   ref) or the `unconfirmed_lead` bucket
7. `assessment` — executive campaign assessment (panel + synthesizer
   fallback) and final report rendering; the assessment and reporting
   stages always run together and share a context, so they live in a
   single stage module (`AssessmentReportingStage`) even though the
   `Stage` vocabulary lists them separately in the resume-at-stage
   contract
8. `reporting` — merged into the `assessment` stage module; see above

The stage names are the authoritative vocabulary used by
`--resume-at-stage`, the campaign state machine, the evidence event
stream, and the run report. They are declared in `./stages/contracts.ts`
as the `StageName` / `Stage` type alias and re-exported from
`./contracts.ts`.

## File layout

Each stage lives in its own module under
`packages/attack-lab/src/autonomous/stages/`:

| Stage | Module | Class |
| --- | --- | --- |
| `static` | `static-investigation.ts` | `StaticInvestigationStage` |
| `verification_packet_build` | `verification-packet-builder.ts` | `VerificationPacketBuilderStage` |
| `focused_lead_confirmation` | `focused-lead-confirmation.ts` | `FocusedLeadConfirmationStage` |
| `local_live` | `local-live.ts` | `LocalLiveStage` |
| `test_synthesis` | `test-synthesis.ts` | `TestSynthesisStage` |
| `focused_closure` | `focused-closure.ts` | `FocusedClosureStage` |
| `assessment` + `reporting` | `assessment-reporting.ts` | `AssessmentReportingStage` |

The runner itself lives in two files:

- `investigation-runner.ts` — the thin coordinator. Hard capped at **500
  non-blank non-comment lines**, enforced by
  `investigation-runner.line-count.test.ts`. Holds only: the public
  `InvestigationRunner` class, the public `run()` entrypoint, and the
  small set of type / function re-exports that the CLI and tests depend
  on.
- `investigation-runner-internals.ts` — `abstract class
  InvestigationRunnerInternals implements RunnerFriend`. Holds the
  pipeline implementation details and the `executeCampaignPipeline()`
  method that `InvestigationRunner.run()` delegates to. The seam is a
  class-inheritance boundary so the `RunnerFriend` interface contract
  (needed by the extracted stage modules) is implemented exactly once.

## The `Stage` interface

Every stage module exports a class implementing:

```ts
export interface Stage {
  readonly name: StageName;
  run(context: StageContext): Promise<StageResult>;
}
```

`StageContext` bundles the long-lived campaign state and the shared
services the stage needs — memory, state, state store, evidence store,
target profile, config, adapter bundle, security runtime, run mode,
role session store, response archiver, telemetry accumulator, campaign
directory, and the `runner` friend handle. A stage reads and writes
`memory` and `state` directly; the shapes are the same as in the
pre-5.2 monolithic runner so behavior is bit-identical across the
extraction boundary.

`StageResult` is the minimal per-stage report handed back to the
pipeline driver:

```ts
export interface StageResult {
  stage: StageName;
  outcome: 'complete' | 'degraded' | 'incomplete' | 'blocked';
  events: StageEmittedEvent[];
  coverageGaps: CoverageGap[];
  metadata: Record<string, unknown>;
}
```

The `outcome` vocabulary is a strict subset of `ExecutionStatus`. No
stage may invent a new value. During Section 5.2, most stages still
emit directly through `context.evidenceStore.appendEvent()` and leave
`events` empty, but the `events` field is in place so future extracted
bodies can accumulate events and let the pipeline driver flush them.

## The `RunnerFriend` interface

Stage modules never touch runner private state. When a stage needs to
call back into runner logic during the 5.2 seam (for example, to
invoke the local-live lane body that still lives in the runner), it
does so through the typed `RunnerFriend` interface declared in
`./stages/contracts.ts`. Every friend method on `RunnerFriend` is
implemented by `InvestigationRunnerInternals` as a public method with
a `Friend` suffix, and each friend method is a narrow hole — no
general-purpose accessors. If a stage needs more runner state, add a
new named friend method rather than widening the interface ad-hoc.

## Adding a new stage

1. Pick the canonical `name` and add it to the `Stage` / `StageName`
   vocabulary in `autonomous/contracts.ts` if it is new.
2. Create a module under `autonomous/stages/<name>.ts` exporting a
   class that implements the `Stage` interface.
3. If the stage needs new runner-private state, add a narrow friend
   method to `RunnerFriend` in `stages/contracts.ts` and implement it
   on `InvestigationRunnerInternals`.
4. Instantiate the stage in
   `InvestigationRunnerInternals.getExtractedStagePipeline()` so the
   resume-at-stage contract and the behavior-equivalence test can
   enumerate it.
5. Add unit tests alongside the module
   (`stages/<name>.test.ts`) and extend
   `stages/behavior-equivalence.test.ts` to cover the new stage in the
   golden event sequence.
6. Update this document and `CLAUDE.md` in the same commit.

## What does NOT belong in `investigation-runner.ts`

- Stage implementations
- Helper functions used by stage bodies
- Data types owned by a specific stage
- Anything that would push the file over the 500-line budget

The 500-line budget is the architectural guardrail. If a change would
push the runner over budget, that change belongs in
`investigation-runner-internals.ts` or a stage module. Raising the
budget requires a governance amendment to SL6 and this document.
