# Portfolio Profiles

Portfolio profiles declare which model fills which role during an investigation (planner, counter-planner, judge, judge panel, synthesizer, reporter) plus the budget ceiling and escalation triggers. They live in `packages/attack-lab/src/orchestration/portfolio-profiles.ts`.

## Role-to-provider rationale

Some roles benefit from direct file/runtime access; others only need bounded reasoning. The serious-path profiles assign roles with those two needs in mind.

| Role | Provider class | Why |
| --- | --- | --- |
| Planner (primary investigator) | CLI worker with file access | Needs to read source, follow chains through middleware, and reason over the actual repo |
| Counter-planner | CLI worker with file access (different vendor) | Different viewpoint on the same evidence base |
| Judge | API model | Bounded arbitration; no filesystem access required |
| Judge panel | Mixed API + CLI reviewer seats | Multi-vendor arbitration for critical/disputed findings without depending on Anthropic API keys |
| Synthesizer | CLI worker with file access | Must read cited evidence files to validate provenance |
| Reporter | CLI worker with file access | Must read source to render `file:line` references |

CLI workers (Claude Code, Codex CLI) can spawn shell commands, mutate scratch files, and traverse directories. API models cannot — but arbitration does not need that; it needs independent reasoning.

## Serious-path profiles

### `serious_local`

- **Planner**: `claude_code` / `claude-opus-4-6` — deep repo exploration
- **Counter-planner**: `codex_cli` / `gpt-5.4` — counter viewpoint with the same file-access tooling
- **Local-live planner**: `codex_cli` / `gpt-5.4` (max effort) — highest-effort runtime probing once live evidence starts flowing
- **Local-live counter**: `claude_code` / `claude-opus-4-6` — deeper selective review for cross-boundary or disputed live rounds
- **Judge**: `openai` / `gpt-5.4` — API arbitration
- **Judge panel**: `[openai/gpt-5.4, claude_code/claude-opus-4-6]` — multi-vendor panel on critical findings without requiring Anthropic API auth
- **Synthesizer**: `claude_code` / `claude-opus-4-6` — re-reads evidence files when reconciling the panel
- **Reporter**: `claude_code` / `claude-opus-4-6` — emits `file:line` references from the source
- **Budget ceiling**: $60

### `serious_end_to_end`

Same role assignments as `serious_local`, raised budget ceiling ($100) for runs that also exercise hosted probes. The role assignment is inherited from `serious_local` via object spread, so a single update keeps both profiles consistent.

## Preflight requirement

If any of the CLI workers declared by a serious profile is unavailable on the machine (binary not on PATH), the preflight doctor fails the run before any budget is spent. The serious path is fail-closed on its declared worker set.

## Non-serious profiles

`balanced`, `cost_sensitive`, `production`, and `ultimate` keep their API-only assignments. The worker-contract rewrite at §4.1 did not change them — only the two `serious_*` profiles need CLI workers for file-access roles.

## Related

- `packages/attack-lab/src/providers/worker-contract.ts` — the minimal two-rule worker contract
- `CLAUDE.md` Conventions — references this file
- `the engineering standards` SL2 — governance rule on not re-tightening worker-side restrictions
