# Provider Effort Mapping

All Security Lab `ModelAdapter.invoke()` calls accept an `effort: 'low' | 'medium' | 'high' | 'max'` hint. Each provider interprets this differently — the adapter normalises the caller's intent, so callers do not need provider-specific strings.

| Security Lab effort | Anthropic (API) | OpenAI (API) | Gemini (API) | Claude Code (CLI) | Codex CLI |
|---|---|---|---|---|---|
| `low` | `extended_thinking: false`, modest `max_tokens` | default, short completion | default | `--thinking none` equivalent | `effort: low` |
| `medium` | `extended_thinking: brief`, normal `max_tokens` | normal | normal | default | `effort: medium` |
| `high` | `extended_thinking: full`, generous `max_tokens` | higher `max_completion_tokens` / reasoning | higher | `--thinking on` equivalent | `effort: high` |
| `max` | maximum thinking budget | maximum reasoning | maximum | maximum | `effort: xhigh` (see below) |

## The Codex `xhigh` mapping

Codex CLI's effort enum is `{none, minimal, low, medium, high, xhigh}`. Security Lab's vocabulary stops at `max`. The adapter maps `max → xhigh` (commit `76bd362`, file `codex-cli-adapter.ts:~85`). Callers do **not** pass `'xhigh'` directly — the adapter is the only place the mapping lives, and tests enforce it.

If you see `xhigh` in a raw Codex invocation log, that corresponds to `effort: 'max'` at the Security Lab layer.

## Cost implications

Higher effort levels increase latency and token usage; they do **not** correlate linearly with quality. Observed pattern (from campaign telemetry):

- **Planner / counter-planner:** benefits from `high` or `max` on hard targets; diminishing returns on trivial ones.
- **Judge:** `medium` is almost always enough. Judges are ensembled (2–3 members in `judge-panel.ts`), so raising per-judge effort multiplies cost.
- **Synthesizer / reporter:** `high` — these roles compose long-form output and benefit from reasoning depth.
- **Focused confirmation workers:** `medium` to `high`. These workers run many iterative turns; each turn's effort compounds.

## Where this is enforced

- `packages/attack-lab/src/providers/contracts.ts` — `InvokeOptions.effort` type.
- `packages/attack-lab/src/providers/codex-cli-adapter.ts` — `max → xhigh` translation.
- `packages/attack-lab/src/providers/claude-code-adapter.ts` — Claude Code equivalent.
- Portfolio profiles (`packages/attack-lab/src/orchestration/profiles/*.ts`) set per-role effort defaults that the runner resolves before invocation.
