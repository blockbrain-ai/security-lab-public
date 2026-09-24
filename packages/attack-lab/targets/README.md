# Target profiles

A target profile is a small YAML file that tells Security Lab what to scan and how it may probe it. Copy one of the starter templates and fill in the placeholders — no TypeScript changes are required.

| Template | Use it for |
|---|---|
| `example-http.yaml` | A web application: static scan **and** live HTTP probing against a running instance |
| `example-code.yaml` | Static source scanning only (no live probes) |
| `example-dependency.yaml` | Supply-chain / dependency manifest scanning |

Every field is documented inline in the templates, and [../docs/TARGET-ONBOARDING.md](../../docs/TARGET-ONBOARDING.md) walks through the full specification: environment tiers, identities, canaries, route roots, overlays, live-probing limits and rollback.

Two conventions worth knowing up front:

- **Environment tier controls what is allowed.** `fixture` and `sandbox` are permissive; `staging`, `hosted_authorized` and `production_shadow` progressively restrict methods, bodies and shell-adjacent probes. Declare the real tier — it is the safety contract, not a label.
- **Never hardcode credentials in a profile.** Reference environment variables (`tokenEnv`, `cookieValueEnv`, `repoRootEnv`) so the profile can be shared.

> **Authorised use only.** A profile is a statement of intent about a system: declare only targets you own or have explicit written authorisation to test, at the environment tier that matches reality. Mis-declaring the tier is how a run escapes its scope. See [Authorised use only](../../README.md#authorised-use-only).
>
- **Shell-executing targets declare an allow-list.** For `kind: shell` (and any target whose probes run commands), `allowedShellCommands` lists the permitted binaries and `allowShellInterpreters: true` acknowledges an interpreter on that list. Without an allow-list, shell probes are refused.

> Profiles are trusted input: they can declare commands that run on your machine (lifecycle hooks, sidecars). Only use profiles you have reviewed.
