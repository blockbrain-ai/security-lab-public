# Target Onboarding Guide

This guide walks you through adding a new target to Security Lab. No TypeScript code changes are required — onboarding is a documentation exercise: copy a starter template, fill in 6-10 fields, and run.

## 1. What Is a Target Profile?

A target profile is a YAML file that tells Security Lab everything it needs to know about the software you want to investigate: where the code lives, what kind of scanning to do, how to authenticate, and what probes are allowed. Target profiles live in `packages/attack-lab/targets/` and are loaded by the investigation runner at campaign start.

## 2. Choosing a Starter Template

Security Lab ships three starter templates. Pick the one that matches your use case:

```
Do you have a running instance to probe?
├── Yes → example-http.yaml    (HTTP live probing + code scanning)
└── No
    ├── Want full code analysis? → example-code.yaml    (static scanning only)
    └── Only need supply-chain checks? → example-dependency.yaml    (dependency scanning)
```

| Template | Kind | Live probing | Code scanning | Dependency scanning |
|----------|------|:---:|:---:|:---:|
| `example-http.yaml` | `http` | Yes | Yes | Yes |
| `example-code.yaml` | `code` | No | Yes | Yes |
| `example-dependency.yaml` | `dependency` | No | No | Yes |

Copy the template to a new file:

```bash
cp packages/attack-lab/targets/example-code.yaml packages/attack-lab/targets/my-project.yaml
```

## 3. Required Fields

Every target profile needs these fields filled in. The rest can stay commented out or use defaults.

### All targets (6 fields minimum)

| Field | Description | Example |
|-------|-------------|---------|
| `id` | Unique kebab-case identifier | `my-project-static` |
| `name` | Human-readable label for reports | `My Project (Static Analysis)` |
| `description` | One-paragraph explanation | `Static security scan of the API layer.` |
| `kind` | `http`, `code`, or `dependency` | `code` |
| `environment` | `sandbox`, `local_live`, `staging`, `hosted_authorized`, etc. | `sandbox` |
| `repoRoot` | Absolute path to the source code | `/home/user/projects/my-app` |

You can use `repoRootEnv` instead of `repoRoot` to read the path from an environment variable (e.g. `repoRootEnv: MY_APP_ROOT`).

### HTTP targets (additional required fields)

| Field | Description | Example |
|-------|-------------|---------|
| `baseUrl` | URL of the running instance | `http://localhost:3000` |

### Dependency targets

No additional required fields beyond the base six. The scanner automatically detects manifest files (`package.json`, `requirements.txt`, `go.mod`, `Cargo.toml`, `pom.xml`, `build.gradle`) in the `repoRoot`.

## 4. Optional Fields

These fields let you customise scanning behavior. None are required for a first run.

### Scoping

| Field | Purpose |
|-------|---------|
| `includePaths` | Limit scanning to these directories (e.g. `[src/, lib/]`) |
| `excludePaths` | Skip these directories (e.g. `[dist, coverage, node_modules]`) |
| `routeRoots` | Where to look for HTTP route definitions |
| `searchRoots` | Where to search for auth/config/persistence surfaces |
| `maxRoutes` | Cap the number of routes extracted (default: unlimited) |
| `maxFiles` | Cap the number of files scanned (default: unlimited) |

### Overlay

An overlay adds programme-specific knowledge the scanner can't discover on its own. It can be an inline object or a path to a separate YAML file:

```yaml
overlay:
  highValuePatterns:
    - "$queryRaw"
    - eval(
  trustBoundaries:
    - from: external_untrusted
      to: public_api
      mechanism: rate limiting + input validation
  vulnerabilityFamilies:
    - family: injection
      description: SQL injection via user input
      priority: critical
      checkLocations:
        - src/db/queries/
```

### Identity ladder

For HTTP targets with live probing, define identities to test privilege escalation:

```yaml
identities:
  - id: anonymous
    label: Anonymous user
  - id: regular
    label: Regular user
    credentials:
      email: test@example.com
      password: test-password
  - id: admin
    label: Admin user
    credentials:
      email: admin@example.com
      password: admin-password
```

### Canaries

Canary requests validate that the probe infrastructure is working before real probes begin:

```yaml
canaries:
  - id: health
    description: Verify the app responds
    request:
      method: GET
      path: /health
    expectedStatus: 200
```

### Rate limits

```yaml
liveProbing:
  rateLimit:
    requestsPerSecond: 5
    burstSize: 10
```

### Auth mechanism

```yaml
authMechanism:
  tenantHeader: x-tenant-id
```

### Verification policy

```yaml
strictVerification: true
requiredLanes:
  - test-synthesis
  - local-live
testSynthesis:
  timeoutMs: 120000
```

## 5. Running Your First Campaign

Once your target profile is ready, run the investigator:

```bash
# Static analysis (code or dependency targets)
npm run investigate -- --target targets/my-project.yaml

# With a specific mode
npm run investigate -- --target targets/my-project.yaml --mode declared

# Resume a previous campaign
npm run investigate -- --resume <campaignId>

# Resume at a specific stage
npm run investigate -- --resume <campaignId> --resume-at-stage verification_packet_build
```

### Choosing a run mode

Run mode is separate from `--mode declared|blind` and controls how the runner
reacts to missing verification coverage:

- `--run-mode smoke` (default) — low-ceremony. Missing prerequisites lower the
  report to `executionStatus: degraded` and the run still exits 0. Use for
  exploratory scans and early onboarding.
- `--run-mode serious-local` — fails closed with `executionStatus: incomplete`
  and a non-zero exit code when a required local-live lane is missing identities
  or source coverage. Use when you need to trust the result.
- `--run-mode serious-end-to-end` — as above, but also fails closed on missing
  hosted verification coverage. Use when hosted verification is mandatory.

For CI environments that prefer to parse the report instead of checking exit
codes, add `--exit-zero-on-incomplete`. The operator still sees the
`incomplete` status in the report.

The campaign output goes to `data/campaigns/<campaignId>/` and includes:
- `events.jsonl` — structured event log
- `report.md` — human-readable findings report
- `state.json` — resumable campaign state
- `model-responses/` — archived model interactions

## 6. What Security Lab Can and Can't Do for Non-Node Stacks

Security Lab's scanner was built for Node.js codebases. When you point it at a non-Node target (Python, Go, Rust, Java), the scanner honestly reports what it can and can't do.

### Coverage classification

Every scan returns a `coverage` field:

| Coverage | Meaning |
|----------|---------|
| `full` | Node.js stack detected. Routes, auth, config, persistence, and dependencies all parsed. |
| `partial` | Non-Node stack detected. Dependencies parsed from manifest files. No route extraction or auth detection. |
| `manifest-only` | Manifest files detected but no dependencies could be parsed. |
| `none` | No recognizable stack or manifest files found. |

### What works for non-Node targets

- **Dependency scanning**: The scanner parses `requirements.txt`, `pyproject.toml` (Python), `go.mod` (Go), `Cargo.toml` (Rust), `pom.xml` and `build.gradle` (Java) to extract dependency lists with risk indicators.
- **Code reading**: The investigation planner can still read source files and reason about them.
- **Overlay-driven analysis**: If you provide an overlay with trust boundaries and vulnerability families, the planner uses this as investigation input regardless of stack.

### What doesn't work for non-Node targets

- **Route extraction**: Only Node.js HTTP frameworks (Express, Fastify, Next, Hono) have route pattern matching.
- **Auth surface detection**: Only Node.js auth patterns (middleware, JWT, session) are recognized.
- **Config extraction**: Only `.env`, `config.json`, and `config.yaml` are scanned.
- **Persistence detection**: Only Prisma schemas and Node.js raw SQL patterns are detected.

### Recommended approach for non-Node targets

1. Use the `example-dependency.yaml` template for supply-chain scanning.
2. Add detailed `hints` about your stack, entry points, and auth surfaces so the planner has context.
3. Use an `overlay` to declare trust boundaries and vulnerability families the scanner can't discover.
4. Check the report's coverage section — it will explicitly state what was and wasn't scanned.

## 7. FAQ

**Q: Do I need to edit any TypeScript to add a new target?**
A: No. Target onboarding is entirely YAML-driven. Copy a starter template, fill in the fields, and run.

**Q: Can I extend one target profile from another?**
A: Yes. Use the `extends` field to inherit from a base profile:
```yaml
extends: ./base-profile.yaml
id: my-variant
environment: staging
baseUrl: https://staging.example.com
```

**Q: Where should I put my target profile?**
A: In `packages/attack-lab/targets/`. The runner also searches the current directory and the security-lab root, but `targets/` is the conventional location.

**Q: How do I know if the scanner understood my target?**
A: Check the coverage classification in the report header. `full` means everything was parsed. `partial` means only dependencies. The report also lists `supportedProbeKinds` so you can see exactly what probes are available.

**Q: Can I disable a specific manifest parser?**
A: Yes. Set the `DISABLED_MANIFEST_PARSERS` environment variable to a comma-separated list of parser names to disable (e.g. `DISABLED_MANIFEST_PARSERS=rust,java`).

**Q: What environments are available?**
A: `fixture` (lab's own fixtures), `sandbox` (isolated test), `local_live` (local running instance), `staging` (pre-production), `hosted_authorized` (production with explicit authorization), `production_shadow` (read-only production).

**Q: How do I add custom vulnerability families?**
A: Use the `overlay` field with a `vulnerabilityFamilies` array. Each family has a name, description, priority, and optional check locations.

**Q: What's the difference between `includePaths` and `routeRoots`?**
A: `includePaths` limits the overall scan scope. `routeRoots` specifically tells the route extractor where to look for HTTP route definitions. Use both for large repos.

**Q: Can I scan a monorepo?**
A: Yes. Set `repoRoot` to the monorepo root and use `includePaths` to scope the scan to relevant packages. You can also create multiple target profiles for different packages in the same monorepo.

**Q: How do I test that my profile loads correctly?**
A: Run `npm run investigate -- --target targets/my-profile.yaml` — the runner validates the profile on startup and will report any schema errors immediately.
