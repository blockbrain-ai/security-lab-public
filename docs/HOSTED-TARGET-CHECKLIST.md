# Hosted Target Checklist

> Status: hosted verification is the **next technical phase** of the Security Lab programme.
> Serious-local verification is proven and complete. No hosted campaign has yet been
> executed through the standalone project as the canonical path. This checklist exists
> so that the first hosted run starts from a clean, explicit operational contract.

This document is the pre-flight checklist for hosted verification. Every item must
be satisfied before a hosted campaign is launched. If any item cannot be satisfied,
the campaign must not proceed — there is no "best effort" mode for hosted work.

---

## 1. Target Environment Prerequisites

A hosted target is a staging or explicitly authorized externally reachable environment.
Production environments are **never** the default target and require separate governance
(see Section 6 below).

### 1.1 Stable Base URL

- [ ] The target has a stable, resolvable base URL (e.g. `https://staging.example.com`)
- [ ] The URL does not rotate, require VPN tunnelling, or depend on ephemeral infrastructure
      unless the operator has confirmed availability for the campaign window
- [ ] The URL is recorded in the hosted target profile's `baseUrl` field

### 1.2 Healthcheck Endpoint

- [ ] The target exposes a healthcheck endpoint (e.g. `/health`, `/api/health`, `/readyz`)
- [ ] The healthcheck returns a 2xx response when the target is operational
- [ ] The healthcheck endpoint is listed in the target profile's `ingressChecks` section
- [ ] The operator has manually confirmed the healthcheck responds before campaign start

### 1.3 Authentication Mechanism

- [ ] The target's auth mechanism is documented (IAP, bearer token, session cookie, API key, etc.)
- [ ] Auth credentials for each identity tier are available and stored in environment variables
- [ ] The target profile's `authSources` section maps each identity to its credential source
- [ ] No credential is hardcoded in the target profile — all use `env:VARIABLE_NAME` references

### 1.4 Test Identities

Every identity used in a hosted campaign must be a **canary identity** — a dedicated
test account that exists solely for security verification. Real user accounts are
never used.

- [ ] At least one unauthenticated identity (guest) is defined
- [ ] At least one authenticated canary identity is defined with `isCanary: true`
- [ ] Each identity has explicit `forbiddenBoundaries` documenting what it must not access
- [ ] Each identity has `allowInHosted: true` in the target profile
- [ ] Canary identities do not share credentials with real users or service accounts
- [ ] The operator has verified that canary identities can authenticate successfully

### 1.5 Safe Canaries and Rollback Plan

Hosted probes can create, modify, or delete state in the target. The campaign must
have a plan for reverting any mutations.

- [ ] Canary resources (test tenants, seed data, throwaway records) are identified
- [ ] The target profile's `rollback` section specifies a rollback strategy:
  - `api_cleanup` — automated API calls to remove seed data (preferred)
  - `manual` — operator performs cleanup after the campaign
  - `ephemeral_environment` — the entire environment is torn down after the campaign
- [ ] If `api_cleanup` is used, the cleanup commands are tested independently before the campaign
- [ ] If `manual` is used, the cleanup steps are documented and assigned to a named operator

### 1.6 Rate Limits and Stop Conditions

- [ ] The target profile's `rateLimit` section specifies:
  - `requestsPerSecond` — maximum sustained request rate (default: 1 req/sec)
  - `maxRequestsPerCampaign` — hard cap per campaign run (default: 100)
  - `maxRequestsPerDay` — hard daily cap across all runs (default: 500)
- [ ] A `cooldownSeconds` value is set between request bursts
- [ ] The operator has confirmed the target's infrastructure can sustain the configured rate
      without triggering WAF blocks, auto-scaling charges, or alerting noise
- [ ] Stop conditions are explicit: if the healthcheck fails mid-campaign, the campaign halts

---

## 2. Security Lab Preconditions

### 2.1 Doctor Passing

- [ ] `npm run doctor -- --preset serious-end-to-end --target ... --hosted-target ...` passes with no errors
- [ ] All required CLI tools are available (node, npm, tsc; optionally claude, codex, docker)
- [ ] All required API keys are set in the environment

### 2.2 Serious Profile Selected

Hosted campaigns require the `serious-end-to-end` run mode. Smoke mode does not
support hosted verification.

- [ ] The campaign will be launched with `--run-mode serious-end-to-end`
- [ ] The `serious_end_to_end` portfolio profile is available and loadable
- [ ] The operator understands that serious-end-to-end fails closed on missing hosted coverage

### 2.3 Hosted Auth Source Configured

- [ ] The `.env.security-lab.local` file contains all credential environment variables
      referenced by the target profile's `authSources`
- [ ] Each credential has been tested manually (e.g. a `curl` to the healthcheck with the token)
- [ ] Credentials are not expired, revoked, or rate-limited independently

### 2.4 Approval for Write-Capable Probes

By default, hosted campaigns operate in **read-only mode**. Write-capable probes
(mutations, deletions, state changes) require explicit operator approval.

- [ ] The operator has decided whether write-capable probes are authorized
- [ ] If authorized, the `--authorize-hosted` flag will be passed at campaign start
- [ ] If write-capable hosted probes are authorized, `--allow-hosted-mutations` will also be passed
- [ ] If authorized, the rollback plan (Section 1.5) is verified and ready
- [ ] If not authorized, the campaign is constrained to read-only probes

---

## 3. Do-Not-Run Conditions

The following conditions mean hosted verification **must not proceed**. These are
hard stops, not warnings.

| Condition | Reason |
|-----------|--------|
| No stable base URL | The campaign cannot target an environment that may disappear mid-run |
| Healthcheck fails | The target is not operational; probes would produce false negatives |
| Canary identities are missing | Real user accounts must never be used for security probing |
| Credentials are expired or untested | Auth failures would corrupt campaign results |
| No rollback plan for write probes | Mutations without cleanup leave the target in an unknown state |
| Rate limits are not configured | Unbounded probing can degrade the target for other users |
| Doctor does not pass | Missing prerequisites will cause mid-campaign failures |
| Operator has not reviewed the target profile | The campaign must be a deliberate act, not an accident |
| The target is a production environment without explicit governance approval | Production is never the default |

---

## 4. Target Profile Structure Reference

A hosted target profile extends a static or local-live profile and adds hosted-specific
sections. The canonical structure (see existing profiles in `packages/attack-lab/targets/`):

```yaml
id: <target>-staging-hosted
name: "<Target> Staging (Hosted)"
extends: <target>-static.yaml
kind: http
environment: hosted_authorized

baseUrl: https://staging.example.com

authSources:
  anonymous: null
  user_a_iap:
    type: bearer
    source: env:TARGET_USER_A_TOKEN

hostedIdentities:
  - name: guest
    authSource: anonymous
    isCanary: true
    allowInHosted: true
    forbiddenBoundaries: [any_protected_route]
  - name: user_a_canary
    authSource: user_a_iap
    isCanary: true
    allowInHosted: true
    forbiddenBoundaries: [tenant_b_resource, admin_action]

ingressChecks:
  - name: health_reachable
    method: GET
    path: /health
    expectedStatus: 200
  - name: auth_enforced
    method: GET
    path: /api/protected
    expectedStatus: [401, 403]

rateLimit:
  requestsPerSecond: 1
  maxRequestsPerCampaign: 100
  maxRequestsPerDay: 500
cooldownSeconds: 2

rollback:
  strategy: manual
  steps:
    - "Delete seed data created during the campaign"
    - "Verify canary accounts are in clean state"
```

For full target profile documentation, see [TARGET-ONBOARDING.md](TARGET-ONBOARDING.md).

---

## 5. Checklist Execution Flow

```
1. Operator selects hosted target profile
2. Walk through Section 1 (target prerequisites) — all items checked
3. Walk through Section 2 (Security Lab preconditions) — all items checked
4. Review Section 3 (do-not-run conditions) — no conditions match
5. Proceed to HOSTED-VERIFICATION-PLAYBOOK.md for execution
```

If any item in Sections 1-2 cannot be checked, or any condition in Section 3 matches,
the campaign does not proceed. The operator documents the blocker and either resolves it
or defers hosted verification.

---

## 6. Production Targeting Governance

Production environments are explicitly out of scope for default hosted verification.
If production targeting is ever considered:

- A separate governance review is required beyond this checklist
- The review must include stakeholders beyond the Security Lab operator
- Read-only constraints must be enforced with no exception path in the initial campaign
- The campaign must be time-boxed and monitored in real time
- This checklist does not authorize production campaigns — it is necessary but not sufficient

---

## Related Documents

- [HOSTED-VERIFICATION-PLAYBOOK.md](HOSTED-VERIFICATION-PLAYBOOK.md) — execution playbook for the first hosted campaign
- [OPERATOR-GUIDE.md](OPERATOR-GUIDE.md) — general operator workflow and CLI reference
- [END-TO-END-RUNBOOK.md](END-TO-END-RUNBOOK.md) — serious-local execution guide
- [TARGET-ONBOARDING.md](TARGET-ONBOARDING.md) — target profile creation and structure
- [FINDINGS-AND-TRIAGE.md](FINDINGS-AND-TRIAGE.md) — finding classification and triage
- [REMEDIATION-PLAYBOOK.md](REMEDIATION-PLAYBOOK.md) — remediation decision framework
