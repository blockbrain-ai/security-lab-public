# Security Lab — Remediation Playbook

> **Audience**: operators and engineering leads converting Security Lab results into engineering action.
> **Prerequisite**: read the [Findings Interpretation and Triage Guide](./FINDINGS-AND-TRIAGE.md) first. This playbook assumes you understand finding classes, `executionStatus`, and evidence hierarchy.
> **Principle**: use evidence, not narrative strength, as the primary decision input.

---

## 1. The Remediation Decision Ladder

Every finding from a Security Lab campaign maps to one of four remediation actions. The mapping is determined by finding class and severity — not by how alarming the description sounds.

### 1.1 Decision Ladder

| Action | When to Use | Timeline |
|---|---|---|
| **Ignore / Note** | Suppressed claims, refuted hypotheses, unconfirmed leads with low plausibility | No engineering work. Note in the campaign log for future reference. |
| **Backlog** | Validated architectural risks (medium/low severity), configuration risks with verified-safe production config, unconfirmed leads with high plausibility | Add to engineering backlog. Fix in normal development cycle. |
| **Patch Before Release** | Validated architectural risks (high/critical severity), configuration risks with uncertain production config, confirmed exploits (low/medium severity) | Fix before the next release. Does not block current development. |
| **Block Release** | Confirmed exploits (high/critical severity), confirmed supply-chain risks with active exposure | Stop the release pipeline. Fix, verify, then unblock. |

### 1.2 Decision Flowchart

```
Is the finding confirmed by mechanical evidence (probe or source ref)?
├── Yes → Is severity critical or high?
│   ├── Yes → BLOCK RELEASE
│   └── No  → PATCH BEFORE RELEASE
└── No  → Is it a validated architectural risk with source refs?
    ├── Yes → Is severity critical or high?
    │   ├── Yes → PATCH BEFORE RELEASE
    │   └── No  → BACKLOG
    └── No  → Is it an unconfirmed lead?
        ├── Yes → Is it independently plausible and on an exposed surface?
        │   ├── Yes → BACKLOG (with follow-up investigation)
        │   └── No  → IGNORE / NOTE
        └── No  → IGNORE / NOTE (suppressed claim or refuted)
```

### 1.3 Severity Override Rules

- A **critical** unconfirmed lead does not automatically escalate to "patch before release." Unconfirmed means unconfirmed. If the lead is critical enough to worry about, schedule a follow-up investigation to confirm or refute it.
- A **low** confirmed exploit still requires a fix. Confirmed means the system demonstrated exploitable behavior. The severity determines timeline (backlog vs patch before release), not whether to fix it.

---

## 2. Converting Findings Into Engineering Work

### 2.1 Confirmed Vulnerability → Bug / Security Issue

**What to file**:

```
Title:  [Security] <description from finding>
Severity: <severity from finding>
Evidence: <list evidenceRefs — source locations and/or probe results>

Reproduction:
<reproductionSteps from finding, verbatim>

Suggested fix:
<remediationSuggestion from finding>

Source: Security Lab campaign <campaignId>, finding <findingId>
```

**Rules**:
- Copy `reproductionSteps` and `evidenceRefs` verbatim from the finding. Do not paraphrase evidence.
- Include the `campaignId` so the fix can be verified by a rerun.
- Tag the issue as a security finding, not a feature request.
- If the finding has `sourceLocationRefs`, link directly to the relevant code.

### 2.2 Validated Architectural Risk → Engineering Task

**What to file**:

```
Title:  [Hardening] <description from risk>
Severity: <severity from risk>
Evidence: <sourceLocationRefs from risk>
Conditions: <requiredConditions — what must be true for this risk to matter>

Context:
Security Lab identified this as a validated architectural risk — a code pattern
that creates attack surface. No exploit was confirmed, but the code evidence
supports the risk assessment.

Suggested approach:
<description from risk, plus any remediation guidance>

Source: Security Lab campaign <campaignId>
```

**Rules**:
- Frame as a hardening task, not a bug. The system is not broken — it has a weakness.
- Include `requiredConditions` so the engineer understands when the risk applies.
- Do not describe it as "a vulnerability found by Security Lab." It is a validated risk, not a confirmed exploit.

### 2.3 Configuration Risk → Configuration Verification Task

**What to file**:

```
Title:  [Config] Verify <description of configuration-dependent risk>
Severity: <severity from risk>

Action items:
1. Verify production configuration does not enable the risky state
2. Add startup validation or deployment check if the dangerous config is easy
   to reach accidentally
3. Document the safe configuration in the deployment runbook

Source: Security Lab campaign <campaignId>
```

**Rules**:
- The first action is always "verify production config." If production is already hardened, the risk may resolve to a documentation task.
- Do not patch code to remove a feature that is safe when configured correctly — add guardrails instead.

### 2.4 Unconfirmed Lead → Follow-Up Investigation

**What to file** (only if independently plausible):

```
Title:  [Investigate] <description of lead>
Priority: low (unless independently verified)

Context:
Security Lab generated this as an unconfirmed lead. No mechanical evidence
supports it. It warrants investigation if the attack surface is exposed and
the hypothesis is plausible.

Next steps:
1. Manual code review of the area described in the lead
2. If plausible, configure a targeted Security Lab rerun to verify
3. If confirmed by manual review or rerun, file as a separate finding

Source: Security Lab campaign <campaignId>, unconfirmed lead
```

**Rules**:
- Do not file an unconfirmed lead as a bug. File it as an investigation task.
- Set priority to low unless you have independent reason to believe the lead is real.
- If the lead is implausible or the attack surface is not exposed, do not file anything — just note it in the campaign log.

---

## 3. How to Avoid Overreacting

### 3.1 The Overreaction Checklist

Before escalating any Security Lab result, verify:

- [ ] **Is the finding confirmed?** Check `evidenceRefs` for probe results or source locations. If neither exists, it is an unconfirmed lead.
- [ ] **Am I reading the right section?** Confirmed vulnerabilities, validated risks, and unconfirmed leads are in separate lists. Do not mix them.
- [ ] **Am I using evidence or narrative?** The description may sound alarming. Check the `evidenceRefs` — they are the ground truth.
- [ ] **Does the severity match the evidence?** A "critical" finding with only a vague `SourceLocationRef` and no probe evidence is likely an architectural risk, not a confirmed exploit.
- [ ] **Is `executionStatus` affecting my read?** An `incomplete` run does not mean the tool failed or that findings are unreliable. It means some areas were not covered.

### 3.2 Common Misreadings

| What You See | Wrong Conclusion | Right Conclusion |
|---|---|---|
| "SQL injection vulnerability" in unconfirmed leads | "We have a SQL injection!" | A model hypothesized SQL injection but no probe confirmed it. Investigate manually if the code area handles user input. |
| Architectural risk with `critical` severity | "This is a critical vulnerability!" | The code pattern is high-risk, but no exploit was demonstrated. Prioritize the fix but do not treat it as an active incident. |
| 0 confirmed findings, 5 architectural risks | "Security Lab found nothing" | Security Lab found 5 validated code weaknesses. They should enter the backlog. |
| `incomplete` execution status | "The results are unreliable" | Findings from completed lanes are reliable. The "incomplete" status means some lanes did not run — check coverage gaps. |
| High number of unconfirmed leads | "We have many potential vulnerabilities" | The model generated many hypotheses. Most are noise. Only act on leads you can independently verify. |

### 3.3 The the target application Example: What to Fix vs. What to Monitor

The the target application serious-local campaign produced:

- **0 confirmed exploits**: no probe replicated an attack. This is a positive signal — the running system defended against automated probing.
- **Several validated architectural risks**: code patterns like unsanitised inputs, missing rate limiting, and incomplete access control checks. These are backed by `SourceLocationRef` evidence pointing to specific code.
- **Unconfirmed leads**: model-generated hypotheses about potential attack chains.

**Correct remediation plan**:

| Category | Action | Priority |
|---|---|---|
| Validated architectural risks (critical/high) | File as hardening tasks, patch before next release | High |
| Validated architectural risks (medium/low) | File as hardening tasks in engineering backlog | Normal |
| Configuration risks | Verify production config is hardened | Normal |
| Unconfirmed leads | Review for plausibility, investigate the most credible ones | Low |
| "0 confirmed exploits" | Celebrate cautiously — but do not ignore the architectural risks | — |

**Incorrect remediation plan**:

- Filing all unconfirmed leads as security bugs
- Emergency-patching architectural risks as if they were active exploits
- Declaring the target application "fully secure" because no exploit was confirmed
- Ignoring all results because "nothing was actually exploited"

---

## 4. Running a Verification Rerun After Fixes

After fixing findings, rerun the campaign to verify the fixes and compare results.

### 4.1 Rerun Process

```bash
# 1. Apply fixes in the target codebase

# 2. Rerun Security Lab against the same target profile
npm run investigate -- --target targets/<target>.yaml \
  --run-mode serious-local \
  --live-target targets/<target>-local-live.yaml

# 3. Compare the new campaign output with the original
```

### 4.2 What to Compare

| Check | How |
|---|---|
| **Fixed finding resolved?** | The original finding should no longer appear in `confirmedVulnerabilities` or `validatedRisks` |
| **No regressions?** | No new findings appeared that were not in the original campaign |
| **Execution status** | The rerun should be `complete` — if it is `incomplete`, the comparison is not valid for missing lanes |
| **Coverage** | The rerun should cover at least the same lanes as the original |

### 4.3 Interpreting Comparison Results

| Scenario | Meaning |
|---|---|
| Finding gone, no new findings | Fix worked, no regressions |
| Finding gone, new findings appeared | Fix worked but may have introduced new issues, or the new run explored paths the old one did not |
| Finding still present | Fix did not address the root cause, or the fix was incomplete |
| Finding downgraded (e.g., confirmed → architectural risk) | Fix partially addressed the issue — the code weakness remains but is no longer exploitable |

### 4.4 Regression Campaigns

For ongoing security hygiene, schedule periodic reruns:

- **After major releases**: rerun to check for regressions introduced by new code.
- **After dependency updates**: rerun to check for supply-chain changes.
- **After configuration changes**: rerun to verify the new configuration does not expose risks.

Use the same target profile and run mode as the baseline campaign to ensure comparable results.

---

## 5. Workflow Summary

```
Campaign completes
    │
    ▼
Read executionStatus → calibrate confidence
    │
    ▼
Read overallVerdict → understand top-level result
    │
    ▼
Review confirmedVulnerabilities → file bugs, prioritize by severity
    │
    ▼
Review validatedRisks → file hardening tasks
    │
    ▼
Review configurationRisks → verify production config
    │
    ▼
Review unconfirmedLeads → investigate plausible ones only
    │
    ▼
Review coverageGaps → plan follow-up runs
    │
    ▼
Apply fixes → rerun → compare
```

---

## 6. Templates

### 6.1 Campaign Summary for Stakeholders

```
Security Lab Campaign Summary
Campaign: <campaignId>
Target: <targetLabel>
Run mode: <runMode>
Execution status: <executionStatus>

Results:
- Confirmed vulnerabilities: <count> (<severities>)
- Validated architectural risks: <count>
- Configuration risks: <count>
- Unconfirmed leads: <count> (not actionable without verification)

Coverage gaps: <count> (<list affected lanes>)

Recommended actions:
1. <highest priority action>
2. <next priority action>
...

Note: unconfirmed leads are model-generated hypotheses, not verified
findings. They are listed for completeness but should not drive
engineering priority without independent verification.
```

### 6.2 Fix Verification Checklist

```
Fix Verification — <findingId>
Original campaign: <campaignId>
Verification campaign: <new campaignId>

[ ] Fix applied in target codebase
[ ] Rerun completed with same target profile and run mode
[ ] Execution status is 'complete'
[ ] Original finding no longer appears
[ ] No new findings introduced
[ ] Coverage gaps are the same or fewer than original
```
