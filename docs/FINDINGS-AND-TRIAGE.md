# Security Lab — Findings Interpretation And Triage Guide

> **Audience**: operators reading Security Lab reports and deciding what matters.
> **Prerequisite**: familiarity with the [Operator Guide](./OPERATOR-GUIDE.md) — run modes, campaign lifecycle, and artifact structure.
> **Binding vocabulary**: defined by the typed contracts in `packages/*/src/*/contracts.ts`. This guide explains how to read the output; it does not redefine terms.

---

## 1. Finding Classes

Security Lab classifies every result into one of five tiers. The tiers are ordered by the strength of evidence behind them — not by narrative persuasiveness or model confidence scores.

### 1.1 Confirmed Vulnerabilities

**What they mean**: the system demonstrated exploitable behavior when tested. A local-live probe received a response matching the `expectedWhenExploitable` canary, or a synthesised test exercised a code path that produced the vulnerable outcome.

**Evidence bar**: at least one `SourceLocationRef` identifying the vulnerable code, OR at least one `ProbeRef` where the response matched the exploit canary. Model narrative alone is never sufficient for confirmation.

**Final classifications in this tier**:

| Classification | Meaning |
|---|---|
| `confirmed_exploitable_local` | Exploit replicated via local-live HTTP probe |
| `confirmed_exploitable_hosted` | Exploit replicated against a hosted target |
| `confirmed_in_isolation_only` | Exploit replicated in synthesised test but not against a running system |

**Operator action**: these are real. Triage by severity and fix them.

### 1.2 Validated Architectural Risks

**What they mean**: static analysis found code patterns that create risk surface — missing input validation, absent CSRF protection, unsanitised parameters reaching sensitive operations. The code evidence is strong enough that the risk is validated, but no running-system probe confirmed exploitation.

**Evidence bar**: `SourceLocationRef` pointing to the relevant code, plus structured analysis explaining why the pattern is risky. The risk is validated by code, not by a successful exploit.

**Final classification**: `architectural_risk`

**Operator action**: these are real design weaknesses. They belong in the engineering backlog. They are not confirmed exploits and should not be treated as emergencies unless severity is critical and the attack surface is exposed.

### 1.3 Configuration Risks

**What they mean**: the system is safe in its current configuration, but a configuration change (enabling debug mode, disabling auth, using default credentials) would create a vulnerability. The risk is conditional on misconfiguration.

**Evidence bar**: `SourceLocationRef` showing the configuration-dependent code path, plus analysis of what configuration state triggers the risk.

**Final classification**: `configuration_risk`

**Operator action**: verify that production configuration is hardened. Add configuration validation or startup checks if the dangerous state is easy to reach accidentally.

### 1.4 Unconfirmed Leads

**What they mean**: the model generated a hypothesis about a potential vulnerability, but no mechanical evidence supports it. The hypothesis may be plausible, but it has not been tested or the test was inconclusive.

**Evidence bar**: at least one evidence ref (the signal or hypothesis that generated the lead), but that ref does not meet the confirmation bar. There is no `ProbeRef` with a matching canary, no `SourceLocationRef` showing vulnerable code, or the probe returned an inconclusive result.

**Final classification**: `unconfirmed_lead`

**Critical rule**: unconfirmed leads are **never** counted in "N findings" summaries. They live in a separate list, visually and structurally distinct from confirmed findings. Do not treat them as vulnerabilities.

**Operator action**: if the lead is plausible and the attack surface matters, schedule a follow-up investigation or manual review. Do not file a bug report based solely on an unconfirmed lead.

### 1.5 Suppressed Claims (Candidate Findings Not Upheld)

**What they mean**: the runner proposed a finding during investigation, but the judge panel or assessment synthesiser rejected it during final review. The claim did not survive evidence scrutiny.

**Where they appear**: in the `suppressedClaims` array of the campaign assessment. They are documented for transparency — so the operator can see what was considered and why it was rejected — but they are not findings.

**Operator action**: read them if you want to understand the investigation's reasoning. Do not act on them unless you independently verify the claim through other means.

### 1.6 Additional Risk Classifications

These appear less frequently but follow the same evidence rules:

| Classification | Meaning |
|---|---|
| `confirmed_supply_chain_risk` | A dependency introduces verified risk |
| `monitoring_gap` | The system lacks detection for a class of attack |
| `evaluator_integrity_risk` | The evaluation/judging layer itself has a weakness |
| `diffuse_degradation_risk` | Cumulative small weaknesses create aggregate risk |
| `refuted` | Hypothesis was tested and the system defended successfully |

---

## 2. How to Read `executionStatus`

Every campaign report includes an `executionStatus` field. This tells you how completely the investigation ran — independent of what it found.

### 2.1 Status Values

| Status | Meaning | Operator Implication |
|---|---|---|
| `complete` | Every required verification lane ran to completion | Full confidence in coverage. Findings (or lack thereof) reflect thorough investigation. |
| `degraded` | Required lanes ran, but some optional lanes were skipped | Results from completed lanes are trustworthy. Check `coverageGaps` to understand what was not covered. |
| `incomplete` | At least one required lane could not run | Findings from completed lanes are still valid, but **absence of findings does not mean absence of vulnerabilities**. The investigation has known blind spots. |
| `blocked` | The run could not start or terminated early | Partial results may exist but the run did not reach a reportable state. Do not draw conclusions from a blocked run. |

### 2.2 The Independence Rule

`executionStatus` is completely independent from the security verdict.

- A `complete` run may find zero vulnerabilities. That is a good result — it means thorough investigation found nothing.
- An `incomplete` run may find confirmed exploits. The findings are real even though coverage was partial.
- A `complete` run with `no_material_findings` is stronger evidence of security than an `incomplete` run with the same verdict.

### 2.3 How Completeness Affects Confidence

When you read a campaign assessment, apply this mental model:

```
confidence_in_clean_bill = f(executionStatus, runMode)

complete + serious-local    → high confidence in local findings
complete + smoke            → moderate confidence (optional lanes may have been skipped)
degraded + serious-local    → moderate confidence (check what was skipped)
incomplete + any mode       → low confidence in "no findings" verdict
blocked + any mode          → no confidence; rerun required
```

**Key insight**: `executionStatus` primarily affects your confidence in **negative results** (finding nothing). Positive results (confirmed findings) are valid regardless of execution status, because the evidence stands on its own.

---

## 3. How to Read Verification Lane Results

The report's `verificationLanes` section breaks down what happened in each verification lane.

### 3.1 Local-Live Lane

The local-live lane sends HTTP probes against a running target instance.

| Field | What It Tells You |
|---|---|
| `attempted` | Total probes dispatched |
| `meaningfulAttempts` | Probes that actually tested a hypothesis (excludes auth failures, rate limits, not-applicable) |
| `confirmed` | Probes where the system behaved exploitably |
| `refuted` | Probes where the system defended successfully |
| `inconclusive` | Evidence insufficient to decide |
| `blocked` | Probes blocked by auth/permission before they could test anything |

**Reading the ratio**: a lane with 15 attempts, 12 meaningful, 0 confirmed, 10 refuted, 2 inconclusive is a strong negative result — the system defended against most probes and only 2 were unclear. A lane with 15 attempts, 3 meaningful, 12 blocked is a weak result — most probes could not run.

### 3.2 Test-Synthesis Lane

The test-synthesis lane generates executable test cases from hypotheses and runs them against the target codebase.

| Field | What It Tells You |
|---|---|
| `attempted` | Tests generated |
| `confirmed` | Tests that demonstrated the vulnerability |
| `refuted` | Tests that showed the system is safe |
| `compileError` | Tests that failed to compile (do not count as evidence either way) |
| `runtimeError` | Tests that crashed during execution (do not count as evidence either way) |

**Reading compile errors**: a high compile-error rate means the synthesiser struggled with the target's build system, not that the target is secure. Check `coverageGaps` for `test_synthesis_compile_retry_exhausted`.

### 3.3 Other Lanes

| Lane | Purpose |
|---|---|
| `hosted` | Probes against a hosted/remote target (serious-end-to-end only) |
| `supplyChain` | Dependency and supply-chain risk analysis |
| `monitoringStress` | Detection and monitoring gap analysis |

---

## 4. How to Read Coverage Gaps

Coverage gaps tell you what the investigation could not cover and why.

### 4.1 Gap Reason Codes

| Code | Meaning | Impact |
|---|---|---|
| `identity_missing` | No test identity available for auth-gated probes | Auth-protected surfaces were not tested |
| `mutation_rollback_missing` | Mutation probes could not guarantee rollback | State-changing probes were skipped |
| `test_synthesis_compile_retry_exhausted` | Generated tests could not compile after retries | Hypothesis was not verified via test synthesis |
| `live_target_unreachable` | Target HTTP endpoint was not responding | Local-live lane could not run |
| `worker_unavailable` | CLI worker (Claude Code / Codex) was not available | Worker-dependent lanes were skipped |
| `auth_bootstrap_unavailable` | Auth bootstrap system was not configured | Identity-dependent probes were skipped |
| `followup_budget_exhausted` | Investigation budget ran out before follow-up probes | Some hypotheses were not fully explored |

### 4.2 Interpreting Gaps

Coverage gaps do not mean the investigation failed. They mean specific areas were not covered. Use them to:

1. **Understand blind spots**: if `identity_missing` appears, authentication-protected routes were not probed. A "no findings" result does not cover those routes.
2. **Plan follow-up runs**: configure the missing prerequisites and rerun to fill the gaps.
3. **Qualify the report**: when communicating results to stakeholders, note which areas had coverage gaps.

---

## 5. How to Read the Campaign Assessment

The campaign assessment is the final synthesised verdict across all lanes and findings.

### 5.1 Overall Verdict

| Verdict | Meaning |
|---|---|
| `confirmed_vulnerabilities_present` | At least one confirmed exploitable finding exists |
| `validated_architectural_risks_only` | No confirmed exploits, but validated code-level risks exist |
| `high_priority_unconfirmed_leads` | No confirmed findings or validated risks, but unconfirmed leads warrant attention |
| `no_material_findings` | Nothing significant found across all lanes |

### 5.2 Assessment Sections

The assessment groups results into four lists:

1. **`confirmedVulnerabilities`** — findings with mechanical exploit evidence
2. **`validatedRisks`** — code-backed architectural risks
3. **`configurationRisks`** — configuration-dependent risks
4. **`unconfirmedLeads`** — hypotheses without supporting evidence

Each item includes `evidenceRefs` pointing to source locations, probes, or events. **Always check the evidence refs** — they are the ground truth. Narrative summaries may over- or under-state; evidence refs are mechanical.

### 5.3 Source Provenance

The assessment's `source` field tells you how the verdict was produced:

| Source | Meaning |
|---|---|
| `deterministic` | Verdict was computed mechanically from lane results (no model judgment) |
| `review_panel` | Multiple models reviewed the evidence and reached consensus |
| `synthesized` | A synthesiser model combined panel outputs into a final assessment |

`deterministic` verdicts are the most reliable. `review_panel` and `synthesized` verdicts are model-mediated and should be read alongside the underlying evidence refs.

---

## 6. Interpreting a "Zero Confirmed Exploits" Campaign

A campaign that finds zero confirmed exploits is not necessarily a clean bill of health. Here is how to interpret it honestly:

### 6.1 Strong Negative (High Confidence)

- `executionStatus`: `complete`
- `runMode`: `serious-local` or `serious-end-to-end`
- Local-live: high meaningful-attempt count, most refuted, few inconclusive
- Test-synthesis: tests compiled and ran, most refuted
- Coverage gaps: none or only non-critical optional lanes
- **Interpretation**: the investigation was thorough and the system defended well. This is genuine evidence of security hardening.

### 6.2 Weak Negative (Low Confidence)

- `executionStatus`: `incomplete` or `degraded`
- Multiple coverage gaps in required lanes
- Low meaningful-attempt count relative to total attempts
- High blocked/auth-failed count
- **Interpretation**: the investigation could not test significant attack surfaces. "No findings" reflects incomplete coverage, not verified security. Rerun with prerequisites fixed.

### 6.3 Zero Exploits But Validated Risks

- Overall verdict: `validated_architectural_risks_only`
- Architectural risks with `SourceLocationRef` evidence
- **Interpretation**: the system was not exploited, but code-level weaknesses exist. These may become exploitable under different conditions, with different payloads, or after code changes. They are worth fixing even without a confirmed exploit.

### 6.4 The the target application Reference Example

The the target application serious-local campaign is the canonical example of this pattern:

- **Zero confirmed exploits** — no probe replicated an attack against the running system.
- **Several validated architectural risks** — static analysis identified code patterns (e.g., unsanitised inputs reaching database queries, missing rate limiting on sensitive endpoints) backed by `SourceLocationRef` evidence.
- **Unconfirmed leads** — model-generated hypotheses about potential attack chains that were not mechanically verified.

**Correct interpretation**: the target application defended against automated probing, which is a positive signal. The architectural risks are real code-level weaknesses that should enter the engineering backlog. The unconfirmed leads should not drive engineering priority — they are hypotheses, not evidence.

**Incorrect interpretation**: "Security Lab found nothing, so the target application is secure" (ignores architectural risks) or "Security Lab found vulnerabilities in the target application" (promotes architectural risks to confirmed exploits).

---

## 7. Decision Framework: What Is Worth Fixing?

Use evidence class, not narrative strength, as the primary decision input.

### 7.1 Evidence Hierarchy

```
Confirmed exploit (probe evidence)     → highest confidence, fix immediately
Confirmed exploit (test-synthesis only) → high confidence, verify in running system
Validated architectural risk            → medium confidence, fix in normal cycle
Configuration risk                     → conditional, verify production config
Unconfirmed lead                        → hypothesis only, investigate if plausible
Suppressed claim                        → rejected by review, do not act on
```

### 7.2 Severity Within Each Class

Within each evidence class, use the `severity` field (critical / high / medium / low) to prioritise. But severity within a class never overrides the class boundary:

- A **critical** unconfirmed lead is still less actionable than a **medium** confirmed exploit.
- A **low** validated architectural risk is still more actionable than a **high** suppressed claim.

### 7.3 Avoiding Overreaction

Common overreaction patterns to watch for:

| Pattern | Why It's Wrong | What to Do Instead |
|---|---|---|
| Filing bugs for every unconfirmed lead | Leads are hypotheses, not evidence | Review leads manually; only escalate if you independently verify the concern |
| Treating architectural risks as active exploits | No probe confirmed exploitation | Add to backlog at appropriate priority; do not emergency-patch |
| Blocking a release over a suppressed claim | The judge panel already rejected this claim | Read the suppression reason; only revisit if you disagree with the panel's reasoning |
| Ignoring architectural risks because "nothing was exploited" | Absence of exploit does not mean absence of risk | Architectural risks are validated code weaknesses — schedule fixes |
| Treating `incomplete` status as "the tool failed" | Incomplete runs still produce valid findings | Act on findings from completed lanes; rerun to fill gaps |

---

## 8. Quick Reference: Reading a Report

When you open a Security Lab report, read it in this order:

1. **`executionStatus`** — did the investigation run completely? This calibrates how much you can trust a "no findings" result.
2. **`runMode`** — smoke or serious? Serious runs have stricter coverage requirements.
3. **`overallVerdict`** — what is the top-level result?
4. **`confirmedVulnerabilities`** — are there confirmed exploits? If yes, these are priority one.
5. **`validatedRisks`** — are there code-backed architectural risks? These are real and belong in the backlog.
6. **`configurationRisks`** — check production configuration.
7. **`unconfirmedLeads`** — review for plausibility, do not act without verification.
8. **`coverageGaps`** — what was not tested? Plan follow-up runs.
9. **`suppressedClaims`** — what was considered and rejected? Read for context only.

---

## 9. Glossary

| Term | Definition |
|---|---|
| **Finding** | A confirmed vulnerability with mechanical evidence (probe or source ref) |
| **Validated risk** | A code-backed weakness that has not been exploited but is structurally real |
| **Unconfirmed lead** | A model-generated hypothesis without mechanical evidence |
| **Suppressed claim** | A candidate finding rejected by the judge panel |
| **Evidence ref** | A pointer to a source location, probe result, or event that supports a claim |
| **Coverage gap** | An area the investigation could not test, with a reason code |
| **Execution status** | How completely the investigation ran (independent of what it found) |
| **Verification lane** | A distinct verification method (local-live, test-synthesis, hosted, etc.) |
| **Meaningful attempt** | A probe that actually tested a hypothesis (excludes auth failures, rate limits) |
| **Canary** | A known-good response pattern used to detect exploitable behavior |
