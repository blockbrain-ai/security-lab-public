/**
 * Shared verification contracts — used by every verification lane
 * (test synthesis, local live, hosted, supply chain) and every
 * Mythos-alignment workstream (monitoring stress, evidence integrity,
 * diffuse sandbagging).
 *
 * The core abstraction is the VerificationExperiment: a structured
 * record of "we asked X, we tried Y, we observed Z, the verdict is W."
 * Every confirmed/refuted finding must trace back to one of these.
 */

// ---------------------------------------------------------------------------
// Verification routes — which lane was used
// ---------------------------------------------------------------------------

export type VerificationRoute =
  | 'test_synthesis'
  | 'local_live'
  | 'hosted'
  | 'supply_chain'
  | 'monitoring_stress'
  | 'evidence_integrity'
  | 'sandbagging'
  | 'browser'
  | 'mixed';

// ---------------------------------------------------------------------------
// Verification verdicts — common shapes across all lanes
// ---------------------------------------------------------------------------

export type VerificationVerdict =
  | 'confirmed'
  | 'refuted'
  | 'inconclusive'
  | 'auto_stopped'
  | 'not_authorized'
  | 'not_applicable'
  | 'compile_error'
  | 'timeout'
  | 'runtime_error'
  | 'rate_limited'
  | 'auth_failed'
  | 'dry_run_simulated'
  | 'coverage_gap';

// ---------------------------------------------------------------------------
// Verification experiment — the canonical record of "we ran this experiment"
// ---------------------------------------------------------------------------

export interface VerificationExperiment {
  /** Unique experiment identifier. */
  experimentId: string;
  /** Which finding/hypothesis this experiment tests. */
  findingId: string;
  /** Which verification route was used. */
  route: VerificationRoute;
  /** When the experiment was run. */
  at: string;
  /** Human-readable hypothesis being tested. */
  hypothesis: string;
  /** Identity context if applicable (e.g., "user_a_low" for IDOR tests). */
  identityContext?: string;
  /** Prerequisites that must be true for the experiment to be valid. */
  prerequisites: string[];
  /** What was done (the intervention). */
  intervention: string;
  /** What we expect to observe if the system is safe. */
  expectedSafeOutcome: string;
  /** What we expect to observe if the system is exploitable. */
  expectedExploitableOutcome: string;
  /** Rollback plan if the experiment caused state changes. */
  rollbackPlan?: string;
  /** Whether rollback was actually executed. */
  rollbackExecuted?: boolean;
  /** What was actually observed. */
  actualObservation: string;
  /** Final verdict. */
  verdict: VerificationVerdict;
  /** Confidence in the verdict (0-1). */
  confidence: number;
  /** Evidence references (event IDs, file paths, audit entries). */
  evidenceRefs: string[];
  /** Any caveats or edge cases. */
  notes?: string;
}

// ---------------------------------------------------------------------------
// Per-lane verification status (used in finding records)
// ---------------------------------------------------------------------------

export interface TestSynthesisStatus {
  attempted: boolean;
  verdict: VerificationVerdict;
  testPath?: string;
  experimentRef?: string;
  rollbackRefs: string[];
  evidenceRefs: string[];
}

export interface LocalLiveStatus {
  attempted: boolean;
  verdict: VerificationVerdict;
  transitionsTested: string[];
  confirmedTransitions: string[];
  canaryResponses: string[];
  rollbackRefs: string[];
  evidenceRefs: string[];
}

export interface HostedStatus {
  attempted: boolean;
  verdict: VerificationVerdict;
  transitionsTested: string[];
  confirmedTransitions: string[];
  auditTrailPath?: string;
  evidenceRefs: string[];
}

export interface SupplyChainStatus {
  attempted: boolean;
  verdict: 'confirmed_risk' | 'approved_drift' | 'needs_review' | 'refuted' | 'not_applicable';
  changedPackages: string[];
  policyHash?: string;
  evidenceRefs: string[];
}

export interface MonitoringStressStatus {
  attempted: boolean;
  mode?: 'declared' | 'blind' | 'paired';
  contextBand?: 'baseline' | '50k' | '100k' | '200k' | '400k';
  verdict: 'no_signal' | 'harmful_action_seen' | 'monitoring_degraded' | 'not_applicable';
  stealthScore?: number;
  detectionLatencyMs?: number;
  evidenceRefs: string[];
}

export interface EvaluatorIntegrityStatus {
  attempted: boolean;
  verdict: 'clean' | 'drift_detected' | 'tampered' | 'not_applicable';
  policyHash?: string;
  rubricHash?: string;
  evidenceRefs: string[];
}

export interface DiffuseDegradationStatus {
  attempted: boolean;
  verdict: 'no_pattern' | 'patterned_degradation' | 'inconclusive' | 'not_applicable';
  cumulativeImpact?: number;
  evidenceRefs: string[];
}

/** Section 12.1 — browser lane verification status. */
export interface BrowserStatus {
  attempted: boolean;
  verdict: VerificationVerdict;
  /** Evidence bundle IDs produced during browser probes. */
  evidenceBundleIds: string[];
  /** Whether storage-state expectations were validated. */
  storageStateValidated: boolean;
  evidenceRefs: string[];
}

// ---------------------------------------------------------------------------
// Final classification — what does the campaign say about this finding?
// ---------------------------------------------------------------------------

export type FinalClassification =
  | 'confirmed_exploitable_local'
  | 'confirmed_exploitable_hosted'
  | 'confirmed_in_isolation_only'
  | 'confirmed_supply_chain_risk'
  | 'monitoring_gap'
  | 'evaluator_integrity_risk'
  | 'diffuse_degradation_risk'
  | 'architectural_risk'
  | 'configuration_risk'
  | 'unconfirmed_lead'
  | 'refuted';

export interface FindingVerificationStatus {
  findingId: string;
  verificationRoute: VerificationRoute;
  staticEvidence: 'present' | 'absent';
  testSynthesis: TestSynthesisStatus;
  localLive: LocalLiveStatus;
  hosted: HostedStatus;
  /** Section 12.1 — browser lane status. */
  browser: BrowserStatus;
  supplyChain: SupplyChainStatus;
  monitoringStress: MonitoringStressStatus;
  evaluatorIntegrity: EvaluatorIntegrityStatus;
  diffuseDegradation: DiffuseDegradationStatus;
  finalClassification: FinalClassification;
  confidence: number;
  experimentRefs: string[];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function emptyVerificationStatus(findingId: string): FindingVerificationStatus {
  return {
    findingId,
    verificationRoute: 'mixed',
    staticEvidence: 'present',
    testSynthesis: { attempted: false, verdict: 'not_applicable', rollbackRefs: [], evidenceRefs: [] },
    localLive: {
      attempted: false,
      verdict: 'not_applicable',
      transitionsTested: [],
      confirmedTransitions: [],
      canaryResponses: [],
      rollbackRefs: [],
      evidenceRefs: [],
    },
    hosted: {
      attempted: false,
      verdict: 'not_applicable',
      transitionsTested: [],
      confirmedTransitions: [],
      evidenceRefs: [],
    },
    browser: {
      attempted: false,
      verdict: 'not_applicable',
      evidenceBundleIds: [],
      storageStateValidated: false,
      evidenceRefs: [],
    },
    supplyChain: {
      attempted: false,
      verdict: 'not_applicable',
      changedPackages: [],
      evidenceRefs: [],
    },
    monitoringStress: { attempted: false, verdict: 'not_applicable', evidenceRefs: [] },
    evaluatorIntegrity: { attempted: false, verdict: 'not_applicable', evidenceRefs: [] },
    diffuseDegradation: { attempted: false, verdict: 'not_applicable', evidenceRefs: [] },
    finalClassification: 'unconfirmed_lead',
    confidence: 0,
    experimentRefs: [],
  };
}

export function classifyFromVerification(status: FindingVerificationStatus): FinalClassification {
  // Highest tier: hosted confirmation
  if (status.hosted.attempted && status.hosted.verdict === 'confirmed') {
    return 'confirmed_exploitable_hosted';
  }
  // Local live confirmation
  if (status.localLive.attempted && status.localLive.verdict === 'confirmed') {
    return 'confirmed_exploitable_local';
  }
  // Section 12.1 — browser lane confirmation (same tier as local-live)
  if (status.browser.attempted && status.browser.verdict === 'confirmed') {
    return 'confirmed_exploitable_local';
  }
  // Test synthesis confirmation only
  if (status.testSynthesis.attempted && status.testSynthesis.verdict === 'confirmed') {
    return 'confirmed_in_isolation_only';
  }
  // Supply chain risk
  if (status.supplyChain.attempted && status.supplyChain.verdict === 'confirmed_risk') {
    return 'confirmed_supply_chain_risk';
  }
  // Monitoring gaps
  if (status.monitoringStress.attempted && status.monitoringStress.verdict === 'monitoring_degraded') {
    return 'monitoring_gap';
  }
  // Evaluator tampering
  if (
    status.evaluatorIntegrity.attempted &&
    (status.evaluatorIntegrity.verdict === 'drift_detected' || status.evaluatorIntegrity.verdict === 'tampered')
  ) {
    return 'evaluator_integrity_risk';
  }
  // Diffuse degradation
  if (status.diffuseDegradation.attempted && status.diffuseDegradation.verdict === 'patterned_degradation') {
    return 'diffuse_degradation_risk';
  }
  // All attempted lanes refuted
  const lanes = [status.testSynthesis, status.localLive, status.hosted, status.browser];
  const attemptedLanes = lanes.filter((l) => l.attempted);
  if (attemptedLanes.length > 0 && attemptedLanes.every((l) => l.verdict === 'refuted')) {
    return 'refuted';
  }
  // No verification attempted
  return 'unconfirmed_lead';
}

export function createExperimentId(route: VerificationRoute, findingId: string): string {
  const ts = Date.now();
  const rand = Math.random().toString(36).slice(2, 8);
  return `exp-${route}-${findingId}-${ts}-${rand}`;
}
