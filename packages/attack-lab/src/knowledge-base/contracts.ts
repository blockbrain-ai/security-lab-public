/**
 * Cross-campaign knowledge base contracts — types for persisting
 * approved findings, strong refutations, regression packs, and
 * dependency decisions across campaigns on the same target.
 */

// ---------------------------------------------------------------------------
// Knowledge records
// ---------------------------------------------------------------------------

export interface PriorFinding {
  id: string;
  campaignId: string;
  confirmedAt: string;
  targetFingerprint: string;
  targetFamily: string;
  severity: string;
  description: string;
  reproductionSteps: string[];
  remediationSuggestion: string;
  signalIds: string[];
  chainLength: number;
  involvedDormantReactivation: boolean;
}

export interface RefutedChain {
  id: string;
  campaignId: string;
  refutedAt: string;
  targetFingerprint: string;
  targetFamily: string;
  description: string;
  signalIds: string[];
  /** Why it was refuted — strong evidence only. */
  refutationEvidence: string;
  /** How many attempts were made before refutation. */
  attemptCount: number;
}

export interface RegressionPackRef {
  id: string;
  campaignId: string;
  createdAt: string;
  targetFingerprint: string;
  severity: string;
  description: string;
  filePath: string;
}

export interface DependencyDecision {
  packageName: string;
  version: string;
  decision: 'approved' | 'rejected';
  decidedAt: string;
  targetFingerprint: string;
  reason: string;
}

export interface TargetFingerprint {
  /** SHA-256 of key target files (package.json, lockfile, etc.). */
  hash: string;
  /** When computed. */
  computedAt: string;
  /** Route count at scan time. */
  routeCount: number;
  /** Source file count. */
  sourceFileCount: number;
  /** Target family label (e.g. "fixture-workspace"). */
  family: string;
}

// ---------------------------------------------------------------------------
// Knowledge store
// ---------------------------------------------------------------------------

export interface KnowledgeBase {
  version: string;
  updatedAt: string;
  targetFamily: string;
  findings: PriorFinding[];
  refutedChains: RefutedChain[];
  regressionPacks: RegressionPackRef[];
  dependencyDecisions: DependencyDecision[];
  fingerprints: TargetFingerprint[];
}
