/**
 * Shared standalone utility functions for the investigation runner family.
 *
 * Extracted from investigation-runner-internals.ts to break circular
 * dependencies between the internals file and the local-live extraction.
 * Both investigation-runner-internals.ts and investigation-runner-local-live.ts
 * import from this module.
 */

import type { ModelAdapter } from '../providers/contracts.js';
import type { PortfolioProfile } from '../orchestration/portfolio-profiles.js';
import { shouldUseCounterPlanner } from '../orchestration/portfolio-profiles.js';
import type { LiveProbeRequest } from '../verification/local-live/contracts.js';
// CampaignMemory not directly needed — these are pure utility functions
import { isUnavailableAdapter } from '../providers/unavailable-adapter.js';

// These types are re-exported from here so both internals and local-live can import them
// without circular dependencies. Originally defined inline in internals.

export type ExecutionStatus = 'complete' | 'degraded' | 'incomplete' | 'blocked';

export interface CoverageGap {
  lane: string;
  code: string;
  message: string;
  severity: ExecutionStatus;
  required?: boolean;
}

export interface ChildCampaignSummary {
  lane: string;
  campaignId: string;
  status: string;
  targetId?: string | null;
  runDir?: string;
  sourceCampaignId?: string;
  totalCostUsd?: number;
  durationMs?: number;
}

export interface VerificationLaneSummary {
  attempted: number;
  meaningfulAttempts: number;
  confirmed: number;
  refuted: number;
  inconclusive: number;
  blocked: number;
  skipped: number;
  authFailed: number;
  notApplicable: number;
  notAuthorized: number;
  rateLimited: number;
  autoStopped: number;
  timeout: number;
  runtimeError: number;
  compileError: number;
  dryRunSimulated: number;
  coverageGapCount: number;
  costUsd: number;
  durationMs: number;
  status: ExecutionStatus;
  required: boolean;
  coverageGaps: string[];
  notes?: string[];
  auditTrailPath?: string;
  childCampaigns?: ChildCampaignSummary[];
  confirmedRisk?: number;
  needsReview?: number;
  approvedDrift?: number;
  runs?: number;
  degraded?: number;
  harmfulSeen?: number;
  /** Section 6.1 — probe origin breakdown for the local-live lane. */
  adaptiveProbes?: {
    hypothesis: { attempted: number; confirmed: number; refuted: number; inconclusive: number };
    adaptive: { attempted: number; confirmed: number; refuted: number; inconclusive: number };
    canary: { attempted: number; matchedSafe: number; matchedExploitable: number };
    surprisesDetected: number;
    followupsGenerated: number;
    midRoundHypothesesSynthesized: number;
  };
  /** Section 6.2 — worker-driven creativity + source correlation breakdown. */
  mythos?: {
    enabled: boolean;
    invocations: number;
    probesExecuted: number;
    hypothesesProposed: number;
    findingsProposed: number;
    findingsRejected: number;
    nonHypothesisProbes: number;
    budgetExhausted: 'probe_budget_exhausted' | 'time_budget_exhausted' | null;
    sourceCorrelations: number;
    sourceRefsCollected: number;
  };
  /** Section 11.3 — assertion-based classification summary. */
  assertionClassification?: {
    totalClassified: number;
    byReason: Record<string, number>;
    byRouteKind: Record<string, number>;
    suppressedCount: number;
  };
  /** Section 11.4 — sequence and identity-differential execution summary. */
  sequenceExecution?: {
    sequencesExecuted: number;
    totalStepsExecuted: number;
    sequencesConfirmed: number;
    sequencesRefuted: number;
    sequencesInconclusive: number;
    differentialsExecuted: number;
    differentialsWithEscalation: number;
    statePassthroughCount: number;
    rollbacksExecuted: number;
  };
  /** Section 12.2 — browser exploit family coverage for the browser lane. */
  browserExploitFamilies?: {
    totalBrowserProbes: number;
    byFamily: Record<string, {
      probes: number;
      variants: string[];
      confirmed: number;
      refuted: number;
      inconclusive: number;
    }>;
  };
}

// ── Pre-class exported functions ──

export function shouldUseCounterPlannerForLocalLive(
  profile: PortfolioProfile,
  input: {
    chainDepth: number;
    noveltyScore: number;
    budgetUsedPercent: number;
    round: number;
    priorProbeCount: number;
    hasUnresolvedOrPositivePriorResults: boolean;
    runtimeSignalCount: number;
    primaryProbeCount: number;
    primaryUsedFallback: boolean;
  },
): boolean {
  if (!profile.counterPlanner) {
    return false;
  }

  if (input.primaryUsedFallback || input.primaryProbeCount === 0) {
    return true;
  }

  const hasFollowOnContext = input.round > 1 || input.priorProbeCount > 0 || input.runtimeSignalCount > 0;
  if (!hasFollowOnContext) {
    return false;
  }

  // If prior rounds only produced safe/refuted outcomes, let the primary
  // worker keep exploring instead of automatically escalating to the heavy
  // counter path just because the static chain is deep.
  if (input.round > 1 && !input.hasUnresolvedOrPositivePriorResults) {
    return false;
  }

  return shouldUseCounterPlanner(profile, {
    consecutiveDeadEnds: input.priorProbeCount > 0 ? 1 : 0,
    chainDepth: input.chainDepth,
    noveltyScore: input.noveltyScore,
    budgetUsedPercent: input.budgetUsedPercent,
  });
}


export function countNovelRuntimeSignals(
  priorRuntimeSignals: string[],
  roundSignals: string[],
): number {
  if (roundSignals.length === 0) {
    return 0;
  }

  const seen = new Set(priorRuntimeSignals.map(normalizeRuntimeSignalSummary));
  let novelCount = 0;
  for (const signal of roundSignals) {
    const normalized = normalizeRuntimeSignalSummary(signal);
    if (!seen.has(normalized)) {
      seen.add(normalized);
      novelCount += 1;
    }
  }
  return novelCount;
}


export function shouldContinueLocalLiveRounds(input: {
  results: Array<{ verdict: string }>;
  priorRuntimeSignals: string[];
  roundSignals: string[];
}): boolean {
  if (countNovelRuntimeSignals(input.priorRuntimeSignals, input.roundSignals) > 0) {
    return true;
  }

  return input.results.some((result) => result.verdict === 'runtime_error');
}


// ── Post-class standalone functions ──

export function severityRank(severity: string): number {
  switch (severity) {
    case 'critical': return 4;
    case 'high': return 3;
    case 'medium': return 2;
    case 'low': return 1;
    default: return 0;
  }
}


export function createLaneSummary(required = false): VerificationLaneSummary {
  return {
    attempted: 0,
    meaningfulAttempts: 0,
    confirmed: 0,
    refuted: 0,
    inconclusive: 0,
    blocked: 0,
    skipped: 0,
    authFailed: 0,
    notApplicable: 0,
    notAuthorized: 0,
    rateLimited: 0,
    autoStopped: 0,
    timeout: 0,
    runtimeError: 0,
    compileError: 0,
    dryRunSimulated: 0,
    coverageGapCount: 0,
    costUsd: 0,
    durationMs: 0,
    status: 'complete',
    required,
    coverageGaps: [],
  };
}


export function addLaneCoverageGap(
  summary: VerificationLaneSummary,
  message: string,
  status: ExecutionStatus = 'incomplete',
): void {
  summary.coverageGaps.push(message);
  summary.status = maxExecutionStatus(summary.status, status);
}


export function countLaneVerdict(summary: VerificationLaneSummary, verdict: string): void {
  switch (verdict) {
    case 'confirmed':
      summary.confirmed += 1;
      summary.meaningfulAttempts += 1;
      break;
    case 'refuted':
      summary.refuted += 1;
      summary.meaningfulAttempts += 1;
      break;
    case 'inconclusive':
      summary.inconclusive += 1;
      summary.meaningfulAttempts += 1;
      break;
    case 'rate_limited':
      summary.rateLimited += 1;
      break;
    case 'not_authorized':
      summary.notAuthorized += 1;
      break;
    case 'not_applicable':
      summary.notApplicable += 1;
      break;
    case 'auth_failed':
      summary.authFailed += 1;
      break;
    case 'auto_stopped':
      summary.autoStopped += 1;
      summary.blocked += 1;
      break;
    case 'compile_error':
      summary.compileError += 1;
      summary.inconclusive += 1;
      break;
    case 'timeout':
      summary.timeout += 1;
      summary.inconclusive += 1;
      break;
    case 'runtime_error':
      summary.runtimeError += 1;
      summary.inconclusive += 1;
      break;
    case 'dry_run_simulated':
      summary.dryRunSimulated += 1;
      break;
    case 'coverage_gap':
      summary.coverageGapCount += 1;
      break;
    default:
      summary.inconclusive += 1;
      break;
  }
}


/**
 * Section 11.3 — count a lane verdict using the assertion classifier's
 * `isMeaningfulAttempt` flag instead of the default heuristic.
 * Falls back to `countLaneVerdict` when no classification is available.
 */
export function countLaneVerdictWithClassification(
  summary: VerificationLaneSummary,
  verdict: string,
  isMeaningfulAttempt?: boolean,
): void {
  // Delegate verdict counting to the standard function
  const prevMeaningful = summary.meaningfulAttempts;
  countLaneVerdict(summary, verdict);
  // If a classification told us this is not meaningful, undo the increment
  if (isMeaningfulAttempt === false && summary.meaningfulAttempts > prevMeaningful) {
    summary.meaningfulAttempts = prevMeaningful;
  }
}


export function usableAdapter<T extends ModelAdapter | undefined | null>(adapter: T): Exclude<T, undefined | null> | undefined {
  if (!adapter || isUnavailableAdapter(adapter)) {
    return undefined;
  }
  return adapter as Exclude<T, undefined | null>;
}


export function coverageGap(lane: string, code: string, message: string, severity: ExecutionStatus, required = true): CoverageGap {
  return { lane, code, message, severity, required };
}


export function buildLinuxSidecarCommand(
  probe: LiveProbeRequest,
  markers: string[],
  workingDir: string,
): string {
  const effectiveMarkers = markers.length > 0 ? markers : ['SECURITY_LAB_DECOY', 'SECURITY_LAB_CANARY'];
  const markersJson = JSON.stringify(effectiveMarkers).replace(/'/g, `'\\''`);
  const escapedPattern = effectiveMarkers
    .map((marker) => marker.replace(/'/g, `'\\''`))
    .join('|');
  const pattern = escapedPattern.length > 0 ? escapedPattern : 'SECURITY_LAB_DECOY|SECURITY_LAB_CANARY';

  if (probe.process?.action === 'fd_scan') {
    return `ls -l /proc/self/fd 2>/dev/null | head -n 80 | grep -E '${pattern}' || true`;
  }
  if (probe.process?.action === 'proc_self_read') {
    return `tr '\\0' '\\n' < /proc/self/environ 2>/dev/null | grep -E '${pattern}' || true`;
  }
  if (probe.persistence?.action === 'background_process_check') {
    const nodeScript = [
      'const fs=require("fs");',
      'const markers=JSON.parse(process.argv[1]);',
      'const skip=new Set();',
      'let current=process.pid;',
      'for(let i=0;i<8 && Number.isFinite(current) && current>0;i+=1){',
      'skip.add(String(current));',
      'try{',
      `const stat=fs.readFileSync("/proc/" + current + "/stat","utf8").trim().split(" ");`,
      'current=Number(stat[3]);',
      '}catch{',
      'break;',
      '}',
      '}',
      'for(const pid of fs.readdirSync("/proc").filter((entry)=>/^\\\\d+$/.test(entry)).slice(0,120)){',
      'if(skip.has(pid)) continue;',
      'try{',
      `const cmd=fs.readFileSync("/proc/" + pid + "/cmdline","utf8").replace(/\\\\0/g," ").trim();`,
      'if(!cmd) continue;',
      `if(markers.some((marker)=>cmd.includes(marker))) console.log(pid + " " + cmd);`,
      '}catch{}',
      '}',
    ].join(' ');
    const escapedNodeScript = nodeScript.replace(/'/g, `'\\''`);
    return `node -e '${escapedNodeScript}' '${markersJson}' || true`;
  }
  if (probe.persistence?.action === 'startup_check') {
    return `grep -R -n -E '${pattern}' '${workingDir}'/package.json '${workingDir}'/pnpm-workspace.yaml '${workingDir}'/.npmrc 2>/dev/null || true`;
  }
  return `printf ''`;
}

// ── Additional helpers needed by the extracted functions above ──

export function normalizeRuntimeSignalSummary(signal: string): string {
  return signal.trim();
}

export function maxExecutionStatus(left: ExecutionStatus, right: ExecutionStatus): ExecutionStatus {
  const rank: Record<ExecutionStatus, number> = {
    complete: 0,
    degraded: 1,
    incomplete: 2,
    blocked: 3,
  };
  return rank[left] >= rank[right] ? left : right;
}
