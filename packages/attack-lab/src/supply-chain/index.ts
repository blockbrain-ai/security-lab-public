export type {
  DependencyBaseline,
  ApprovedPackage,
  DependencyDrift,
  DriftKind,
  QuarantineResult,
  QuarantineCheck,
  SentinelResult,
} from './contracts.js';
export { createBaseline, loadBaseline, saveBaseline, detectDrift } from './baseline.js';
export { inspectInstalledPackage } from './quarantine.js';
export { runSentinel, approveAndUpdateBaseline, summarizeSentinelResult } from './sentinel.js';
export { shouldBlockBuild, summarizePendingDrift, getApprovedResults, getPendingResults } from './gate.js';
