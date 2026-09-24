export * from './loaders/runfile-loader.js';
export * from './runs/security-lab-runner.js';
export * from './types/runfile.js';
export * from './autonomous/index.js';
export type {
  TargetSurfaceMap,
  StackInfo,
  RouteSurface,
  AuthSurface,
  ConfigSurface,
  PersistenceSurface,
  PublicSurface,
  DependencySurface,
  StructureSummary,
  TrustBoundaryMap,
  TrustBoundary,
  TrustZone,
  DependencyRiskMap,
  PackageRisk,
  KnownExploitPattern,
} from './intelligence/index.js';
export { scanTarget, summarizeForModel, getRelevantExploitPatterns, renderExploitIntelligence } from './intelligence/index.js';
