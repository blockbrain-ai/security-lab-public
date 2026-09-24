export type {
  TargetSurfaceMap,
  StackInfo,
  RouteSurface,
  RouteAuthObservation,
  AuthSurface,
  ConfigSurface,
  PersistenceSurface,
  PublicSurface,
  DependencySurface,
  StructureSummary,
  TrustBoundaryMap,
  TrustBoundary,
  TrustZone,
  BoundaryCrossing,
  DependencyRiskMap,
  PackageRisk,
  CoverageClassification,
  DetectedStack,
} from './contracts.js';
export { scanTarget, summarizeForModel } from './target-scanner.js';
export type { KnownExploitPattern } from './exploit-intelligence.js';
export { getRelevantExploitPatterns, renderExploitIntelligence } from './exploit-intelligence.js';
