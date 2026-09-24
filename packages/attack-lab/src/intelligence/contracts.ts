/**
 * Surface intelligence contracts — structured representations of a
 * target's code, routes, auth, config, and dependency surfaces.
 */

// ---------------------------------------------------------------------------
// Target surface map
// ---------------------------------------------------------------------------

export interface TargetSurfaceMap {
  /** Target identifier. */
  targetId: string;
  /** When the scan was performed. */
  scannedAt: string;
  /** Repository root path. */
  repoRoot: string;
  /** Detected framework/stack. */
  stack: StackInfo;
  /** Route and handler surfaces. */
  routes: RouteSurface[];
  /** Middleware and auth surfaces. */
  auth: AuthSurface[];
  /** Configuration touchpoints. */
  config: ConfigSurface[];
  /** Database and persistence surfaces. */
  persistence: PersistenceSurface[];
  /** Public/export surfaces. */
  publicSurfaces: PublicSurface[];
  /** Dependency risk surfaces. */
  dependencies: DependencySurface[];
  /** File count and structure summary. */
  structure: StructureSummary;
  /** Coverage classification for the scanned target. */
  coverage: CoverageClassification;
  /** Probe kinds the scanner can support based on what it parsed. */
  supportedProbeKinds: string[];
  /** Detected language and framework stack (may differ from StackInfo for non-Node targets). */
  detectedStack?: DetectedStack;
}

export type CoverageClassification = 'full' | 'partial' | 'manifest-only' | 'none';

export interface DetectedStack {
  language: string;
  framework: string;
  manifestFiles: string[];
}

export interface StackInfo {
  runtime: string;
  framework: string;
  orm?: string;
  frontend?: string;
  testFramework?: string;
}

export interface RouteSurface {
  method: string;
  path: string;
  file: string;
  line?: number;
  hasAuth: boolean;
  authObservation: RouteAuthObservation;
  authEvidence: string[];
  hasValidation: boolean;
  provenance: SurfaceProvenance;
  notes?: string;
}

export type RouteAuthObservation =
  | 'handler_local'
  | 'file_middleware'
  | 'not_observed';

export interface AuthSurface {
  type: 'middleware' | 'guard' | 'decorator' | 'inline';
  file: string;
  line?: number;
  mechanism: string;
  provenance: SurfaceProvenance;
  notes?: string;
}

export interface ConfigSurface {
  file: string;
  kind: 'env' | 'json' | 'yaml' | 'code';
  sensitiveKeys: string[];
  provenance: SurfaceProvenance;
  notes?: string;
}

export interface PersistenceSurface {
  type: 'prisma' | 'sql' | 'nosql' | 'file';
  file: string;
  models?: string[];
  hasRawQueries: boolean;
  provenance: SurfaceProvenance;
  notes?: string;
}

export interface PublicSurface {
  type: 'api' | 'page' | 'export' | 'webhook' | 'static';
  path: string;
  file: string;
  tier?: 'public' | 'authenticated' | 'admin';
  provenance: SurfaceProvenance;
  notes?: string;
}

export interface DependencySurface {
  name: string;
  version: string;
  hasInstallScript: boolean;
  isDirectDependency: boolean;
  riskIndicators: string[];
}

export type SurfaceProvenance = 'first_party' | 'generated' | 'third_party' | 'test' | 'docs';

export interface StructureSummary {
  totalFiles: number;
  sourceFiles: number;
  testFiles: number;
  configFiles: number;
  directories: string[];
}

// ---------------------------------------------------------------------------
// Trust boundary map
// ---------------------------------------------------------------------------

export interface TrustBoundaryMap {
  /** Boundaries between trust zones. */
  boundaries: TrustBoundary[];
}

export interface TrustBoundary {
  /** Source zone. */
  from: TrustZone;
  /** Destination zone. */
  to: TrustZone;
  /** What crosses this boundary. */
  crossings: BoundaryCrossing[];
  /** How the boundary is enforced. */
  enforcement: string;
  /** Whether enforcement appears complete. */
  enforcementComplete: boolean;
}

export type TrustZone =
  | 'external_untrusted'
  | 'public_api'
  | 'authenticated_api'
  | 'admin_api'
  | 'internal_service'
  | 'database'
  | 'file_system'
  | 'process'
  | 'external_service';

export interface BoundaryCrossing {
  type: 'data' | 'control' | 'credential' | 'code';
  description: string;
  file?: string;
  line?: number;
}

// ---------------------------------------------------------------------------
// Dependency risk map
// ---------------------------------------------------------------------------

export interface DependencyRiskMap {
  /** When the scan was performed. */
  scannedAt: string;
  /** Overall risk level. */
  overallRisk: 'low' | 'medium' | 'high' | 'critical';
  /** Per-package risk assessments. */
  packages: PackageRisk[];
  /** Lockfile anomalies. */
  lockfileAnomalies: string[];
  /** Install script risks. */
  installScriptRisks: string[];
}

export interface PackageRisk {
  name: string;
  version: string;
  risk: 'low' | 'medium' | 'high' | 'critical';
  reasons: string[];
}
