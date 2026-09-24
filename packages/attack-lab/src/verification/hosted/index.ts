export type {
  AuthSource,
  HostedIdentitySpec,
  HostedProbeRequest,
  HostedExecutionResult,
  AuditEntry,
  AuthorizationContext,
  AutoStopIncident,
  HostedTargetMeta,
} from './contracts.js';

export { AuthManager, type ResolvedCredentials } from './auth-manager.js';
export { HostedIdentityMatrix, resolveIsCanary } from './hosted-identity-matrix.js';
export { AuthorizationGate } from './authorization-gate.js';
export { AuditTrail } from './audit-trail.js';
export { AutoStopMonitor, type AutoStopOptions } from './auto-stop.js';
export { executeHostedProbe, type HostedProbeOptions } from './hosted-http-probe.js';
