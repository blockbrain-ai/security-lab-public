import type { EnvironmentTier, SafetyState, SecurityMode } from '../../evidence-plane/src/contracts.js';

export type ProbeKind =
  | 'http_request'
  | 'shell_command'
  | 'code_read'
  | 'dependency_read'
  | 'prompt_injection'
  | 'process_check'
  | 'state_check'
  | 'evidence_check'
  | 'persistence_check';

export interface RuntimeTargetContext {
  id: string;
  kind: 'http' | 'shell' | 'code' | 'dependency' | 'hybrid';
  environment: EnvironmentTier;
  baseUrl?: string;
  cwd?: string;
  repoRoot?: string;
}

export interface RuntimeProbeContext {
  kind: ProbeKind;
  timeoutMs: number;
  method?: string;
  body?: string;
  command?: string[];
}

export interface RuntimePolicy {
  killSwitchPath: string;
  maxTimeoutMs: number;
  destructiveCommandFragments: string[];
  blockedShellEnvironments: EnvironmentTier[];
}

export interface RuntimeDecision {
  allowed: boolean;
  observedSafetyState: SafetyState;
  reason: string | null;
  mode: SecurityMode;
}
