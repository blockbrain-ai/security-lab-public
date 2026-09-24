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
  /**
   * Executable basenames this target permits for shell/process/persistence
   * probes (e.g. ['ps', 'docker']). Missing or empty means the target permits
   * no shell execution at all — the gate fails closed rather than relying on a
   * denylist of dangerous command fragments.
   */
  allowedShellCommands?: string[];
  /**
   * Explicit acknowledgement that the allow-list contains an interpreter or
   * indirection binary (sh, bash, python, env, xargs, …). Allowing one of
   * those is equivalent to allowing arbitrary code execution, so it takes a
   * second, deliberate opt-in.
   */
  allowShellInterpreters?: boolean;
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
