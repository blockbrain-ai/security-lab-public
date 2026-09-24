/**
 * Host-execution policy.
 *
 * Some providers do not merely answer prompts: they run a coding agent or a
 * shell on the operator's machine with the operator's environment and
 * privileges (`claude_code`, `codex_cli`, `pi_cli`, `bounded_local`). Those
 * adapters are spawned with permission/sandbox bypass flags and, when the
 * scanned repository contains prompt injection, whatever the worker reads can
 * be executed as the operator (see the 2026-09-24 audit, findings B6/B7).
 *
 * The public default is therefore **fail closed**: host-executing providers are
 * refused unless the operator explicitly opts in, either with the CLI flag
 * `--allow-host-execution` or `SECURITY_LAB_ALLOW_HOST_EXECUTION=1`.
 *
 * Opting in is an acknowledgement that the operator accepts arbitrary code
 * execution on this machine, not a sandbox.
 */

import type { ModelConfig } from './contracts.js';

type ProviderName = ModelConfig['provider'];

/** Providers that execute code on the operator's host. */
export const HOST_EXECUTING_PROVIDERS: ReadonlySet<ProviderName> = new Set<ProviderName>([
  'claude_code',
  'codex_cli',
  'pi_cli',
  'bounded_local',
]);

export const HOST_EXECUTION_ENV_VAR = 'SECURITY_LAB_ALLOW_HOST_EXECUTION';

export interface HostExecutionPolicy {
  /** Whether host-executing providers may be created. */
  allowed: boolean;
  /** Where the decision came from, for diagnostics and evidence events. */
  source: 'default' | 'env' | 'explicit';
}

/** The fail-closed default. */
export const DEFAULT_HOST_EXECUTION_POLICY: HostExecutionPolicy = { allowed: false, source: 'default' };

export function isHostExecutingProvider(provider: ProviderName): boolean {
  return HOST_EXECUTING_PROVIDERS.has(provider);
}

/**
 * Resolve the policy from an explicit opt-in and/or the environment.
 * Explicit `true` wins; explicit `false` wins over the environment.
 */
export function resolveHostExecutionPolicy(options: {
  explicit?: boolean;
  env?: NodeJS.ProcessEnv;
} = {}): HostExecutionPolicy {
  if (options.explicit === true) {
    return { allowed: true, source: 'explicit' };
  }
  if (options.explicit === false) {
    return { allowed: false, source: 'explicit' };
  }
  const env = options.env ?? process.env;
  const raw = env[HOST_EXECUTION_ENV_VAR];
  if (raw !== undefined && ['1', 'true', 'yes', 'on'].includes(raw.trim().toLowerCase())) {
    return { allowed: true, source: 'env' };
  }
  return DEFAULT_HOST_EXECUTION_POLICY;
}

/** Human-readable refusal used in place of a host-executing adapter. */
export function hostExecutionRefusal(provider: ProviderName): string {
  return (
    `Provider "${provider}" executes code on this host and is disabled by default. ` +
    `Re-run with --allow-host-execution (or set ${HOST_EXECUTION_ENV_VAR}=1) if you accept ` +
    'that a scanned repository can cause arbitrary commands to run as your user. ' +
    'Isolation (container/VM) is strongly recommended when opting in.'
  );
}
