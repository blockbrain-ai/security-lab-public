import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import type { SecurityMode } from '../../evidence-plane/src/contracts.js';
import type {
  RuntimeDecision,
  RuntimePolicy,
  RuntimeProbeContext,
  RuntimeTargetContext,
} from './contracts.js';

const DEFAULT_POLICY: RuntimePolicy = {
  killSwitchPath: '.security-lab-stop',
  maxTimeoutMs: 30000,
  destructiveCommandFragments: [
    'rm -rf',
    'launchctl',
    'crontab',
    'cron',
    'pkill',
    'killall',
    'shutdown',
    'reboot',
    'osascript',
  ],
  blockedShellEnvironments: ['staging', 'hosted_authorized', 'production_shadow'],
};

/**
 * Binaries that can execute arbitrary code or indirect into another command.
 * Permitting one is equivalent to permitting arbitrary execution, so it needs
 * the target's explicit `allowShellInterpreters: true` acknowledgement.
 */
const INTERPRETER_BINARIES: ReadonlySet<string> = new Set([
  'sh', 'bash', 'zsh', 'dash', 'ksh', 'csh', 'tcsh', 'fish',
  'python', 'python2', 'python3', 'perl', 'ruby', 'node', 'deno', 'bun',
  'php', 'lua', 'awk', 'gawk', 'mawk', 'nawk',
  'env', 'xargs', 'find', 'sudo', 'doas', 'ssh', 'nohup', 'setsid', 'time',
  'make', 'parallel', 'eval', 'exec', 'source',
]);

/** Executable basename, so `/bin/sh` and `sh` are the same decision. */
function binaryBasename(command: string): string {
  const parts = command.split('/');
  return (parts[parts.length - 1] ?? command).toLowerCase();
}

/** Every probe kind the policy understands. */
const KNOWN_PROBE_KINDS: ReadonlySet<string> = new Set([
  'http_request',
  'shell_command',
  'code_read',
  'dependency_read',
  'prompt_injection',
  'process_check',
  'state_check',
  'evidence_check',
  'persistence_check',
]);

export class SecurityRuntime {
  private readonly policy: RuntimePolicy;
  private readonly repoRoot: string;

  constructor(options?: Partial<RuntimePolicy> & { repoRoot?: string }) {
    this.policy = {
      ...DEFAULT_POLICY,
      ...options,
    };
    this.repoRoot = options?.repoRoot ?? process.cwd();
  }

  authorizeProbe(
    mode: SecurityMode,
    target: RuntimeTargetContext,
    probe: RuntimeProbeContext,
  ): RuntimeDecision {
    if (this.killSwitchIsActive()) {
      return blocked(mode, 'Kill switch is active');
    }

    // Deny-by-default: an unknown kind (arriving through an unchecked cast) must
    // not fall through to "allowed".
    if (!KNOWN_PROBE_KINDS.has(probe.kind)) {
      return blocked(mode, `Unrecognised probe kind: ${String(probe.kind)}`);
    }

    // A missing or non-finite timeout must not bypass the cap: `NaN > max` is
    // false, which previously let an unbounded probe through.
    if (!Number.isFinite(probe.timeoutMs) || probe.timeoutMs <= 0) {
      return blocked(mode, `Probe timeout is missing or invalid: ${String(probe.timeoutMs)}`);
    }

    if (probe.timeoutMs > this.policy.maxTimeoutMs) {
      return blocked(mode, `Timeout ${probe.timeoutMs}ms exceeds policy maximum`);
    }

    if (probe.kind === 'shell_command' || probe.kind === 'process_check' || probe.kind === 'persistence_check') {
      if (this.policy.blockedShellEnvironments.includes(target.environment)) {
        return blocked(mode, `Shell-adjacent probes are disabled in ${target.environment}`);
      }

      const command = probe.command ?? [];
      // Executable probe kinds must declare what they run, otherwise a filter
      // over the command string inspects nothing and always passes.
      if (command.length === 0) {
        return blocked(mode, `${probe.kind} probe did not declare a command`);
      }

      // Allow-list, not denylist: the target declares which binaries it
      // permits. No declaration means no shell execution.
      const allowed = target.allowedShellCommands ?? [];
      if (allowed.length === 0) {
        return blocked(
          mode,
          `Target ${target.id} declares no allowedShellCommands, so ${probe.kind} probes are disabled. ` +
            'Declare the binaries this target permits (and allowShellInterpreters: true if one of them is an interpreter).',
        );
      }

      const binary = binaryBasename(command[0]!);
      const normalisedAllowed = allowed.map((entry) => binaryBasename(entry));
      if (!normalisedAllowed.includes(binary)) {
        return blocked(
          mode,
          `Binary "${binary}" is not in the allowedShellCommands for target ${target.id} (${normalisedAllowed.join(', ') || 'none'})`,
        );
      }

      if (INTERPRETER_BINARIES.has(binary) && target.allowShellInterpreters !== true) {
        return blocked(
          mode,
          `Binary "${binary}" is an interpreter or indirection; permitting it allows arbitrary code execution. ` +
            'Set allowShellInterpreters: true on the target if that is intended.',
        );
      }

      // Defence in depth: the historical fragment denylist still applies.
      const joined = command.join(' ').toLowerCase();
      const blockedFragment = this.policy.destructiveCommandFragments.find((fragment) =>
        joined.includes(fragment),
      );
      if (blockedFragment) {
        return blocked(mode, `Shell probe contains blocked fragment: ${blockedFragment}`);
      }
    }

    if (
      probe.kind === 'code_read' ||
      probe.kind === 'dependency_read' ||
      probe.kind === 'state_check' ||
      probe.kind === 'evidence_check'
    ) {
      if (
        target.environment === 'staging' ||
        target.environment === 'hosted_authorized' ||
        target.environment === 'production_shadow'
      ) {
        return blocked(mode, `Code-adjacent probes are disabled in ${target.environment}`);
      }
    }

    if (
      (probe.kind === 'http_request' || probe.kind === 'prompt_injection') &&
      (target.environment === 'staging' || target.environment === 'production_shadow')
    ) {
      const method = (probe.method ?? 'GET').toUpperCase();
      if (!['GET', 'HEAD'].includes(method)) {
        return blocked(mode, `HTTP method ${method} is not allowed in ${target.environment}`);
      }
      if (probe.body && probe.body.length > 0) {
        return blocked(mode, `HTTP bodies are not allowed in ${target.environment}`);
      }
    }

    // hosted_authorized — hosted probing tier with strict gates
    if (
      (probe.kind === 'http_request' || probe.kind === 'prompt_injection') &&
      target.environment === 'hosted_authorized'
    ) {
      const method = (probe.method ?? 'GET').toUpperCase();
      if (!['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
        return blocked(mode, `HTTP method ${method} not recognised for hosted_authorized tier`);
      }
    }

    return {
      allowed: true,
      observedSafetyState: 'allowed',
      reason: null,
      mode,
    };
  }

  private killSwitchIsActive(): boolean {
    return existsSync(resolve(this.repoRoot, this.policy.killSwitchPath));
  }
}

function blocked(mode: SecurityMode, reason: string): RuntimeDecision {
  return {
    allowed: false,
    observedSafetyState: 'blocked',
    reason,
    mode,
  };
}
