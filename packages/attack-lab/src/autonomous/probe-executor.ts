import type { ProbeObservation } from '../../../evidence-plane/src/contracts.js';
import type { RuntimeProbeContext, RuntimeTargetContext } from '../../../security-runtime/src/contracts.js';
import { runCodeProbe } from '../probes/code-probe.js';
import { runDependencyProbe } from '../probes/dependency-probe.js';
import { runEvidenceProbe } from '../probes/evidence-probe.js';
import { runHttpProbe } from '../probes/http-probe.js';
import { runPersistenceProbe } from '../probes/persistence-probe.js';
import { runProcessProbe } from '../probes/process-probe.js';
import { runPromptProbe } from '../probes/prompt-probe.js';
import { runShellProbe } from '../probes/shell-probe.js';
import { runStateProbe } from '../probes/state-probe.js';
import type { GeneratedProbe } from './probe-generator.js';
import type { InvestigationTarget } from './target-profile.js';

export async function executeGeneratedProbe(
  probe: GeneratedProbe,
  target: InvestigationTarget,
): Promise<ProbeObservation> {
  switch (probe.kind) {
    case 'http_request':
      return runHttpProbe(
        {
          kind: 'http_request',
          method: (probe.parameters['method'] as 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD') ?? 'GET',
          path: String(probe.parameters['path']),
          headers: asStringRecord(probe.parameters['headers']),
          body: asOptionalString(probe.parameters['body']),
          timeoutMs: asNumber(probe.parameters['timeoutMs'], 10000),
        },
        {
          kind: 'http',
          id: target.id,
          environment: target.environment,
          baseUrl: requireBaseUrl(target, probe.kind),
          defaultHeaders: target.defaultHeaders,
        },
      );
    case 'shell_command':
      return runShellProbe(
        {
          kind: 'shell_command',
          command: asStringArray(probe.parameters['command']),
          timeoutMs: asNumber(probe.parameters['timeoutMs'], 10000),
          cwd: target.cwd,
          env: asStringRecord(probe.parameters['env']),
        },
        {
          kind: 'shell',
          id: target.id,
          environment: target.environment,
          cwd: target.cwd,
          env: target.env,
        },
      );
    case 'code_read':
      return runCodeProbe(
        {
          kind: 'code_read',
          action: probe.parameters['action'] as 'read_file' | 'list_dir' | 'search_pattern',
          filePath: asOptionalString(probe.parameters['filePath']),
          pattern: asOptionalString(probe.parameters['pattern']),
          maxDepth: asOptionalNumber(probe.parameters['maxDepth']),
          timeoutMs: asNumber(probe.parameters['timeoutMs'], 10000),
        },
        {
          kind: 'code',
          id: target.id,
          environment: target.environment,
          repoRoot: requireRepoRoot(target, probe.kind),
          includePaths: target.includePaths,
          excludePaths: target.excludePaths,
        },
      );
    case 'dependency_read':
      return runDependencyProbe(
        {
          kind: 'dependency_read',
          action: probe.parameters['action'] as 'inspect_lockfile' | 'check_scripts' | 'scan_provenance' | 'diff_lockfile',
          filePath: asOptionalString(probe.parameters['filePath']),
          previousContent: asOptionalString(probe.parameters['previousContent']),
          timeoutMs: asNumber(probe.parameters['timeoutMs'], 10000),
        },
        {
          kind: 'dependency',
          id: target.id,
          environment: target.environment,
          repoRoot: requireRepoRoot(target, probe.kind),
        },
      );
    case 'prompt_injection':
      return runPromptProbe(
        {
          kind: 'prompt_injection',
          action: probe.parameters['action'] as 'field_injection' | 'tool_output_smuggle' | 'system_prompt_leak',
          payload: String(probe.parameters['payload']),
          targetField: String(probe.parameters['targetField']),
          successIndicator: String(probe.parameters['successIndicator']),
          endpoint: asOptionalString(probe.parameters['endpoint']),
          timeoutMs: asNumber(probe.parameters['timeoutMs'], 10000),
        },
        requireBaseUrl(target, probe.kind),
        target.defaultHeaders,
      );
    case 'process_check':
      return runProcessProbe({
        kind: 'process_check',
        action: probe.parameters['action'] as 'env_scan' | 'fd_scan' | 'proc_self_read' | 'credential_search',
        searchPatterns: asStringArray(probe.parameters['searchPatterns']),
        timeoutMs: asNumber(probe.parameters['timeoutMs'], 10000),
      });
    case 'state_check':
      return runStateProbe(
        {
          kind: 'state_check',
          action: probe.parameters['action'] as 'writability_check' | 'tamper_detect' | 'config_mutation_check',
          filePath: String(probe.parameters['filePath']),
          expectedHash: asOptionalString(probe.parameters['expectedHash']),
          timeoutMs: asNumber(probe.parameters['timeoutMs'], 10000),
        },
        requireRepoRoot(target, probe.kind),
      );
    case 'evidence_check':
      return runEvidenceProbe(
        {
          kind: 'evidence_check',
          action: probe.parameters['action'] as 'manifest_verify' | 'label_writability' | 'baseline_drift',
          filePath: String(probe.parameters['filePath']),
          expectedHashes: asRecord(probe.parameters['expectedHashes']),
          timeoutMs: asNumber(probe.parameters['timeoutMs'], 10000),
        },
        requireRepoRoot(target, probe.kind),
      );
    case 'persistence_check':
      return runPersistenceProbe({
        kind: 'persistence_check',
        action: probe.parameters['action'] as 'cron_check' | 'launchd_check' | 'background_process_check' | 'startup_check',
        timeoutMs: asNumber(probe.parameters['timeoutMs'], 10000),
      });
    default:
      return {
        kind: probe.kind,
        stderr: `Unsupported generated probe kind: ${probe.kind}`,
        exitCode: 1,
        durationMs: 0,
      };
  }
}

export function buildRuntimeTargetContext(target: InvestigationTarget): RuntimeTargetContext {
  return {
    id: target.id,
    kind: target.kind,
    environment: target.environment,
    baseUrl: target.baseUrl,
    cwd: target.cwd,
    repoRoot: target.repoRoot,
  };
}

export function buildRuntimeProbeContext(probe: GeneratedProbe): RuntimeProbeContext {
  const body =
    typeof probe.parameters['body'] === 'string'
      ? (probe.parameters['body'] as string)
      : probe.kind === 'prompt_injection'
        ? JSON.stringify({
            payload: probe.parameters['payload'],
            targetField: probe.parameters['targetField'],
            successIndicator: probe.parameters['successIndicator'],
          })
        : undefined;

  return {
    kind: probe.kind as RuntimeProbeContext['kind'],
    timeoutMs: asNumber(probe.parameters['timeoutMs'], 10000),
    method:
      probe.kind === 'prompt_injection'
        ? 'POST'
        : asOptionalString(probe.parameters['method']),
    body,
    command: asStringArrayOrUndefined(probe.parameters['command']),
  };
}

export function targetSupportsProbe(target: InvestigationTarget, probe: GeneratedProbe): boolean {
  return target.supportedProbeKinds.includes(probe.kind);
}

export function unsupportedTargetReason(target: InvestigationTarget, probe: GeneratedProbe): string {
  return `Target ${target.id} (${target.kind}) does not support ${probe.kind}; supported kinds: ${target.supportedProbeKinds.join(', ')}`;
}

export function formatObservation(probe: GeneratedProbe, observation: ProbeObservation): string {
  const parts = [`[${probe.kind}] ${probe.fingerprint}`];

  if (observation.statusCode != null) parts.push(`status=${observation.statusCode}`);
  if (observation.exitCode != null) parts.push(`exit=${observation.exitCode}`);

  const body = observation.responseBody ?? observation.stdout ?? observation.stderr ?? '';
  if (body) {
    parts.push(body.slice(0, 400));
  }

  return parts.join(' | ');
}

function requireBaseUrl(target: InvestigationTarget, probeKind: string): string {
  if (!target.baseUrl) {
    throw new Error(`Probe ${probeKind} requires baseUrl on target ${target.id}`);
  }
  return target.baseUrl;
}

function requireRepoRoot(target: InvestigationTarget, probeKind: string): string {
  if (!target.repoRoot) {
    throw new Error(`Probe ${probeKind} requires repoRoot on target ${target.id}`);
  }
  return target.repoRoot;
}

function asOptionalString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.map((item) => String(item)) : [];
}

function asStringArrayOrUndefined(value: unknown): string[] | undefined {
  return Array.isArray(value) ? value.map((item) => String(item)) : undefined;
}

function asNumber(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

function asOptionalNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function asStringRecord(value: unknown): Record<string, string> | undefined {
  if (!value || typeof value !== 'object') {
    return undefined;
  }

  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, entry]) => [key, String(entry)]),
  );
}

function asRecord(value: unknown): Record<string, string> | undefined {
  if (!value || typeof value !== 'object') {
    return undefined;
  }

  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, entry]) => [key, String(entry)]),
  );
}
