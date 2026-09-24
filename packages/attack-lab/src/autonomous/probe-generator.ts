/**
 * Probe generator — translates model-generated PlannerProbeRequests
 * into validated SecurityLabProbe objects. Rejects anything the probe
 * system can't express and feeds rejections back to planner memory.
 */

import type { PlannerProbeRequest } from './schemas.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface GeneratedProbe {
  kind: string;
  parameters: Record<string, unknown>;
  fingerprint: string;
}

export interface ProbeGenerationResult {
  generated: GeneratedProbe[];
  rejected: RejectedProbe[];
}

export interface RejectedProbe {
  request: PlannerProbeRequest;
  reason: string;
}

// ---------------------------------------------------------------------------
// Translation
// ---------------------------------------------------------------------------

export function translateProbeRequests(
  requests: PlannerProbeRequest[],
): ProbeGenerationResult {
  const generated: GeneratedProbe[] = [];
  const rejected: RejectedProbe[] = [];

  for (const request of requests) {
    const result = translateSingle(request);
    if (result.ok) {
      generated.push(result.probe);
    } else {
      rejected.push({ request, reason: result.reason });
    }
  }

  return { generated, rejected };
}

function translateSingle(
  request: PlannerProbeRequest,
): { ok: true; probe: GeneratedProbe } | { ok: false; reason: string } {
  switch (request.targetKind) {
    case 'http':
      return translateHttpProbe(request);
    case 'shell':
      return translateShellProbe(request);
    case 'code':
      return translateCodeProbe(request);
    case 'dependency':
      return translateDependencyProbe(request);
    case 'prompt':
      return translatePromptProbe(request);
    case 'process':
      return translateProcessProbe(request);
    case 'state':
      return translateStateProbe(request);
    case 'evidence':
      return translateEvidenceProbe(request);
    case 'persistence':
      return translatePersistenceProbe(request);
    default:
      return { ok: false, reason: `Unknown target kind: ${request.targetKind}` };
  }
}

function translateHttpProbe(
  request: PlannerProbeRequest,
): { ok: true; probe: GeneratedProbe } | { ok: false; reason: string } {
  const params = request.parameters;
  const method = (params['method'] as string ?? 'GET').toUpperCase();
  const path = params['path'] as string;

  if (!path) return { ok: false, reason: 'HTTP probe requires path parameter' };

  const validMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'];
  if (!validMethods.includes(method)) {
    return { ok: false, reason: `Invalid HTTP method: ${method}` };
  }

  const probe: GeneratedProbe = {
    kind: 'http_request',
    parameters: {
      method,
      path,
      headers: params['headers'] ?? {},
      body: params['body'],
      timeoutMs: params['timeoutMs'] ?? 10000,
    },
    fingerprint: `http:${method}:${path}:${JSON.stringify(params['headers'] ?? {})}`,
  };

  return { ok: true, probe };
}

function translateShellProbe(
  request: PlannerProbeRequest,
): { ok: true; probe: GeneratedProbe } | { ok: false; reason: string } {
  const params = request.parameters;
  const command = params['command'] as string[];

  if (!command || !Array.isArray(command) || command.length === 0) {
    return { ok: false, reason: 'Shell probe requires command array parameter' };
  }

  // Block destructive commands at translation time too
  const joined = command.join(' ').toLowerCase();
  const blocked = ['rm -rf', 'pkill', 'killall', 'shutdown', 'reboot', 'crontab', 'launchctl'];
  for (const b of blocked) {
    if (joined.includes(b)) {
      return { ok: false, reason: `Shell command contains blocked fragment: ${b}` };
    }
  }

  const probe: GeneratedProbe = {
    kind: 'shell_command',
    parameters: {
      command,
      timeoutMs: params['timeoutMs'] ?? 10000,
      env: params['env'] ?? {},
    },
    fingerprint: `shell:${command.join(':')}`,
  };

  return { ok: true, probe };
}

function translateCodeProbe(
  request: PlannerProbeRequest,
): { ok: true; probe: GeneratedProbe } | { ok: false; reason: string } {
  const params = request.parameters;
  const action = params['action'] as string ?? request.action;

  const validActions = ['read_file', 'list_dir', 'search_pattern'];
  if (!validActions.includes(action)) {
    return { ok: false, reason: `Invalid code action: ${action}` };
  }

  const probe: GeneratedProbe = {
    kind: 'code_read',
    parameters: {
      action,
      filePath: params['filePath'],
      pattern: params['pattern'],
      maxDepth: params['maxDepth'] ?? 3,
      timeoutMs: params['timeoutMs'] ?? 10000,
    },
    fingerprint: `code:${action}:${params['filePath'] ?? params['pattern'] ?? ''}`,
  };

  return { ok: true, probe };
}

function translateDependencyProbe(
  request: PlannerProbeRequest,
): { ok: true; probe: GeneratedProbe } | { ok: false; reason: string } {
  const params = request.parameters;
  const action = params['action'] as string ?? request.action;

  const validActions = ['inspect_lockfile', 'check_scripts', 'scan_provenance', 'diff_lockfile'];
  if (!validActions.includes(action)) {
    return { ok: false, reason: `Invalid dependency action: ${action}` };
  }

  const probe: GeneratedProbe = {
    kind: 'dependency_read',
    parameters: {
      action,
      filePath: params['filePath'],
      timeoutMs: params['timeoutMs'] ?? 10000,
    },
    fingerprint: `dep:${action}:${params['filePath'] ?? ''}`,
  };

  return { ok: true, probe };
}

function translatePromptProbe(
  request: PlannerProbeRequest,
): { ok: true; probe: GeneratedProbe } | { ok: false; reason: string } {
  const params = request.parameters;
  const action = params['action'] as string ?? request.action;
  const payload = params['payload'] as string;
  const targetField = params['targetField'] as string;
  const successIndicator = params['successIndicator'] as string;

  const validActions = ['field_injection', 'tool_output_smuggle', 'system_prompt_leak'];
  if (!validActions.includes(action)) {
    return { ok: false, reason: `Invalid prompt action: ${action}` };
  }
  if (!payload || !targetField || !successIndicator) {
    return { ok: false, reason: 'Prompt probe requires payload, targetField, and successIndicator' };
  }

  return {
    ok: true,
    probe: {
      kind: 'prompt_injection',
      parameters: {
        action,
        payload,
        targetField,
        successIndicator,
        endpoint: params['endpoint'],
        timeoutMs: params['timeoutMs'] ?? 10000,
      },
      fingerprint: `prompt:${action}:${targetField}:${successIndicator}`,
    },
  };
}

function translateProcessProbe(
  request: PlannerProbeRequest,
): { ok: true; probe: GeneratedProbe } | { ok: false; reason: string } {
  const params = request.parameters;
  const action = params['action'] as string ?? request.action;
  const validActions = ['env_scan', 'fd_scan', 'proc_self_read', 'credential_search'];

  if (!validActions.includes(action)) {
    return { ok: false, reason: `Invalid process action: ${action}` };
  }

  return {
    ok: true,
    probe: {
      kind: 'process_check',
      parameters: {
        action,
        searchPatterns: params['searchPatterns'] ?? [],
        timeoutMs: params['timeoutMs'] ?? 10000,
      },
      fingerprint: `process:${action}:${JSON.stringify(params['searchPatterns'] ?? [])}`,
    },
  };
}

function translateStateProbe(
  request: PlannerProbeRequest,
): { ok: true; probe: GeneratedProbe } | { ok: false; reason: string } {
  const params = request.parameters;
  const action = params['action'] as string ?? request.action;
  const filePath = params['filePath'] as string;
  const validActions = ['writability_check', 'tamper_detect', 'config_mutation_check'];

  if (!validActions.includes(action)) {
    return { ok: false, reason: `Invalid state action: ${action}` };
  }
  if (!filePath) {
    return { ok: false, reason: 'State probe requires filePath' };
  }

  return {
    ok: true,
    probe: {
      kind: 'state_check',
      parameters: {
        action,
        filePath,
        expectedHash: params['expectedHash'],
        timeoutMs: params['timeoutMs'] ?? 10000,
      },
      fingerprint: `state:${action}:${filePath}`,
    },
  };
}

function translateEvidenceProbe(
  request: PlannerProbeRequest,
): { ok: true; probe: GeneratedProbe } | { ok: false; reason: string } {
  const params = request.parameters;
  const action = params['action'] as string ?? request.action;
  const filePath = params['filePath'] as string;
  const validActions = ['manifest_verify', 'label_writability', 'baseline_drift'];

  if (!validActions.includes(action)) {
    return { ok: false, reason: `Invalid evidence action: ${action}` };
  }
  if (!filePath) {
    return { ok: false, reason: 'Evidence probe requires filePath' };
  }

  return {
    ok: true,
    probe: {
      kind: 'evidence_check',
      parameters: {
        action,
        filePath,
        expectedHashes: params['expectedHashes'] ?? {},
        timeoutMs: params['timeoutMs'] ?? 10000,
      },
      fingerprint: `evidence:${action}:${filePath}`,
    },
  };
}

function translatePersistenceProbe(
  request: PlannerProbeRequest,
): { ok: true; probe: GeneratedProbe } | { ok: false; reason: string } {
  const params = request.parameters;
  const action = params['action'] as string ?? request.action;
  const validActions = ['cron_check', 'launchd_check', 'background_process_check', 'startup_check'];

  if (!validActions.includes(action)) {
    return { ok: false, reason: `Invalid persistence action: ${action}` };
  }

  return {
    ok: true,
    probe: {
      kind: 'persistence_check',
      parameters: {
        action,
        timeoutMs: params['timeoutMs'] ?? 10000,
      },
      fingerprint: `persistence:${action}`,
    },
  };
}
