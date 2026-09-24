import { execFile } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { basename, dirname, resolve } from 'node:path';
import { promisify } from 'node:util';
import type { InvestigationTarget } from '../../autonomous/target-profile.js';
import { prepareLocalAuthBootstrap, type LocalAuthBootstrapResult } from './auth-bootstrap.js';
import { resolveRequestUrl } from '../shared/url-policy.js';

const execFileAsync = promisify(execFile);

export interface LocalTargetSession {
  bootstrap?: LocalAuthBootstrapResult | null;
  composeOverridePath?: string;
  started: boolean;
  warnings?: string[];
  stop(): Promise<void>;
}

export async function prepareLocalTargetSession(
  target: InvestigationTarget,
  campaignDir: string,
): Promise<LocalTargetSession> {
  const bootstrap = await prepareLocalAuthBootstrap(target, campaignDir);
  const startup = asCommandSpec(target.localStartup);
  const shutdown = asCommandSpec(target.localShutdown);
  const warnings: string[] = [];

  let composeOverridePath: string | undefined;
  if (bootstrap?.environment && startup && isDockerComposeCommand(startup.command, startup.args)) {
    composeOverridePath = await writeComposeOverride(target, campaignDir, bootstrap.environment);
  }

  if (startup && shutdown && shouldResetLocalTargetBeforeStart(target) && isDockerComposeCommand(startup.command, startup.args)) {
    const cleanupCommand = applyComposeDownPolicy(applyComposeOverride(shutdown, composeOverridePath), target);
    await executeConfiguredCommand(cleanupCommand);
  }

  if (startup) {
    const startedCommand = applyComposeBuildPolicy(applyComposeOverride(startup, composeOverridePath), target);
    const readinessTimeoutMs = resolveReadinessTimeoutMs(target, startedCommand.timeoutMs);
    let startupError: Error | null = null;
    try {
      await executeConfiguredCommand(startedCommand);
    } catch (error) {
      startupError = toError(error);
    }

    try {
      await waitForReadiness(target, readinessTimeoutMs);
    } catch (readinessError) {
      if (startupError) {
        throw new Error(
          `Local target startup failed for ${target.id}: ${startupError.message}`,
          { cause: readinessError },
        );
      }
      throw readinessError;
    }

    if (startupError) {
      warnings.push(
        `Startup command reported an error for ${target.id}, but readiness succeeded: ${startupError.message}`,
      );
    }
  }

  return {
    bootstrap,
    composeOverridePath,
    started: Boolean(startup),
    warnings,
    stop: async () => {
      if (!shutdown) {
        return;
      }
      await executeConfiguredCommand(applyComposeDownPolicy(applyComposeOverride(shutdown, composeOverridePath), target));
    },
  };
}

interface CommandSpec {
  command: string;
  args: string[];
  cwd?: string;
  env?: Record<string, string>;
  timeoutMs: number;
}

function asCommandSpec(value: Record<string, unknown> | undefined): CommandSpec | null {
  if (!value || typeof value['command'] !== 'string') {
    return null;
  }

  return {
    command: value['command'],
    args: Array.isArray(value['args']) ? value['args'].filter((entry): entry is string => typeof entry === 'string') : [],
    cwd: typeof value['cwd'] === 'string' ? value['cwd'] : undefined,
    env: isRecordOfStrings(value['env']) ? value['env'] : undefined,
    timeoutMs: typeof value['timeoutMs'] === 'number' ? value['timeoutMs'] : 120_000,
  };
}

function isRecordOfStrings(value: unknown): value is Record<string, string> {
  return Boolean(value) && typeof value === 'object' && Object.values(value as Record<string, unknown>).every((entry) => typeof entry === 'string');
}

function toError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

async function executeConfiguredCommand(command: CommandSpec): Promise<void> {
  await execFileAsync(command.command, command.args, {
    cwd: command.cwd,
    env: {
      ...process.env,
      ...(command.env ?? {}),
    },
    timeout: command.timeoutMs,
    maxBuffer: 50 * 1024 * 1024,
  });
}

function isDockerComposeCommand(command: string, args: string[]): boolean {
  return basename(command) === 'docker' && args[0] === 'compose';
}

function applyComposeOverride(command: CommandSpec, composeOverridePath?: string): CommandSpec {
  if (!composeOverridePath || !isDockerComposeCommand(command.command, command.args)) {
    return command;
  }

  const args = [...command.args];
  if (!args.includes('-f') && !args.includes('--file')) {
    args.splice(1, 0, '-f', 'docker-compose.yml', '-f', composeOverridePath);
    return { ...command, args };
  }

  const insertAt = findComposeSubcommandIndex(args);
  args.splice(insertAt, 0, '-f', composeOverridePath);
  return { ...command, args };
}

function applyComposeBuildPolicy(command: CommandSpec, target: InvestigationTarget): CommandSpec {
  if (!isDockerComposeCommand(command.command, command.args)) {
    return command;
  }

  const args = [...command.args];
  const subcommandIndex = findComposeSubcommandIndex(args);
  const subcommand = args[subcommandIndex];
  if (subcommand !== 'up') {
    return command;
  }

  const sidecar = (target.linuxSidecar as Record<string, unknown> | undefined) ?? {};
  const hasBuildOverride = Object.values(getComposeServiceOverrides(target)).some((override) => Boolean(override.build));
  const buildOnStartup = sidecar['buildOnStartup'] === true || hasBuildOverride;
  if (!buildOnStartup || args.includes('--build')) {
    return command;
  }

  args.splice(subcommandIndex + 1, 0, '--build');
  return { ...command, args };
}

function applyComposeDownPolicy(command: CommandSpec, target: InvestigationTarget): CommandSpec {
  if (!isDockerComposeCommand(command.command, command.args)) {
    return command;
  }

  const args = [...command.args];
  const subcommandIndex = findComposeSubcommandIndex(args);
  const subcommand = args[subcommandIndex];
  if (subcommand !== 'down') {
    return command;
  }

  const policy = (target.verificationPolicy as Record<string, unknown> | undefined) ?? {};
  const shouldRemoveVolumes = policy['removeVolumesOnShutdown'] === true || policy['cleanStartup'] === true;
  if (!shouldRemoveVolumes) {
    return command;
  }

  if (!args.includes('-v') && !args.includes('--volumes')) {
    args.splice(subcommandIndex + 1, 0, '-v');
  }
  if (!args.includes('--remove-orphans')) {
    args.splice(subcommandIndex + 1, 0, '--remove-orphans');
  }
  return { ...command, args };
}

function shouldResetLocalTargetBeforeStart(target: InvestigationTarget): boolean {
  const policy = (target.verificationPolicy as Record<string, unknown> | undefined) ?? {};
  return policy['cleanStartup'] === true;
}

function findComposeSubcommandIndex(args: string[]): number {
  let index = 1;
  while (index < args.length) {
    const entry = args[index];
    if (entry === '-f' || entry === '--file' || entry === '--project-directory' || entry === '-p' || entry === '--project-name') {
      index += 2;
      continue;
    }
    if (entry.startsWith('-')) {
      index += 1;
      continue;
    }
    break;
  }
  return index;
}

async function writeComposeOverride(
  target: InvestigationTarget,
  campaignDir: string,
  environment: Record<string, string>,
): Promise<string> {
  const composeService = getComposeService(target);
  if (!composeService) {
    throw new Error(`Target ${target.id} requested auth bootstrap but no linuxSidecar.composeService is configured`);
  }

  const markerEntries = Array.isArray((target.processDecoys as Record<string, unknown> | undefined)?.['envMarkers'])
    ? ((target.processDecoys as Record<string, unknown>)['envMarkers'] as string[]).map((marker, index) => [`SECURITY_LAB_MARKER_${index + 1}`, marker] as const)
    : [];
  const serviceOverrides = getComposeServiceOverrides(target);
  const composeServiceOverride = serviceOverrides[composeService] ?? {};
  composeServiceOverride.environment = {
    ...(composeServiceOverride.environment ?? {}),
    ...environment,
    ...Object.fromEntries(markerEntries),
  };
  serviceOverrides[composeService] = composeServiceOverride;

  const overridePath = resolve(campaignDir, 'bootstrap', `${target.id}.compose.override.yaml`);
  await mkdir(resolve(overridePath, '..'), { recursive: true });
  const yaml = [
    'services:',
    ...Object.entries(serviceOverrides).flatMap(([service, override]) => renderComposeServiceOverride(service, override)),
    '',
  ].join('\n');
  await writeFile(overridePath, yaml, 'utf8');
  return overridePath;
}

interface ComposeServiceOverride {
  environment?: Record<string, string>;
  ports?: string[];
  build?: ComposeBuildOverride;
  healthcheck?: ComposeHealthcheckOverride;
}

interface ComposeBuildOverride {
  context?: string;
  dockerfile?: string;
  args?: Record<string, string>;
}

interface ComposeHealthcheckOverride {
  test?: string | string[];
  interval?: string;
  timeout?: string;
  retries?: number;
  startPeriod?: string;
}

function getComposeServiceOverrides(target: InvestigationTarget): Record<string, ComposeServiceOverride> {
  const sidecar = (target.linuxSidecar as Record<string, unknown> | undefined) ?? {};
  const rawOverrides = sidecar['serviceOverrides'];
  if (!rawOverrides || typeof rawOverrides !== 'object') {
    return {};
  }

  const normalized: Record<string, ComposeServiceOverride> = {};
  for (const [service, override] of Object.entries(rawOverrides as Record<string, unknown>)) {
    if (!override || typeof override !== 'object') {
      continue;
    }
    const record = override as Record<string, unknown>;
    const ports = Array.isArray(record['ports'])
      ? record['ports'].filter((entry): entry is string => typeof entry === 'string' && entry.length > 0)
      : undefined;
    const environment = isRecordOfStrings(record['environment']) ? record['environment'] : undefined;
    const build = parseBuildOverride(record['build'], target);
    const healthcheck = parseHealthcheckOverride(record['healthcheck']);
    normalized[service] = {
      ...(ports?.length ? { ports } : {}),
      ...(environment ? { environment } : {}),
      ...(build ? { build } : {}),
      ...(healthcheck ? { healthcheck } : {}),
    };
  }
  return normalized;
}

function renderComposeServiceOverride(service: string, override: ComposeServiceOverride): string[] {
  const lines = [`  ${service}:`];
  if (override.environment && Object.keys(override.environment).length > 0) {
    lines.push('    environment:');
    for (const [key, value] of Object.entries(override.environment)) {
      lines.push(`      ${key}: ${JSON.stringify(value)}`);
    }
  }
  if (override.ports && override.ports.length > 0) {
    lines.push('    ports: !override');
    for (const port of override.ports) {
      lines.push(`      - ${JSON.stringify(port)}`);
    }
  }
  if (override.build) {
    lines.push('    build:');
    if (override.build.context) {
      lines.push(`      context: ${JSON.stringify(override.build.context)}`);
    }
    if (override.build.dockerfile) {
      lines.push(`      dockerfile: ${JSON.stringify(override.build.dockerfile)}`);
    }
    if (override.build.args && Object.keys(override.build.args).length > 0) {
      lines.push('      args:');
      for (const [key, value] of Object.entries(override.build.args)) {
        lines.push(`        ${key}: ${JSON.stringify(value)}`);
      }
    }
  }
  if (override.healthcheck) {
    lines.push('    healthcheck:');
    const test = override.healthcheck.test;
    if (Array.isArray(test) && test.length > 0) {
      lines.push('      test:');
      for (const part of test) {
        lines.push(`        - ${JSON.stringify(part)}`);
      }
    } else if (typeof test === 'string' && test.length > 0) {
      lines.push(`      test: ${JSON.stringify(test)}`);
    }
    if (override.healthcheck.interval) {
      lines.push(`      interval: ${JSON.stringify(override.healthcheck.interval)}`);
    }
    if (override.healthcheck.timeout) {
      lines.push(`      timeout: ${JSON.stringify(override.healthcheck.timeout)}`);
    }
    if (typeof override.healthcheck.retries === 'number') {
      lines.push(`      retries: ${override.healthcheck.retries}`);
    }
    if (override.healthcheck.startPeriod) {
      lines.push(`      start_period: ${JSON.stringify(override.healthcheck.startPeriod)}`);
    }
  }
  return lines;
}

function parseBuildOverride(value: unknown, target: InvestigationTarget): ComposeBuildOverride | undefined {
  if (!value || typeof value !== 'object') {
    return undefined;
  }

  const record = value as Record<string, unknown>;
  const profileDir = target.profilePath ? dirname(target.profilePath) : process.cwd();
  const context = typeof record['context'] === 'string'
    ? resolveOverridePath(record['context'], profileDir, target.repoRoot)
    : undefined;
  const dockerfile = typeof record['dockerfile'] === 'string'
    ? resolveOverridePath(record['dockerfile'], profileDir, target.repoRoot)
    : undefined;
  const args = isRecordOfStrings(record['args']) ? record['args'] : undefined;

  if (!context && !dockerfile && !args) {
    return undefined;
  }

  return {
    ...(context ? { context } : {}),
    ...(dockerfile ? { dockerfile } : {}),
    ...(args ? { args } : {}),
  };
}

function parseHealthcheckOverride(value: unknown): ComposeHealthcheckOverride | undefined {
  if (!value || typeof value !== 'object') {
    return undefined;
  }

  const record = value as Record<string, unknown>;
  const rawTest = record['test'];
  const test = Array.isArray(rawTest)
    ? rawTest.filter((entry): entry is string => typeof entry === 'string' && entry.length > 0)
    : typeof rawTest === 'string' && rawTest.length > 0
      ? rawTest
      : undefined;
  const interval = typeof record['interval'] === 'string' ? record['interval'] : undefined;
  const timeout = typeof record['timeout'] === 'string' ? record['timeout'] : undefined;
  const retries = typeof record['retries'] === 'number' ? record['retries'] : undefined;
  const startPeriod = typeof record['startPeriod'] === 'string'
    ? record['startPeriod']
    : typeof record['start_period'] === 'string'
      ? record['start_period']
      : undefined;

  if (!test && !interval && !timeout && retries == null && !startPeriod) {
    return undefined;
  }

  return {
    ...(test ? { test } : {}),
    ...(interval ? { interval } : {}),
    ...(timeout ? { timeout } : {}),
    ...(retries != null ? { retries } : {}),
    ...(startPeriod ? { startPeriod } : {}),
  };
}

function resolveOverridePath(value: string, profileDir: string, repoRoot?: string): string {
  if (value.startsWith('.') || value.startsWith('..')) {
    return resolve(profileDir, value);
  }
  if (repoRoot && !value.startsWith('/')) {
    return resolve(repoRoot, value);
  }
  return value;
}

function getComposeService(target: InvestigationTarget): string | undefined {
  const sidecar = (target.linuxSidecar as Record<string, unknown> | undefined) ?? {};
  return typeof sidecar['composeService'] === 'string'
    ? sidecar['composeService']
    : typeof sidecar['targetContainer'] === 'string'
      ? sidecar['targetContainer']
      : undefined;
}

async function waitForReadiness(target: InvestigationTarget, fallbackTimeoutMs: number): Promise<void> {
  const startup = (target.localStartup as Record<string, unknown> | undefined) ?? {};
  const readiness = (startup['readinessCheck'] as Record<string, unknown> | undefined) ?? {};
  if (!target.baseUrl) {
    return;
  }

  const method = typeof readiness['method'] === 'string' ? readiness['method'].toUpperCase() : 'GET';
  const path = typeof readiness['path'] === 'string' ? readiness['path'] : '/';
  const expectStatus = typeof readiness['expectStatus'] === 'number' ? readiness['expectStatus'] : undefined;
  const expectStatusIn = Array.isArray(readiness['expectStatusIn'])
    ? readiness['expectStatusIn'].filter((entry): entry is number => typeof entry === 'number')
    : undefined;
  const timeoutMs = typeof readiness['timeoutMs'] === 'number' ? readiness['timeoutMs'] : fallbackTimeoutMs;
  const intervalMs = typeof readiness['intervalMs'] === 'number' ? readiness['intervalMs'] : 1500;
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    try {
      const response = await fetch(resolveRequestUrl(path, target.baseUrl, { label: 'readiness check path' }), {
        method,
        signal: AbortSignal.timeout(Math.min(intervalMs, 5_000)),
      });
      if ((expectStatus != null && response.status === expectStatus) || (expectStatusIn?.includes(response.status) ?? (response.status >= 200 && response.status < 500))) {
        return;
      }
    } catch {
      // keep polling until deadline
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, intervalMs));
  }

  throw new Error(`Timed out waiting for ${target.id} readiness at ${path}`);
}

function resolveReadinessTimeoutMs(target: InvestigationTarget, fallbackTimeoutMs: number): number {
  const startup = (target.localStartup as Record<string, unknown> | undefined) ?? {};
  const readiness = (startup['readinessCheck'] as Record<string, unknown> | undefined) ?? {};
  return typeof readiness['timeoutMs'] === 'number' ? readiness['timeoutMs'] : fallbackTimeoutMs;
}
