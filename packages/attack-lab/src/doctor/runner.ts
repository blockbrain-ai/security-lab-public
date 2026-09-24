import { execFile } from 'node:child_process';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { promisify } from 'node:util';
import type { InvestigationTarget } from '../autonomous/target-profile.js';
import { loadInvestigationTarget } from '../autonomous/target-profile.js';
import { prepareLocalAuthBootstrap } from '../verification/local-live/auth-bootstrap.js';

const execFileAsync = promisify(execFile);

export interface DoctorCheck {
  id: string;
  status: 'pass' | 'fail' | 'warn';
  message: string;
  details?: string;
}

export interface DoctorResult {
  ok: boolean;
  checks: DoctorCheck[];
  target?: InvestigationTarget;
  liveTarget?: InvestigationTarget;
  hostedTarget?: InvestigationTarget;
}

export interface DoctorOptions {
  targetRef?: string;
  targetId?: string;
  liveTargetRef?: string;
  liveTargetId?: string;
  hostedTargetRef?: string;
  preset?: 'serious-local' | 'serious-end-to-end' | 'smoke' | 'diagnostic';
  linuxRuntime?: 'container' | 'fail' | 'skip';
}

export async function runDoctor(options: DoctorOptions): Promise<DoctorResult> {
  const checks: DoctorCheck[] = [];

  await checkCommand('claude', ['--version'], checks, 'claude_binary', 'Claude Code CLI is available');
  await checkCommand('codex', ['--version'], checks, 'codex_binary', 'Codex CLI is available');

  await checkStatusCommand('claude', ['auth', 'status'], checks, 'claude_auth', 'Claude Code is authenticated');
  await checkStatusCommand('codex', ['login', 'status'], checks, 'codex_auth', 'Codex is authenticated');

  if (options.preset === 'serious-local' || options.preset === 'serious-end-to-end') {
    checks.push(
      process.env['OPENAI_API_KEY']
        ? { id: 'openai_api_key', status: 'pass', message: 'OPENAI_API_KEY is present' }
        : { id: 'openai_api_key', status: 'fail', message: 'OPENAI_API_KEY is required for serious runs' },
    );
    checks.push(
      process.env['GOOGLE_AI_API_KEY']
        ? { id: 'google_ai_api_key', status: 'pass', message: 'GOOGLE_AI_API_KEY is present' }
        : { id: 'google_ai_api_key', status: 'fail', message: 'GOOGLE_AI_API_KEY or GEMINI_API_KEY is required for serious runs' },
    );
  }

  const target = options.targetRef ? await loadTargetSafely(options.targetRef, options.targetId, 'target_profile', checks) : undefined;
  const liveTarget = options.liveTargetRef ? await loadTargetSafely(options.liveTargetRef, options.liveTargetId, 'live_target_profile', checks) : undefined;
  const hostedTarget = options.hostedTargetRef ? await loadTargetSafely(options.hostedTargetRef, undefined, 'hosted_target_profile', checks) : undefined;

  if (liveTarget?.linuxSidecar && options.linuxRuntime === 'container') {
    await checkDocker(checks);
  }

  if (liveTarget?.authBootstrap) {
    await checkLocalAuthBootstrap(liveTarget, checks);
  }

  const ok = checks.every((check) => check.status !== 'fail');
  return { ok, checks, target, liveTarget, hostedTarget };
}

async function loadTargetSafely(
  ref: string,
  id: string | undefined,
  checkId: string,
  checks: DoctorCheck[],
): Promise<InvestigationTarget | undefined> {
  try {
    const target = await loadInvestigationTarget(ref, id);
    checks.push({
      id: checkId,
      status: 'pass',
      message: `Loaded target profile ${target.id}`,
      details: target.profilePath ?? ref,
    });
    return target;
  } catch (error) {
    checks.push({
      id: checkId,
      status: 'fail',
      message: `Failed to load target profile ${ref}`,
      details: error instanceof Error ? error.message : String(error),
    });
    return undefined;
  }
}

async function checkCommand(
  command: string,
  args: string[],
  checks: DoctorCheck[],
  id: string,
  message: string,
): Promise<void> {
  try {
    const { stdout } = await execFileAsync(command, args, { timeout: 10_000, env: process.env });
    checks.push({ id, status: 'pass', message, details: stdout.trim() });
  } catch (error) {
    checks.push({
      id,
      status: 'fail',
      message: `${command} is unavailable`,
      details: error instanceof Error ? error.message : String(error),
    });
  }
}

async function checkStatusCommand(
  command: string,
  args: string[],
  checks: DoctorCheck[],
  id: string,
  message: string,
): Promise<void> {
  try {
    const { stdout } = await execFileAsync(command, args, { timeout: 15_000, env: process.env });
    checks.push({ id, status: 'pass', message, details: stdout.trim() });
  } catch (error) {
    checks.push({
      id,
      status: 'fail',
      message: `${command} authentication check failed`,
      details: error instanceof Error ? error.message : String(error),
    });
  }
}

async function checkDocker(checks: DoctorCheck[]): Promise<void> {
  try {
    await execFileAsync('docker', ['info'], { timeout: 15_000, env: process.env });
    checks.push({ id: 'docker_daemon', status: 'pass', message: 'Docker daemon is available for Linux-backed verification' });
  } catch (error) {
    checks.push({
      id: 'docker_daemon',
      status: 'fail',
      message: 'Docker daemon is required for Linux-backed verification',
      details: error instanceof Error ? error.message : String(error),
    });
  }
}

async function checkLocalAuthBootstrap(target: InvestigationTarget, checks: DoctorCheck[]): Promise<void> {
  try {
    const tempCampaignDir = await mkdtemp(resolve(tmpdir(), 'security-lab-doctor-'));
    const result = await prepareLocalAuthBootstrap(target, tempCampaignDir);
    if (!result) {
      checks.push({
        id: 'local_auth_bootstrap',
        status: 'warn',
        message: `Target ${target.id} declares authBootstrap but no bootstrap handler matched it`,
      });
      return;
    }
    checks.push({
      id: 'local_auth_bootstrap',
      status: 'pass',
      message: `Local auth bootstrap can mint ${result.issuedIdentities.length} canary identities`,
      details: result.issuedIdentities.join(', '),
    });
  } catch (error) {
    checks.push({
      id: 'local_auth_bootstrap',
      status: 'fail',
      message: `Local auth bootstrap failed for ${target.id}`,
      details: error instanceof Error ? error.message : String(error),
    });
  }
}
