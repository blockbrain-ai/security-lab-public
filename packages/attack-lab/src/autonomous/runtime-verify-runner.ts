import { resolve, dirname } from 'node:path';
import { readFile, writeFile, appendFile, mkdir, unlink } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import YAML from 'yaml';
import { BoundedLocalAdapter } from '../providers/bounded-local-adapter.js';
import { executeGate } from './gate-supervisor.js';
import {
  DockerSetupResultSchema,
  RuntimeVerificationResultSchema,
  type DockerSetupResult,
  type RuntimeVerificationResult,
  type RuntimeVerificationArtifact,
  type ValidatedCandidate,
  type ServiceInfo,
} from './runtime-verify-schemas.js';
import {
  buildDockerSetupPrompt,
  buildPerCandidateRuntimePrompt,
  type RuntimeCandidateInfo,
} from './runtime-verify-prompts.js';
import type { SourceVerificationArtifact } from './source-verify-schemas.js';
import { extractCandidatesFromReport, extractCandidatesFromCampaign } from './source-verify-runner.js';
import { validateRuntimeResult } from './runtime-evidence-validator.js';
import type { RunMonitor } from './run-monitor.js';
import {
  behaviorForLevel,
  checkNoProgressTimeout,
  gateClassToAnomalyKind,
  recordProgress,
  recordAnomaly,
  type DegradationState,
  type DegradationThresholds,
  DEFAULT_THRESHOLDS,
} from './degradation-ladder.js';

const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

export interface RuntimeVerifyOptions {
  reportPath: string;
  campaignId?: string;
  targetId: string;
  repoRoot: string;
  outputDir: string;
  model: string;
  baseUrl?: string;
  dryRun: boolean;
  candidateLimit?: number;
  sourceArtifactPath?: string;
  monitor?: RunMonitor;
  setupModel?: string;
  setupBaseUrl?: string;
  probeModel?: string;
  probeBaseUrl?: string;
  degradationState?: DegradationState;
  degradationThresholds?: DegradationThresholds;
}

export interface RuntimeVerifyResult {
  artifact: RuntimeVerificationArtifact;
  artifactPath: string;
  costUsd: number;
}

// ---------------------------------------------------------------------------
// Candidate selection
// ---------------------------------------------------------------------------

async function loadRuntimeCandidates(
  options: RuntimeVerifyOptions,
): Promise<RuntimeCandidateInfo[]> {
  if (options.sourceArtifactPath) {
    const raw = await readFile(options.sourceArtifactPath, 'utf8');
    const sourceArtifact = JSON.parse(raw) as SourceVerificationArtifact;
    const all = [
      ...sourceArtifact.candidates,
      ...(sourceArtifact.auditFindings ?? []),
    ];

    const prioritized = all
      .filter((c) => c.status !== 'refuted')
      .sort((a, b) => {
        const order = { supported: 0, needs_runtime: 1, weakened: 2 } as Record<string, number>;
        const ao = order[a.status] ?? 3;
        const bo = order[b.status] ?? 3;
        if (ao !== bo) return ao - bo;
        return b.confidence - a.confidence;
      });

    return prioritized.map((c) => ({
      id: c.candidateId,
      claim: c.claim,
      sourceVerification: c,
    }));
  }

  const reportContent = await readFile(options.reportPath, 'utf8');
  const campaignDir = options.campaignId
    ? resolve('data', 'campaigns', 'runs', options.campaignId)
    : undefined;
  const rawCandidates = campaignDir
    ? await extractCandidatesFromCampaign(campaignDir, reportContent)
    : extractCandidatesFromReport(reportContent);

  return rawCandidates.map((c) => ({
    id: c.id,
    claim: c.claim,
  }));
}

// ---------------------------------------------------------------------------
// Docker lifecycle
// ---------------------------------------------------------------------------

export async function ensureDockerRunning(timeoutMs: number = 240_000): Promise<void> {
  const isRunning = async (): Promise<boolean> => {
    try {
      await execFileAsync('docker', ['info'], { timeout: 10_000 });
      return true;
    } catch {
      return false;
    }
  };

  if (await isRunning()) {
    console.log('Docker daemon is already running.');
    return;
  }

  console.log('Docker daemon is not running — attempting to start Docker Desktop...');

  const platform = process.platform;
  if (platform === 'darwin') {
    try {
      await execFileAsync('open', ['-a', 'Docker'], { timeout: 15_000 });
    } catch (err) {
      throw new Error(
        `Failed to launch Docker Desktop: ${err instanceof Error ? err.message : String(err)}. ` +
        `Install Docker Desktop from https://www.docker.com/products/docker-desktop/`,
      );
    }
  } else if (platform === 'linux') {
    try {
      await execFileAsync('systemctl', ['start', 'docker'], { timeout: 15_000 });
    } catch {
      try {
        await execFileAsync('sudo', ['service', 'docker', 'start'], { timeout: 15_000 });
      } catch (err) {
        throw new Error(
          `Failed to start Docker daemon: ${err instanceof Error ? err.message : String(err)}. ` +
          `Start Docker manually with: sudo systemctl start docker`,
        );
      }
    }
  } else {
    throw new Error(
      `Docker daemon is not running and automatic startup is not supported on ${platform}. ` +
      `Start Docker Desktop manually before running runtime verification.`,
    );
  }

  const pollIntervalMs = 3_000;
  const deadline = Date.now() + timeoutMs;
  let lastLog = 0;

  while (Date.now() < deadline) {
    if (await isRunning()) {
      console.log('Docker daemon is now running.');
      return;
    }
    if (Date.now() - lastLog > 15_000) {
      const remaining = Math.round((deadline - Date.now()) / 1000);
      console.log(`Waiting for Docker daemon... (${remaining}s remaining)`);
      lastLog = Date.now();
    }
    await new Promise((r) => setTimeout(r, pollIntervalMs));
  }

  throw new Error(
    `Docker daemon did not start within ${Math.round(timeoutMs / 1000)}s. ` +
    `Check Docker Desktop and try again.`,
  );
}

async function dockerTeardown(serviceInfo: ServiceInfo): Promise<void> {
  if (!serviceInfo.composeCwd) return;

  const args = ['compose'];
  for (const f of serviceInfo.composeFiles) {
    args.push('-f', f);
  }
  args.push('down', '--volumes', '--remove-orphans');

  const env: Record<string, string> = { ...process.env as Record<string, string> };
  if (serviceInfo.projectName) {
    env['COMPOSE_PROJECT_NAME'] = serviceInfo.projectName;
  }

  try {
    await execFileAsync('docker', args, {
      cwd: serviceInfo.composeCwd,
      env,
      timeout: 60_000,
    });
    console.log('Docker teardown complete');
  } catch (err) {
    console.log(`Docker teardown warning: ${err instanceof Error ? err.message : String(err)}`);
  }
}

async function bootstrapEnvFile(repoRoot: string): Promise<string[]> {
  const created: string[] = [];
  const composeNames = ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml'];
  for (const name of composeNames) {
    const composePath = resolve(repoRoot, name);
    if (!existsSync(composePath)) continue;
    try {
      const content = await readFile(composePath, 'utf8');
      const envFileRefs = content.match(/env_file\s*:\s*\n(\s+-\s+\S+)+|env_file\s*:\s*\S+/g);
      if (!envFileRefs && !content.includes('env_file')) continue;
      const envPath = resolve(dirname(composePath), '.env');
      if (!existsSync(envPath)) {
        await writeFile(envPath, '# Bootstrap .env created by runtime verification runner\n', 'utf8');
        created.push(envPath);
        console.log(`Created bootstrap .env at ${envPath}`);
      }
    } catch { /* ignore read errors */ }
  }
  return created;
}

async function cleanupBootstrapEnvFiles(paths: string[]): Promise<void> {
  for (const p of paths) {
    try {
      const content = await readFile(p, 'utf8');
      if (content.startsWith('# Bootstrap .env created by runtime verification runner')) {
        await unlink(p);
        console.log(`Cleaned up bootstrap .env at ${p}`);
      }
    } catch { /* ignore cleanup errors */ }
  }
}

const COMPOSE_FILENAMES = ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml'] as const;

export function extractPortFromBaseUrl(baseUrl?: string): string | null {
  if (!baseUrl) return null;
  try {
    const url = new URL(baseUrl);
    if (url.port) return url.port;
    if (url.protocol === 'http:') return '80';
    if (url.protocol === 'https:') return '443';
    return null;
  } catch {
    return null;
  }
}

function parsePublishedPort(portValue: unknown): string | null {
  if (typeof portValue === 'number') return String(portValue);
  if (typeof portValue === 'string') {
    const cleaned = portValue.trim().replace(/\/(tcp|udp)$/i, '');
    const parts = cleaned.split(':');
    if (parts.length === 1) return cleaned || null;
    const published = parts[parts.length - 2]?.trim();
    return published || null;
  }
  if (portValue && typeof portValue === 'object' && 'published' in portValue) {
    const published = (portValue as { published?: unknown }).published;
    if (typeof published === 'number') return String(published);
    if (typeof published === 'string') return published.trim() || null;
  }
  return null;
}

export async function extractComposePublishedPorts(repoRoot: string): Promise<string[]> {
  const ports = new Set<string>();

  for (const name of COMPOSE_FILENAMES) {
    const composePath = resolve(repoRoot, name);
    if (!existsSync(composePath)) continue;

    try {
      const raw = await readFile(composePath, 'utf8');
      const parsed = YAML.parse(raw) as { services?: Record<string, { ports?: unknown[] }> } | null;
      const services = parsed?.services ?? {};
      for (const service of Object.values(services)) {
        for (const portValue of service.ports ?? []) {
          const published = parsePublishedPort(portValue);
          if (published) ports.add(published);
        }
      }
    } catch {
      // Ignore unreadable or unparsable compose files; setup agent can still try.
    }
  }

  return [...ports];
}

export async function determineServicePrecheckPorts(
  repoRoot: string,
  excludedBaseUrls: Array<string | undefined>,
): Promise<string[]> {
  const excluded = new Set(
    excludedBaseUrls
      .map((url) => extractPortFromBaseUrl(url))
      .filter((port): port is string => Boolean(port)),
  );

  const composePorts = await extractComposePublishedPorts(repoRoot);
  // Only pre-detect services on ports declared in a compose file.
  // Without a compose file we have no way to know which port the target
  // uses, and scanning common ports picks up unrelated services (e.g.
  // macOS AirPlay on 5000, local model servers on 8080).
  return composePorts.filter((port) => !excluded.has(port));
}

// ---------------------------------------------------------------------------
// Runtime verification runner
// ---------------------------------------------------------------------------

export async function runBoundedRuntimeVerification(
  options: RuntimeVerifyOptions,
): Promise<RuntimeVerifyResult> {
  await mkdir(options.outputDir, { recursive: true });

  const allCandidates = await loadRuntimeCandidates(options);
  const candidates = options.candidateLimit
    ? allCandidates.slice(0, options.candidateLimit)
    : allCandidates;

  console.log(`Runtime verification: ${allCandidates.length} candidates${options.candidateLimit ? ` (limited to ${candidates.length})` : ''}`);

  if (candidates.length === 0) {
    console.log('No candidates for runtime verification.');
    const artifact: RuntimeVerificationArtifact = {
      campaignId: options.campaignId ?? 'unknown',
      targetId: options.targetId,
      timestamp: new Date().toISOString(),
      dockerSetupSuccess: false,
      dockerSetupLog: 'No candidates to verify',
      candidates: [],
    };
    const artifactPath = resolve(options.outputDir, 'runtime-verification.json');
    await writeFile(artifactPath, JSON.stringify(artifact, null, 2), 'utf8');
    return { artifact, artifactPath, costUsd: 0 };
  }

  const projectName = `securitylab-${(options.campaignId ?? options.targetId).replace(/[^a-z0-9-]/gi, '-')}-${Date.now()}`;
  const baseUrl = options.baseUrl ?? 'http://127.0.0.1:8080/v1';
  const setupModel = options.setupModel ?? options.model;
  const setupBaseUrl = (options.setupBaseUrl ?? baseUrl).replace(/\/+$/, '');
  const probeModel = options.probeModel ?? options.model;
  const probeBaseUrl = (options.probeBaseUrl ?? baseUrl).replace(/\/+$/, '');
  const sessionLogPath = resolve(options.outputDir, 'runtime-verification-session.jsonl');

  // --- Dry run ---
  if (options.dryRun) {
    console.log('\n=== DRY RUN — Runtime verification prompts ===\n');
    const setupPrompt = buildDockerSetupPrompt(options.repoRoot, options.targetId, projectName);
    console.log('--- Docker Setup ---');
    console.log(`Prompt length: ${setupPrompt.length} chars`);
    console.log(setupPrompt.slice(0, 500) + '...\n');

    for (const candidate of candidates) {
      const prompt = buildPerCandidateRuntimePrompt(
        candidate, options.repoRoot, options.targetId,
        { baseUrl: 'http://localhost:4000', ports: ['4000'], composeCwd: '.', composeFiles: ['docker-compose.yml'], projectName },
      );
      console.log(`--- Candidate: ${candidate.id} ---`);
      console.log(`Prompt length: ${prompt.length} chars`);
      console.log(prompt.slice(0, 500) + '...\n');
    }

    const artifact: RuntimeVerificationArtifact = {
      campaignId: options.campaignId ?? 'unknown',
      targetId: options.targetId,
      timestamp: new Date().toISOString(),
      dockerSetupSuccess: false,
      candidates: [],
    };
    return { artifact, artifactPath: '', costUsd: 0 };
  }

  // --- Pre-setup: ensure Docker daemon is running ---
  await ensureDockerRunning();

  // --- Pre-setup: create bootstrap .env if compose expects env_file ---
  const bootstrappedEnvFiles = await bootstrapEnvFile(options.repoRoot);

  // --- Pre-setup: detect already-running services on expected ports ---
  const preCheckPorts = await determineServicePrecheckPorts(options.repoRoot, [
    baseUrl,
    setupBaseUrl,
    probeBaseUrl,
  ]);
  let preDetectedService: ServiceInfo | undefined;
  for (const port of preCheckPorts) {
    try {
      const ctrl = new AbortController();
      const timeout = setTimeout(() => ctrl.abort(), 3000);
      const resp = await fetch(`http://localhost:${port}/`, { signal: ctrl.signal });
      clearTimeout(timeout);
      if (resp.ok || resp.status < 500) {
        console.log(`Pre-check: service already running on localhost:${port} (HTTP ${resp.status})`);
        preDetectedService = {
          baseUrl: `http://localhost:${port}`,
          ports: [port],
          composeCwd: options.repoRoot,
          composeFiles: [],
          projectName,
        };
        break;
      }
    } catch {
      // Port not responding, continue
    }
  }

  // --- Phase 1: Docker Setup ---
  console.log('\nPhase 1: Docker setup...');
  const setupAdapter = new BoundedLocalAdapter({
    provider: 'bounded_local',
    model: setupModel,
    baseUrl: setupBaseUrl,
    workingDirectory: options.repoRoot,
    boundedConfig: {
      runtimeTools: true,
      shellBudget: 8,
      httpBudget: 0,
      readBudget: 2,
      maxTurns: 12,
      shellPolicy: 'runtime',
      shellTimeoutMs: 180_000,
      maxContextChars: 30_000,
    },
    requestTimeoutMs: 300_000,
  });

  const setupPrompt = buildDockerSetupPrompt(options.repoRoot, options.targetId, projectName);
  let setupResult: DockerSetupResult;
  let serviceInfo: ServiceInfo | undefined;
  const dockerSetupStart = Date.now();
  const degradation = options.degradationState;
  const degThresholds = options.degradationThresholds ?? DEFAULT_THRESHOLDS;

  const noteDegradationProgress = (): void => {
    if (!degradation) return;
    const now = new Date().toISOString();
    const { escalated, newLevel } = checkNoProgressTimeout(
      degradation,
      degradation.lastActivityAt,
      now,
      degThresholds,
    );
    if (escalated) {
      console.log(`Degradation: escalated to level ${newLevel} due to inactivity`);
    }
    recordProgress(degradation, now);
  };

  if (preDetectedService) {
    setupResult = {
      success: true,
      baseUrl: preDetectedService.baseUrl,
      ports: preDetectedService.ports,
      composeCwd: '.',
      composeFiles: [],
      projectName,
      log: `Reused pre-existing service on ${preDetectedService.baseUrl}`,
    };
  } else {
    try {
      const response = await setupAdapter.invoke({
        systemPrompt: 'You are a Docker environment setup agent. Start the target application and report the service info. Return structured JSON only.',
        prompt: setupPrompt,
        requestTimeoutMs: 300_000,
        workingDirectory: options.repoRoot,
      });

      await appendFile(sessionLogPath, JSON.stringify({
        type: 'docker_setup_response',
        content: response.content,
        usage: response.usage,
        durationMs: response.durationMs,
        toolTranscript: response.toolTranscript,
      }) + '\n', 'utf8');

      // Gate 3: Docker setup response parse
      const setupGate = await executeGate(DockerSetupResultSchema, {
        gateId: 'runtime:docker-setup',
        rawContent: response.content,
        originalPrompt: setupPrompt,
        originalSystemPrompt: 'You are a Docker environment setup agent.',
        toolTranscript: response.toolTranscript,
        model: setupModel,
        baseUrl: setupBaseUrl,
        workingDirectory: options.repoRoot,
        sessionLogPath,
      }, { provider: 'bounded_local' });

      if (setupGate.classification) {
        console.log(`Docker setup: gate(${setupGate.classification.failureClass}) ${setupGate.repairSucceeded ? 'repaired' : 'failed'}`);
      }

      if (setupGate.success && setupGate.output) {
        setupResult = setupGate.output as DockerSetupResult;
      } else {
        setupResult = {
          success: false, ports: [], composeFiles: [],
          log: `Failed to parse Docker setup output${setupGate.classification ? ` (${setupGate.classification.failureClass})` : ''}`,
        };
      }
    } catch (err) {
      setupResult = {
        success: false,
        ports: [],
        composeFiles: [],
        log: `Docker setup error: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }

  console.log(`Docker setup: ${setupResult.success ? 'SUCCESS' : 'FAILED'} — ${setupResult.log ?? ''}`);
  if (options.monitor) await options.monitor.emitDockerSetup(setupResult.success, Date.now() - dockerSetupStart);
  if (degradation && !setupResult.success) {
    const { escalated, newLevel } = recordAnomaly(
      degradation,
      {
        at: new Date().toISOString(),
        kind: 'docker_failure',
        detail: setupResult.log ?? 'Docker setup failed',
      },
      degThresholds,
    );
    if (escalated) {
      console.log(`Degradation: escalated to level ${newLevel}`);
    }
  }
  noteDegradationProgress();

  if (setupResult.success) {
    serviceInfo = {
      baseUrl: setupResult.baseUrl,
      ports: setupResult.ports,
      composeCwd: setupResult.composeCwd ? resolve(options.repoRoot, setupResult.composeCwd) : options.repoRoot,
      composeFiles: setupResult.composeFiles,
      projectName: setupResult.projectName ?? projectName,
    };
  }

  // --- Phase 2: Per-candidate runtime probing ---
  const results: ValidatedCandidate[] = [];

  function wrapNoValidation(r: RuntimeVerificationResult): ValidatedCandidate {
    return { modelResult: r, validatedResult: r, wasDowngraded: false, validationNotes: [] };
  }

  try {
    if (!setupResult.success) {
      console.log('\nDocker setup failed — marking all candidates as blocked.');
      for (const candidate of candidates) {
        results.push(wrapNoValidation({
          candidateId: candidate.id,
          claim: candidate.claim,
          status: 'blocked',
          rootCause: 'Docker setup failed',
          reproducerCommands: [],
          httpEvidence: [],
          pvrReady: false,
          blocker: setupResult.log ?? 'Docker setup failed',
          confidence: 0,
        }));
      }
    } else {
      console.log(`\nPhase 2: Probing ${candidates.length} candidates...`);

      for (let i = 0; i < candidates.length; i++) {
        if (degradation) {
          const behavior = behaviorForLevel(degradation.currentLevel);
          if (behavior.halt) {
            console.log(`Degradation level ${degradation.currentLevel}: halting remaining runtime candidates`);
            for (let j = i; j < candidates.length; j++) {
              results.push(wrapNoValidation({
                candidateId: candidates[j]!.id,
                claim: candidates[j]!.claim,
                status: 'blocked',
                rootCause: 'Degradation halt',
                reproducerCommands: [],
                httpEvidence: [],
                pvrReady: false,
                blocker: 'degradation_halt',
                confidence: 0,
              }));
            }
            break;
          }
          if (!behavior.allowNonCriticalRuntime) {
            const policy = candidates[i]!.sourceVerification?.reviewPolicy;
            if (policy && policy.riskTier !== 'critical') {
              console.log(`[${i + 1}/${candidates.length}] ${candidates[i]!.id}: skipped (degradation level ${degradation.currentLevel}, non-critical)`);
              results.push(wrapNoValidation({
                candidateId: candidates[i]!.id,
                claim: candidates[i]!.claim,
                status: 'blocked',
                rootCause: 'Degradation: non-critical runtime skipped',
                reproducerCommands: [],
                httpEvidence: [],
                pvrReady: false,
                blocker: 'degradation_non_critical_skip',
                confidence: 0,
              }));
              continue;
            }
          }
        }

        const candidate = candidates[i]!;
        const label = `[${i + 1}/${candidates.length}] ${candidate.id}`;
        console.log(`${label}: probing...`);
        if (options.monitor) await options.monitor.emitCandidateStart(candidate.id, 'runtime');

        const allowedHttpHosts = ['localhost', '127.0.0.1', '::1'];
        if (serviceInfo?.baseUrl) {
          try {
            const serviceHost = new URL(serviceInfo.baseUrl).hostname;
            if (!allowedHttpHosts.includes(serviceHost)) {
              allowedHttpHosts.push(serviceHost);
            }
          } catch { /* ignore bad URL */ }
        }

        const candidateAdapter = new BoundedLocalAdapter({
          provider: 'bounded_local',
          model: probeModel,
          baseUrl: probeBaseUrl,
          workingDirectory: options.repoRoot,
          boundedConfig: {
            runtimeTools: true,
            shellBudget: 5,
            httpBudget: 5,
            readBudget: 3,
            maxTurns: 20,
            shellPolicy: 'runtime',
            shellTimeoutMs: 60_000,
            maxContextChars: 40_000,
            allowedHttpHosts,
          },
          requestTimeoutMs: 180_000,
        });

        const prompt = buildPerCandidateRuntimePrompt(
          candidate, options.repoRoot, options.targetId, serviceInfo!,
        );

        try {
          const response = await candidateAdapter.invoke({
            systemPrompt: 'You are a runtime verification agent. Probe the running service to verify the security finding. Return structured JSON only.',
            prompt,
            requestTimeoutMs: 180_000,
            workingDirectory: options.repoRoot,
          });

          await appendFile(sessionLogPath, JSON.stringify({
            type: 'candidate_runtime_response',
            candidateId: candidate.id,
            content: response.content,
            usage: response.usage,
            durationMs: response.durationMs,
            toolTranscript: response.toolTranscript,
          }) + '\n', 'utf8');

          // Mechanical check: reject probe results with zero tool calls
          const probeToolCalls = (response.toolTranscript ?? []).filter(
            (t) => t.tool === 'http_request' || t.tool === 'shell_exec',
          );
          if (probeToolCalls.length === 0) {
            console.log(`${label}: no tool calls — model did not probe the service, marking blocked`);
            results.push(wrapNoValidation({
              candidateId: candidate.id,
              claim: candidate.claim,
              status: 'blocked',
              rootCause: 'Model produced verdict without making any probe tool calls',
              reproducerCommands: [],
              httpEvidence: [],
              pvrReady: false,
              blocker: 'no_probe_tool_calls',
              confidence: 0,
            }));
            if (options.monitor) await options.monitor.emitCandidateEnd(candidate.id, 'runtime', { status: 'blocked', confidence: 0 });
            noteDegradationProgress();
            continue;
          }

          // Gate 4: per-candidate runtime probe response
          const runtimeGate = await executeGate(RuntimeVerificationResultSchema, {
            gateId: `runtime:${candidate.id}`,
            rawContent: response.content,
            originalPrompt: prompt,
            originalSystemPrompt: 'You are a runtime verification agent.',
            toolTranscript: response.toolTranscript,
            model: probeModel,
            baseUrl: probeBaseUrl,
            workingDirectory: options.repoRoot,
            sessionLogPath,
          }, { provider: 'bounded_local' });

          if (runtimeGate.classification) {
            console.log(`${label}: gate(${runtimeGate.classification.failureClass}) ${runtimeGate.repairSucceeded ? 'repaired' : 'failed'}`);
            if (options.monitor) await options.monitor.emitGateRepair(candidate.id, runtimeGate.classification.failureClass, runtimeGate.repairSucceeded, runtimeGate.repairCostUsd, 'runtime');
            if (degradation) {
              const anomalyKind = gateClassToAnomalyKind(runtimeGate.classification.failureClass);
              if (anomalyKind) {
                const { escalated, newLevel } = recordAnomaly(degradation, { at: new Date().toISOString(), kind: anomalyKind, candidateId: candidate.id }, degThresholds);
                if (escalated) console.log(`Degradation: escalated to level ${newLevel}`);
              }
            }
          }

          if (runtimeGate.success && runtimeGate.output) {
            const parsed = runtimeGate.output as RuntimeVerificationResult;
            const validated = validateRuntimeResult(parsed, response.toolTranscript ?? []);

            // Gate 5: archival for evidence fabrication (no mutation — validator already handled it)
            if (validated.wasDowngraded && validated.validationNotes.length > 0) {
              const gate5Content = runtimeGate.repairContent ?? response.content;
              await executeGate(RuntimeVerificationResultSchema, {
                gateId: `runtime-evidence:${candidate.id}`,
                rawContent: gate5Content,
                originalPrompt: prompt,
                originalSystemPrompt: 'You are a runtime verification agent.',
                model: probeModel,
                sessionLogPath,
              }, {
                validationNotes: validated.validationNotes,
                provider: 'bounded_local',
              });
            }

            const validatedCandidate: ValidatedCandidate = {
              ...validated,
              reviewPolicy: candidate.sourceVerification?.reviewPolicy ?? undefined,
            };

            results.push(validatedCandidate);
            const vr = validated.validatedResult;
            const downgradeTag = validated.wasDowngraded ? ' [DOWNGRADED]' : '';
            const policyTag = validatedCandidate.reviewPolicy ? ` [${validatedCandidate.reviewPolicy.riskTier}]` : '';
            console.log(`${label}: ${vr.status} (confidence: ${vr.confidence})${vr.pvrReady ? ' [PVR READY]' : ''}${downgradeTag}${policyTag}`);
            if (options.monitor) await options.monitor.emitCandidateEnd(candidate.id, 'runtime', { status: vr.status, confidence: vr.confidence, wasDowngraded: validated.wasDowngraded });
            if (validated.wasDowngraded) {
              for (const note of validated.validationNotes) {
                console.log(`  ⚠ ${note.rule}: ${note.detail.slice(0, 120)}`);
              }
              if (degradation && validated.validationNotes.some((note) => note.rule.includes('fabricat'))) {
                const { escalated, newLevel } = recordAnomaly(
                  degradation,
                  {
                    at: new Date().toISOString(),
                    kind: 'evidence_fabrication',
                    candidateId: candidate.id,
                    detail: validated.validationNotes.map((note) => note.detail).join(' | '),
                  },
                  degThresholds,
                );
                if (escalated) {
                  console.log(`Degradation: escalated to level ${newLevel}`);
                }
              }
              if (options.monitor) await options.monitor.emitValidatorDowngrade(candidate.id, parsed.status, vr.status, validated.validationNotes.map(n => n.detail), 'runtime');
            }
          } else {
            results.push(wrapNoValidation({
              candidateId: candidate.id,
              claim: candidate.claim,
              status: 'not_reproducible',
              rootCause: 'Runtime verification output could not be parsed',
              reproducerCommands: [],
              httpEvidence: [],
              pvrReady: false,
              blocker: runtimeGate.classification ? `gate_${runtimeGate.classification.failureClass}` : 'structured_parse_failure',
              confidence: 0,
            }));
            console.log(`${label}: parse_failure → not_reproducible`);
            if (options.monitor) await options.monitor.emitCandidateEnd(candidate.id, 'runtime', { status: 'not_reproducible', error: 'parse_failure' });
          }
        } catch (err) {
          results.push(wrapNoValidation({
            candidateId: candidate.id,
            claim: candidate.claim,
            status: 'not_reproducible',
            rootCause: 'Runtime verification failed',
            reproducerCommands: [],
            httpEvidence: [],
            pvrReady: false,
            blocker: err instanceof Error ? err.message : String(err),
            confidence: 0,
          }));
          console.log(`${label}: error → not_reproducible (${err instanceof Error ? err.message : String(err)})`);
          if (options.monitor) await options.monitor.emitCandidateEnd(candidate.id, 'runtime', { status: 'not_reproducible', error: err instanceof Error ? err.message : String(err) });
        }

        noteDegradationProgress();
      }
    }
  } finally {
    // --- Phase 3: Docker teardown ---
    if (serviceInfo) {
      console.log('\nPhase 3: Docker teardown...');
      const teardownStart = Date.now();
      await dockerTeardown(serviceInfo);
      if (options.monitor) await options.monitor.emitDockerTeardown(Date.now() - teardownStart);
    }
    if (bootstrappedEnvFiles.length > 0) {
      await cleanupBootstrapEnvFiles(bootstrappedEnvFiles);
    }
  }

  // --- Assemble artifact ---
  const artifact: RuntimeVerificationArtifact = {
    campaignId: options.campaignId ?? 'unknown',
    targetId: options.targetId,
    timestamp: new Date().toISOString(),
    dockerSetupSuccess: setupResult.success,
    dockerSetupLog: setupResult.log,
    serviceInfo,
    candidates: results,
  };

  const artifactPath = resolve(options.outputDir, 'runtime-verification.json');
  await writeFile(artifactPath, JSON.stringify(artifact, null, 2), 'utf8');

  // Write runtime report
  await writeRuntimeReport(options.outputDir, artifact);

  // Write draft PVRs for pvrReady results
  await writeDraftPvrs(options.outputDir, artifact);

  // Print summary
  const vResults = results.map((r) => r.validatedResult);
  const counts = {
    confirmed: vResults.filter((r) => r.status === 'confirmed').length,
    partial: vResults.filter((r) => r.status === 'partially_confirmed').length,
    not_reproducible: vResults.filter((r) => r.status === 'not_reproducible').length,
    blocked: vResults.filter((r) => r.status === 'blocked').length,
    refuted: vResults.filter((r) => r.status === 'refuted').length,
    pvrReady: vResults.filter((r) => r.pvrReady).length,
    downgraded: results.filter((r) => r.wasDowngraded).length,
  };
  console.log(`\nRuntime verification summary:`);
  console.log(`  ${counts.confirmed} confirmed, ${counts.partial} partial, ${counts.not_reproducible} not_reproducible, ${counts.blocked} blocked, ${counts.refuted} refuted`);
  console.log(`  ${counts.pvrReady} PVR-ready findings`);
  if (counts.downgraded > 0) {
    console.log(`  ${counts.downgraded} downgraded by evidence validator`);
  }
  console.log(`  Cost: $0.00`);
  console.log(`  Artifact: ${artifactPath}`);

  return { artifact, artifactPath, costUsd: 0 };
}

// ---------------------------------------------------------------------------
// Report and PVR generation
// ---------------------------------------------------------------------------

async function writeRuntimeReport(
  outputDir: string,
  artifact: RuntimeVerificationArtifact,
): Promise<void> {
  const lines: string[] = [
    '# Qwen Runtime Verification Report',
    '',
    `**Target:** ${artifact.targetId}`,
    `**Timestamp:** ${artifact.timestamp}`,
    `**Docker setup:** ${artifact.dockerSetupSuccess ? 'Success' : 'Failed'}`,
    '',
  ];

  if (artifact.dockerSetupLog) {
    lines.push(`**Setup log:** ${artifact.dockerSetupLog}`, '');
  }

  const groups: Record<string, ValidatedCandidate[]> = {
    confirmed: [],
    partially_confirmed: [],
    not_reproducible: [],
    blocked: [],
    refuted: [],
  };
  for (const c of artifact.candidates) {
    (groups[c.validatedResult.status] ??= []).push(c);
  }

  for (const [status, items] of Object.entries(groups)) {
    if (items.length === 0) continue;
    lines.push(`## ${status.replace(/_/g, ' ')} (${items.length})`, '');
    for (const entry of items) {
      const item = entry.validatedResult;
      lines.push(`### ${item.candidateId}`);
      if (entry.wasDowngraded) {
        lines.push(`- **VALIDATION OVERRIDE:** model claimed "${entry.modelResult.status}" → downgraded to "${item.status}"`);
      }
      lines.push(`- **Claim:** ${item.claim}`);
      lines.push(`- **Root cause:** ${item.rootCause}`);
      lines.push(`- **Confidence:** ${item.confidence}`);
      if (item.severity) lines.push(`- **Severity:** ${item.severity}`);
      if (item.pvrReady) lines.push(`- **PVR Ready:** yes`);
      if (item.blocker) lines.push(`- **Blocker:** ${item.blocker}`);
      if (item.reproducerCommands.length > 0) {
        lines.push('- **Reproducer commands:**');
        lines.push('```');
        lines.push(...item.reproducerCommands);
        lines.push('```');
      }
      if (item.reproducerOutput) {
        lines.push('- **Reproducer output:**');
        lines.push('```');
        lines.push(item.reproducerOutput.slice(0, 2000));
        lines.push('```');
      }
      if (item.httpEvidence.length > 0) {
        lines.push('- **HTTP evidence:**');
        for (const ev of item.httpEvidence) {
          lines.push(`  - ${ev.method} ${ev.url} → ${ev.statusCode}: ${ev.snippet.slice(0, 200)}`);
        }
      }
      if (entry.validationNotes.length > 0) {
        lines.push('- **Validation notes:**');
        for (const note of entry.validationNotes) {
          lines.push(`  - [${note.rule}] ${note.detail}`);
        }
      }
      lines.push('');
    }
  }

  const reportPath = resolve(outputDir, 'QWEN-RUNTIME-REPORT.md');
  await writeFile(reportPath, lines.join('\n'), 'utf8');
}

async function writeDraftPvrs(
  outputDir: string,
  artifact: RuntimeVerificationArtifact,
): Promise<void> {
  const pvrReady = artifact.candidates.filter((entry) => entry.validatedResult.pvrReady);
  for (let i = 0; i < pvrReady.length; i++) {
    const c = pvrReady[i]!.validatedResult;
    const slug = c.candidateId.replace(/[^a-z0-9]+/gi, '-').slice(0, 40);
    const pvrPath = resolve(outputDir, `pvr-qwen-${String(i + 1).padStart(2, '0')}-${slug}.md`);

    const lines = [
      `# PVR Draft: ${c.candidateId}`,
      '',
      '> **Generated by Qwen runtime verification. Pending human/hosted dedup review.**',
      '',
      `## Summary`,
      '',
      c.claim,
      '',
      `## Severity: ${c.severity ?? 'unknown'}`,
      '',
      `## Root Cause`,
      '',
      c.rootCause,
      '',
      `## Reproducer`,
      '',
      '```bash',
      ...c.reproducerCommands,
      '```',
      '',
    ];

    if (c.reproducerOutput) {
      lines.push('### Output', '', '```', c.reproducerOutput.slice(0, 4000), '```', '');
    }

    if (c.httpEvidence.length > 0) {
      lines.push('## HTTP Evidence', '');
      for (const ev of c.httpEvidence) {
        lines.push(`### ${ev.method} ${ev.url}`, '', `Status: ${ev.statusCode}`, '', '```', ev.snippet.slice(0, 2000), '```', '');
      }
    }

    if (c.suggestedFix) {
      lines.push('## Suggested Fix', '', c.suggestedFix, '');
    }

    if (c.regressionTest) {
      lines.push('## Regression Test', '', c.regressionTest, '');
    }

    if (c.filingNotes) {
      lines.push('## Filing Notes', '', c.filingNotes, '');
    }

    await writeFile(pvrPath, lines.join('\n'), 'utf8');
  }
}
