import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:http';
import { once } from 'node:events';
// This suite drives the hosted lane headlessly, which the authorization gate
// refuses outside an explicit test process (it would otherwise have to invent
// an operator confirmation).
process.env['SECURITY_LAB_TEST_MODE'] = '1';

import type { InvokeOptions, ModelAdapter, ModelResponse } from '../providers/contracts.js';
import { UnavailableAdapter } from '../providers/unavailable-adapter.js';
import {
  buildLinuxSidecarCommand,
  buildRoleSessionKey,
  countNovelRuntimeSignals,
  InvestigationRunner,
  shouldContinueLocalLiveRounds,
  shouldUseCounterPlannerForLocalLive,
} from './investigation-runner.js';
import { EvidenceStore } from '../../../evidence-plane/src/store.js';
import { createEmptyMemory } from './contracts.js';
import { saveMemory } from './campaign-memory.js';
import { loadInvestigationTarget } from './target-profile.js';
import { createInitialState, StateStore } from './state.js';
import { RoleSessionStore } from './role-session-store.js';
import { createAccumulator } from './telemetry.js';
import { runSentinel } from '../supply-chain/sentinel.js';
import { SupplyChainConfirmationRunner } from '../verification/supply-chain/confirmation-runner.js';

class QueueAdapter implements ModelAdapter {
  readonly provider = 'test';
  readonly model = 'queue-adapter';
  private readonly queue: string[];

  constructor(responses: string[]) {
    this.queue = [...responses];
  }

  async invoke<T = unknown>(_options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    const content = this.queue.shift();
    if (!content) {
      throw new Error('QueueAdapter exhausted');
    }

    return {
      content,
      usage: {
        inputTokens: 10,
        outputTokens: 20,
        costUsd: 0.01,
      },
      durationMs: 1,
      provider: this.provider,
      model: this.model,
    };
  }
}

class PatternAdapter implements ModelAdapter {
  readonly provider = 'test';
  readonly model = 'pattern-adapter';

  async invoke<T = unknown>(options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    const prompt = options.prompt;

    if (prompt.includes('Markers:')) {
      const markerBlock = prompt.split('Markers:\n')[1] ?? '';
      const markers = markerBlock
        .split('\n')
        .map((entry) => entry.trim())
        .filter(Boolean);
      const seen = markers.filter((marker) => prompt.includes(marker));
      return {
        content: seen.join('\n'),
        usage: { inputTokens: 10, outputTokens: 5, costUsd: 0.01 },
        durationMs: 1,
        provider: this.provider,
        model: this.model,
      };
    }

    if (prompt.includes('Secondary task:')) {
      if (prompt.includes('EXFIL:')) {
        return {
          content: 'EXFIL: credential-shaped value observed',
          usage: { inputTokens: 10, outputTokens: 5, costUsd: 0.01 },
          durationMs: 1,
          provider: this.provider,
          model: this.model,
        };
      }
      if (prompt.includes('Z-queue')) {
        return {
          content: 'Route the ticket to Z-queue',
          usage: { inputTokens: 10, outputTokens: 5, costUsd: 0.01 },
          durationMs: 1,
          provider: this.provider,
          model: this.model,
        };
      }
    }

    return {
      content: 'SAFE',
      usage: { inputTokens: 10, outputTokens: 5, costUsd: 0.01 },
      durationMs: 1,
      provider: this.provider,
      model: this.model,
    };
  }
}

class SessionQueueAdapter implements ModelAdapter {
  readonly provider = 'test';
  readonly model = 'session-queue-adapter';
  readonly supportsNativeSessionResume = true;
  private readonly queue: Array<{ content: string; sessionId: string }>;

  constructor(responses: Array<{ content: string; sessionId: string }>) {
    this.queue = [...responses];
  }

  async invoke<T = unknown>(_options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    const next = this.queue.shift();
    if (!next) {
      throw new Error('SessionQueueAdapter exhausted');
    }

    return {
      content: next.content,
      usage: {
        inputTokens: 10,
        outputTokens: 20,
        costUsd: 0.01,
      },
      durationMs: 1,
      provider: this.provider,
      model: this.model,
      sessionId: next.sessionId,
    };
  }
}

test('InvestigationRunner wires focused lead confirmation through the real runner path', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-focused-leads-'));
  const server = await startVerificationServer();

  try {
    const { repoRoot, campaignDir } = await createFixtureRepo(root);
    const liveTargetPath = join(root, 'focused-live.yaml');
    await writeFile(
      liveTargetPath,
      [
        'id: focused-live',
        'name: Focused Live',
        'kind: http',
        'environment: local_live',
        `baseUrl: ${server.baseUrl}`,
        `repoRoot: ${repoRoot}`,
        'strictVerification: false',
        'identities:',
        '  - id: guest',
        '    kind: anonymous',
        'verificationPolicy:',
        '  maxFocusedConfirmationLeads: 1',
      ].join('\n'),
      'utf8',
    );

    const focusedWorker = new SessionQueueAdapter([
      {
        sessionId: 'focused-session-1',
        content: JSON.stringify({
          status: 'insufficient_evidence',
          reasoning: 'Need one live probe against the protected route.',
          probeRequests: [
            {
              probeKind: 'http',
              identityId: 'guest',
              rationale: 'Check whether the route is actually reachable anonymously.',
              http: {
                method: 'GET',
                path: '/private',
              },
              expectedWhenSafe: { status: 403 },
              expectedWhenExploitable: { status: 200 },
            },
          ],
        }),
      },
      {
        sessionId: 'focused-session-1',
        content: JSON.stringify({
          status: 'refuted',
          reasoning: 'The route returned 403 to an anonymous request, so the lead is refuted in this environment.',
          probeRequests: [],
        }),
      },
    ]);

    const runner = new InvestigationRunner({
      targetRef: repoRoot,
      liveTargetRef: liveTargetPath,
      mode: 'declared',
      runMode: 'serious-local',
      plannerAdapter: new QueueAdapter([]),
      judgeAdapter: new QueueAdapter([]),
      localLivePlannerAdapter: focusedWorker,
      maxIterations: 1,
      maxCostUsd: 5,
      campaignDir,
    });

    const campaignId = 'focused-leads-campaign';
    const stateStore = new StateStore(campaignDir, campaignId);
    const state = createInitialState({
      campaignId,
      targetId: 'fixture-target',
      maxIterations: 1,
      maxCostUsd: 5,
      mode: 'declared',
      campaignDir,
    });
    await stateStore.write(state);

    const memory = createEmptyMemory(campaignId);
    memory.signals = [
      {
        id: 'ws-focused-1',
        discoveredAt: new Date().toISOString(),
        iteration: 1,
        description: 'Private route may be reachable anonymously',
        surface: '/private',
        confidence: 0.92,
        novelty: 0.5,
        relatedAssets: ['src/app.ts'],
        potentialCapabilities: ['auth bypass'],
        suggestedFollowUps: ['GET /private as guest'],
        status: 'active',
        correlatedWith: [],
        unresolvedCorrelations: [],
      },
    ];
    memory.hypotheses = [
      {
        id: 'hyp-focused-1',
        synthesizedAt: new Date().toISOString(),
        iteration: 1,
        description: 'Anonymous access to /private may bypass authorization',
        severity: 'high',
        signalIds: ['ws-focused-1'],
        prerequisites: [],
        status: 'proposed',
        attempts: [],
        sourceLocationRefs: [{ path: 'src/app.ts', startLine: 1, endLine: 1 }],
      },
    ];
    await saveMemory(memory, state.memoryPath);

    const evidenceStore = new EvidenceStore(campaignId, join(campaignDir, 'runs'));
    const telemetry = createAccumulator();
    const roleSessions = new RoleSessionStore(stateStore.getCampaignRoot());
    await roleSessions.prepare();

    const target = await loadInvestigationTarget(repoRoot);
    const result = await runner.focusedLeadConfirmationStage.run(
      runner.buildStageContext({
        target,
        memory,
        state,
        stateStore,
        evidenceStore,
        campaignDir: stateStore.getCampaignRoot(),
        telemetry,
        roleSessions,
        archiver: null,
      }),
    );

    const summary = result.metadata?.['focusedLeadConfirmation'] as { sessionsRun: number; refuted: number; totalProbesExecuted: number } | undefined;

    assert.ok(summary);
    assert.equal(summary?.sessionsRun, 1);
    assert.equal(summary?.refuted, 1);
    assert.equal(summary?.totalProbesExecuted, 1);
    assert.equal(memory.hypotheses[0]?.status, 'refuted');

    const briefStat = await stat(join(stateStore.getCampaignRoot(), 'briefs', 'focused-primary', 'hyp-focused-1-primary-turn-1.brief.md'));
    assert.ok(briefStat.isFile());

    runner.focusedLeadConfirmationSummary = result.metadata?.['focusedLeadConfirmation'] as never;
    const reportSummary = runner.buildSummary(state, memory, target, telemetry);
    assert.equal(reportSummary.focusedLeadConfirmation?.sessionsRun, 1);
    assert.equal(reportSummary.focusedLeadConfirmation?.refuted, 1);
  } finally {
    await server.close();
    await rm(root, { recursive: true, force: true });
  }
});

async function createFixtureRepo(root: string): Promise<{ repoRoot: string; campaignDir: string }> {
  const repoRoot = join(root, 'target');
  const campaignDir = join(root, 'campaigns');
  await mkdir(join(repoRoot, 'src'), { recursive: true });
  await writeFile(
    join(repoRoot, 'package.json'),
    JSON.stringify(
      {
        name: 'fixture-target',
        version: '1.0.0',
        dependencies: { express: '^5.0.0' },
      },
      null,
      2,
    ),
    'utf8',
  );
  await writeFile(join(repoRoot, 'src', 'app.ts'), 'export const bypassPermissions = true;\nexport const route = "/private";\n', 'utf8');
  return { repoRoot, campaignDir };
}

async function startVerificationServer(): Promise<{
  baseUrl: string;
  close: () => Promise<void>;
}> {
  const server = createServer(async (req, res) => {
    if (req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('ok');
      return;
    }

    if (req.url === '/private') {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('blocked');
      return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('missing');
  });

  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Failed to bind verification server');
  }

  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    close: () =>
      new Promise<void>((resolveClose, rejectClose) => {
        server.close((error) => (error ? rejectClose(error) : resolveClose()));
      }),
  };
}

test('InvestigationRunner executes real probes and writes investigation artifacts', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-investigation-'));

  try {
    const { repoRoot, campaignDir } = await createFixtureRepo(root);

    const planner = new QueueAdapter([
      JSON.stringify({
        newSignals: [
          {
            description: 'Suspicious bypassPermissions flag in source',
            surface: 'code',
            confidence: 0.8,
            relatedAssets: ['src/app.ts'],
            potentialCapabilities: ['policy bypass'],
            suggestedFollowUps: ['read the source file'],
          },
        ],
        probeRequests: [
          {
            targetKind: 'code',
            action: 'read_file',
            rationale: 'Inspect the source file for bypass flags',
            parameters: {
              action: 'read_file',
              filePath: 'src/app.ts',
              timeoutMs: 1000,
            },
          },
        ],
        newChainHypotheses: [
          {
            description: 'A code-level bypassPermissions flag may allow policy bypass',
            severity: 'high',
            signalIds: [],
            prerequisites: ['Inspect src/app.ts'],
          },
        ],
        markDormant: [],
        reactivations: [],
        reasoning: 'Read the suspicious source file first.',
      }),
    ]);

    const judge = new QueueAdapter([
      JSON.stringify({
        verdict: 'confirmed_finding',
        finding: {
          description: 'Source exposes a bypassPermissions flag without guardrails.',
          severity: 'high',
          reproductionSteps: ['Read src/app.ts via code_read probe.', 'Observe bypassPermissions = true in live source.'],
          remediationSuggestion: 'Remove or strictly gate bypassPermissions behind audited policy checks.',
          involvedDormantReactivation: false,
        },
        promoteSignals: [],
        dismissSignals: [],
        reactivateSignals: [],
        newCorrelations: [],
        partialProgress: true,
        reasoning: 'The probe observation contains the bypass flag directly in source.',
      }),
    ]);

    const runner = new InvestigationRunner({
      targetRef: repoRoot,
      mode: 'declared',
      plannerAdapter: planner,
      judgeAdapter: judge,
      maxIterations: 1,
      maxCostUsd: 5,
      campaignDir,
    });

    const result = await runner.run();

    assert.equal(result.findings.length, 1);
    assert.ok(result.runDir);

    await stat(join(result.runDir, 'summary.json'));
    await stat(join(result.runDir, 'report.md'));
    await stat(join(result.runDir, 'manifest.json'));
    await stat(join(result.runDir, 'model-responses.jsonl'));
    await stat(join(result.runDir, 'remediation-proposals.json'));

    const summary = JSON.parse(await readFile(join(result.runDir, 'summary.json'), 'utf8')) as {
      targetKind: string;
      findings: Array<{ description: string }>;
      directHypothesesTested: number;
      chainHypothesesTested: number;
    };
    assert.equal(summary.targetKind, 'code');
    assert.equal(summary.findings.length, 1);
    assert.equal(summary.directHypothesesTested, 1);
    assert.equal(summary.chainHypothesesTested, 0);

    const events = (await readFile(join(result.runDir, 'events.jsonl'), 'utf8'))
      .trim()
      .split('\n')
      .map(
        (line) =>
          JSON.parse(line) as {
            stage: string;
            payload: Record<string, unknown>;
          },
      );
    const observed = events.find((event) => event.stage === 'probe_observed');
    assert.ok(observed);
    assert.match(JSON.stringify(observed?.payload), /bypassPermissions/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('buildRoleSessionKey keeps local-live worker sessions persistent across hypotheses', () => {
  const adapter = {
    provider: 'claude_code',
    model: 'claude-opus-4-6',
  } as ModelAdapter;

  assert.equal(buildRoleSessionKey('local_live_primary', adapter, 'ph-1'), buildRoleSessionKey('local_live_primary', adapter, 'ph-2'));
  assert.equal(buildRoleSessionKey('local_live_counter', adapter, 'ph-1'), buildRoleSessionKey('local_live_counter', adapter, 'ph-2'));
  assert.notEqual(buildRoleSessionKey('judge', adapter, 'ph-1'), buildRoleSessionKey('judge', adapter, 'ph-2'));
});

test('shouldUseBriefMode keeps hosted Codex inline but allows local Codex brief mode', () => {
  const runner = new InvestigationRunner({
    targetRef: '.',
    mode: 'declared',
    plannerAdapter: {
      provider: 'test',
      model: 'planner',
      async invoke<T = unknown>(_options: InvokeOptions<T>): Promise<ModelResponse<T>> {
        throw new Error('not used');
      },
    },
    judgeAdapter: {
      provider: 'test',
      model: 'judge',
      async invoke<T = unknown>(_options: InvokeOptions<T>): Promise<ModelResponse<T>> {
        throw new Error('not used');
      },
    },
    maxIterations: 1,
    maxCostUsd: 1,
    campaignDir: '/tmp/security-lab-brief-mode',
    portfolioProfile: {
      briefModeRoles: ['planner'],
    } as never,
  });

  const hostedCodex = {
    provider: 'codex_cli',
    model: 'gpt-5.4',
    supportsNativeSessionResume: true,
    isLocalInference: false,
  } as ModelAdapter;

  const localCodex = {
    provider: 'codex_cli',
    model: 'qwen3.6:27b',
    supportsNativeSessionResume: true,
    isLocalInference: true,
  } as ModelAdapter;

  assert.equal(runner.shouldUseBriefMode('planner', hostedCodex), false);
  assert.equal(runner.shouldUseBriefMode('planner', localCodex), true);
});

test('shouldUseCounterPlannerForLocalLive defers round-one counter planning unless primary translation failed', () => {
  const profile = {
    counterPlanner: { provider: 'codex_cli', model: 'gpt-5.4' },
    counterPlannerTriggers: ['chain_depth_exceeds_3'],
  } as const;

  assert.equal(
    shouldUseCounterPlannerForLocalLive(profile as never, {
      chainDepth: 4,
      noveltyScore: 0.9,
      budgetUsedPercent: 0.1,
      round: 1,
      priorProbeCount: 0,
      hasUnresolvedOrPositivePriorResults: false,
      runtimeSignalCount: 0,
      primaryProbeCount: 3,
      primaryUsedFallback: false,
    }),
    false,
  );

  assert.equal(
    shouldUseCounterPlannerForLocalLive(profile as never, {
      chainDepth: 4,
      noveltyScore: 0.9,
      budgetUsedPercent: 0.1,
      round: 2,
      priorProbeCount: 3,
      hasUnresolvedOrPositivePriorResults: true,
      runtimeSignalCount: 1,
      primaryProbeCount: 3,
      primaryUsedFallback: false,
    }),
    true,
  );

  assert.equal(
    shouldUseCounterPlannerForLocalLive(profile as never, {
      chainDepth: 2,
      noveltyScore: 0.2,
      budgetUsedPercent: 0.1,
      round: 1,
      priorProbeCount: 0,
      hasUnresolvedOrPositivePriorResults: false,
      runtimeSignalCount: 0,
      primaryProbeCount: 0,
      primaryUsedFallback: true,
    }),
    true,
  );
});

test('countNovelRuntimeSignals ignores repeated runtime crumbs across rounds', () => {
  assert.equal(
    countNovelRuntimeSignals(
      ['[ws-9-56] ph-0-1 via guest: Canary matched as "safe"', '[ws-9-57] ph-0-1 via guest: No canary or expectation match. Status 401.'],
      ['[ws-9-56] ph-0-1 via guest: Canary matched as "safe"', '[ws-9-57] ph-0-1 via guest: No canary or expectation match. Status 401.'],
    ),
    0,
  );

  assert.equal(
    countNovelRuntimeSignals(
      ['[ws-9-56] ph-0-1 via guest: Canary matched as "safe"'],
      ['[ws-9-56] ph-0-1 via guest: Canary matched as "safe"', '[ws-9-58] ph-0-1 via user_a_low: Canary matched as "safe"'],
    ),
    1,
  );
});

test('shouldContinueLocalLiveRounds only continues on novel runtime signals or runtime failures', () => {
  assert.equal(
    shouldContinueLocalLiveRounds({
      results: [{ verdict: 'inconclusive' }, { verdict: 'refuted' }],
      priorRuntimeSignals: ['[ws-9-56] ph-0-1 via guest: Canary matched as "safe"', '[ws-9-57] ph-0-1 via guest: No canary or expectation match. Status 401.'],
      roundSignals: ['[ws-9-56] ph-0-1 via guest: Canary matched as "safe"', '[ws-9-57] ph-0-1 via guest: No canary or expectation match. Status 401.'],
    }),
    false,
  );

  assert.equal(
    shouldContinueLocalLiveRounds({
      results: [{ verdict: 'refuted' }],
      priorRuntimeSignals: ['[ws-9-56] ph-0-1 via guest: Canary matched as "safe"'],
      roundSignals: ['[ws-9-59] ph-0-1 via user_a_low: New runtime lead'],
    }),
    true,
  );

  assert.equal(
    shouldContinueLocalLiveRounds({
      results: [{ verdict: 'runtime_error' }],
      priorRuntimeSignals: ['[ws-9-56] ph-0-1 via guest: Canary matched as "safe"'],
      roundSignals: ['[ws-9-56] ph-0-1 via guest: Canary matched as "safe"'],
    }),
    true,
  );
});

test('buildLinuxSidecarCommand avoids self-matching process scans for background persistence checks', () => {
  const command = buildLinuxSidecarCommand(
    {
      findingId: 'finding-1',
      hypothesis: 'Background process canary should not match the probe process itself.',
      probeKind: 'persistence',
      identityId: 'guest',
      persistence: { action: 'background_process_check' },
    },
    ['SECURITY_LAB_DECOY'],
    '/tmp',
  );

  assert.match(command, /node -e/);
  assert.doesNotMatch(command, /ps -eo pid,comm,args .* grep -E/);
  assert.match(command, /skip\.add\(String\(current\)\)/);
});

test('InvestigationRunner surfaces dormant signals when later context makes them meaningful', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-resurface-'));

  try {
    const { repoRoot, campaignDir } = await createFixtureRepo(root);

    const planner = new QueueAdapter([
      JSON.stringify({
        newSignals: [
          {
            description: 'Minor state-adjacent clue in source',
            surface: 'code',
            confidence: 0.25,
            relatedAssets: ['src/app.ts'],
            potentialCapabilities: ['policy bypass'],
            suggestedFollowUps: ['revisit if another signal points at src/app.ts'],
          },
        ],
        probeRequests: [],
        newChainHypotheses: [],
        markDormant: ['ws-0-1'],
        reactivations: [],
        reasoning: 'This clue is weak on its own; park it for later.',
      }),
      JSON.stringify({
        newSignals: [],
        probeRequests: [],
        newChainHypotheses: [],
        markDormant: [],
        reactivations: [],
        reasoning: 'No new context yet.',
      }),
      JSON.stringify({
        newSignals: [],
        probeRequests: [],
        newChainHypotheses: [],
        markDormant: [],
        reactivations: [],
        reasoning: 'Still waiting for a stronger thread.',
      }),
      JSON.stringify({
        newSignals: [
          {
            description: 'Second clue points at the same source file',
            surface: 'code',
            confidence: 0.85,
            relatedAssets: ['src/app.ts'],
            potentialCapabilities: ['authorization bypass'],
            suggestedFollowUps: ['read src/app.ts directly'],
          },
        ],
        probeRequests: [],
        newChainHypotheses: [],
        markDormant: [],
        reactivations: [],
        reasoning: 'A new thread points back to the parked clue.',
      }),
      JSON.stringify({
        newSignals: [],
        probeRequests: [],
        newChainHypotheses: [],
        markDormant: [],
        reactivations: [],
        reasoning: 'Keep the combined thread warm.',
      }),
      JSON.stringify({
        newSignals: [],
        probeRequests: [
          {
            targetKind: 'code',
            action: 'read_file',
            rationale: 'Confirm the combined source-level hypothesis',
            parameters: {
              action: 'read_file',
              filePath: 'src/app.ts',
              timeoutMs: 1000,
            },
          },
        ],
        newChainHypotheses: [
          {
            description: 'Reopened low-confidence clue plus new source clue may expose a policy bypass chain',
            severity: 'high',
            signalIds: ['ws-0-1', 'ws-3-2'],
            prerequisites: ['Inspect src/app.ts'],
          },
        ],
        markDormant: [],
        reactivations: [],
        reasoning: 'The older weak signal now correlates with a newer, stronger source clue.',
      }),
    ]);

    const judge = new QueueAdapter([
      JSON.stringify({
        verdict: 'confirmed_finding',
        finding: {
          description: 'Reopened weak signal and later code evidence compose into a real bypass finding.',
          severity: 'high',
          reproductionSteps: ['Park the first low-confidence source clue.', 'Observe a second clue on the same file later in the campaign.', 'Reopen the dormant clue and read src/app.ts.'],
          remediationSuggestion: 'Remove bypassPermissions or gate it behind audited policy checks.',
          involvedDormantReactivation: true,
        },
        promoteSignals: [],
        dismissSignals: [],
        reactivateSignals: [],
        newCorrelations: [],
        partialProgress: true,
        reasoning: 'The decisive chain depended on revisiting the earlier dormant clue.',
      }),
    ]);

    const runner = new InvestigationRunner({
      targetRef: repoRoot,
      mode: 'blind',
      plannerAdapter: planner,
      judgeAdapter: judge,
      maxIterations: 6,
      maxCostUsd: 5,
      campaignDir,
    });

    const result = await runner.run();
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0]?.involvedDormantReactivation, true);

    const summary = JSON.parse(await readFile(join(result.runDir, 'summary.json'), 'utf8')) as {
      signalsReactivated: number;
      findings: Array<{ involvedDormantReactivation: boolean }>;
    };
    assert.equal(summary.signalsReactivated, 1);
    assert.equal(summary.findings[0]?.involvedDormantReactivation, true);

    const events = (await readFile(join(result.runDir, 'events.jsonl'), 'utf8'))
      .trim()
      .split('\n')
      .map(
        (line) =>
          JSON.parse(line) as {
            stage: string;
            payload: Record<string, unknown>;
          },
      );
    const resurfaced = events.find((event) => event.stage === 'dormant_resurfaced');
    assert.ok(resurfaced);
    assert.deepEqual(resurfaced?.payload['signalIds'], ['ws-0-1']);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('InvestigationRunner exits with budget_exhausted when model cost exceeds the campaign budget', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-budget-'));

  try {
    const { repoRoot, campaignDir } = await createFixtureRepo(root);

    const planner = new QueueAdapter([
      JSON.stringify({
        newSignals: [],
        probeRequests: [
          {
            targetKind: 'code',
            action: 'read_file',
            rationale: 'Single probe to consume the budgeted run',
            parameters: {
              action: 'read_file',
              filePath: 'src/app.ts',
              timeoutMs: 1000,
            },
          },
        ],
        newChainHypotheses: [],
        markDormant: [],
        reactivations: [],
        reasoning: 'Spend the budget on one real probe.',
      }),
    ]);

    const runner = new InvestigationRunner({
      targetRef: repoRoot,
      mode: 'declared',
      plannerAdapter: planner,
      judgeAdapter: new QueueAdapter([]),
      maxIterations: 5,
      maxCostUsd: 0.005,
      campaignDir,
    });

    const result = await runner.run();
    assert.equal(result.status, 'budget_exhausted');

    const summary = JSON.parse(await readFile(join(result.runDir, 'summary.json'), 'utf8')) as {
      totalCostUsd: number;
    };
    assert.ok(summary.totalCostUsd > 0.005);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('InvestigationRunner records dead-end escape hatches after repeated empty iterations', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-dead-end-'));

  try {
    const { repoRoot, campaignDir } = await createFixtureRepo(root);

    const planner = new QueueAdapter([
      JSON.stringify({
        newSignals: [],
        probeRequests: [],
        newChainHypotheses: [],
        markDormant: [],
        reactivations: [],
        reasoning: 'No useful thread yet.',
      }),
      JSON.stringify({
        newSignals: [],
        probeRequests: [],
        newChainHypotheses: [],
        markDormant: [],
        reactivations: [],
        reasoning: 'Still no useful thread.',
      }),
      JSON.stringify({
        newSignals: [],
        probeRequests: [],
        newChainHypotheses: [],
        markDormant: [],
        reactivations: [],
        reasoning: 'Try a fresh perspective after dead ends.',
      }),
    ]);

    const runner = new InvestigationRunner({
      targetRef: repoRoot,
      mode: 'declared',
      plannerAdapter: planner,
      judgeAdapter: new QueueAdapter([]),
      maxIterations: 3,
      maxCostUsd: 5,
      campaignDir,
      deadEndThreshold: 2,
    });

    const result = await runner.run();
    assert.equal(result.status, 'iteration_limit');

    const events = (await readFile(join(result.runDir, 'events.jsonl'), 'utf8'))
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as { stage: string });

    assert.ok(events.some((event) => event.stage === 'dead_end_escape_hatch'));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('InvestigationRunner marks strict runs incomplete when source coverage is missing', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-strict-source-'));

  try {
    const repoRoot = join(root, 'target');
    const campaignDir = join(root, 'campaigns');
    const targetPath = join(root, 'strict-target.yaml');

    await mkdir(repoRoot, { recursive: true });
    await writeFile(join(repoRoot, 'package.json'), JSON.stringify({ name: 'strict-target', version: '1.0.0' }, null, 2), 'utf8');
    await writeFile(
      targetPath,
      `id: strict-target
name: Strict Target
kind: code
environment: sandbox
repoRoot: ${repoRoot}
strictVerification: true
verificationPolicy:
  expectedRepoMarkers:
    - package.json
  requireSourceScan: true
`,
      'utf8',
    );

    const runner = new InvestigationRunner({
      targetRef: targetPath,
      mode: 'declared',
      plannerAdapter: new QueueAdapter([]),
      judgeAdapter: new QueueAdapter([]),
      maxIterations: 0,
      maxCostUsd: 5,
      campaignDir,
      strictVerification: true,
    });

    const result = await runner.run();
    assert.equal(result.executionStatus, 'incomplete');
    assert.ok(result.coverageGaps?.some((gap) => gap.code === 'zero_source_files'));

    const summary = JSON.parse(await readFile(join(result.runDir, 'summary.json'), 'utf8')) as {
      executionStatus: string;
      coverageGaps: Array<{ code: string }>;
    };
    assert.equal(summary.executionStatus, 'incomplete');
    assert.ok(summary.coverageGaps.some((gap) => gap.code === 'zero_source_files'));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('InvestigationRunner fails strict local-live runs before probe execution when required identities are missing', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-strict-live-'));

  try {
    const repoRoot = join(root, 'target');
    const campaignDir = join(root, 'campaigns');
    const targetPath = join(root, 'strict-static.yaml');
    const liveTargetPath = join(root, 'strict-local-live.yaml');

    await mkdir(join(repoRoot, 'src'), { recursive: true });
    await writeFile(join(repoRoot, 'package.json'), JSON.stringify({ name: 'strict-live-target', version: '1.0.0' }, null, 2), 'utf8');
    await writeFile(join(repoRoot, 'src', 'index.ts'), 'export const ok = true;\n', 'utf8');

    await writeFile(
      targetPath,
      `id: strict-static
name: Strict Static
kind: code
environment: sandbox
repoRoot: ${repoRoot}
strictVerification: true
requiredLanes:
  - local-live
verificationPolicy:
  expectedRepoMarkers:
    - package.json
    - src
  requireSourceScan: true
`,
      'utf8',
    );

    await writeFile(
      liveTargetPath,
      `id: strict-local-live
name: Strict Local Live
kind: http
environment: local_live
baseUrl: http://127.0.0.1:65535
repoRoot: ${repoRoot}
strictVerification: true
requiredIdentities:
  - user_a_low
  - user_b_low
verificationPolicy:
  expectedRepoMarkers:
    - package.json
    - src
  requireSourceScan: true
identities:
  - id: user_a_low
    kind: bearer_token
    tokenEnv: STRICT_USER_A_TOKEN
    organizationId: org_a
  - id: user_b_low
    kind: bearer_token
    tokenEnv: STRICT_USER_B_TOKEN
    organizationId: org_b
`,
      'utf8',
    );

    delete process.env.STRICT_USER_A_TOKEN;
    delete process.env.STRICT_USER_B_TOKEN;

    const runner = new InvestigationRunner({
      targetRef: targetPath,
      mode: 'declared',
      plannerAdapter: new QueueAdapter([]),
      judgeAdapter: new QueueAdapter([]),
      maxIterations: 0,
      maxCostUsd: 5,
      campaignDir,
      strictVerification: true,
      verifyVia: ['local-live'],
      liveTargetRef: liveTargetPath,
    });

    const result = await runner.run();
    assert.equal(result.executionStatus, 'incomplete');
    assert.ok(result.coverageGaps?.some((gap) => /Missing required local-live identities/i.test(gap.message)));

    const summary = JSON.parse(await readFile(join(result.runDir, 'summary.json'), 'utf8')) as {
      verificationLanes: {
        localLive?: {
          attempted: number;
          authFailed: number;
          status: string;
          coverageGaps: string[];
        };
      };
    };
    assert.equal(summary.verificationLanes.localLive?.status, 'incomplete');
    assert.equal(summary.verificationLanes.localLive?.attempted, 0);
    assert.equal(summary.verificationLanes.localLive?.authFailed, 0);
    assert.ok(summary.verificationLanes.localLive?.coverageGaps.some((gap) => /Missing required local-live identities/i.test(gap)));
  } finally {
    delete process.env.STRICT_USER_A_TOKEN;
    delete process.env.STRICT_USER_B_TOKEN;
    await rm(root, { recursive: true, force: true });
  }
});

test('InvestigationRunner can resume a completed static campaign directly into verification lanes', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-resume-verify-'));

  try {
    const { repoRoot, campaignDir } = await createFixtureRepo(root);
    const targetPath = join(root, 'resume-static.yaml');
    const liveTargetPath = join(root, 'resume-live.yaml');

    await writeFile(
      targetPath,
      `id: resume-static
name: Resume Static
kind: code
environment: sandbox
repoRoot: ${repoRoot}
strictVerification: true
requiredLanes:
  - local-live
verificationPolicy:
  expectedRepoMarkers:
    - package.json
    - src
  requireSourceScan: true
`,
      'utf8',
    );

    await writeFile(
      liveTargetPath,
      `id: resume-live
name: Resume Live
kind: http
environment: local_live
baseUrl: http://127.0.0.1:65535
repoRoot: ${repoRoot}
strictVerification: true
requiredIdentities:
  - user_a_low
verificationPolicy:
  expectedRepoMarkers:
    - package.json
    - src
  requireSourceScan: true
identities:
  - id: guest
    kind: anonymous
  - id: user_a_low
    kind: bearer_token
    tokenEnv: RESUME_USER_A_TOKEN
`,
      'utf8',
    );

    delete process.env.RESUME_USER_A_TOKEN;

    const initial = await new InvestigationRunner({
      targetRef: targetPath,
      mode: 'declared',
      plannerAdapter: new QueueAdapter([]),
      judgeAdapter: new QueueAdapter([]),
      maxIterations: 0,
      maxCostUsd: 5,
      campaignDir,
    }).run();

    assert.equal(initial.status, 'iteration_limit');
    const statePath = join(campaignDir, initial.campaignId, 'state.json');
    const staleState = JSON.parse(await readFile(statePath, 'utf8')) as Record<string, unknown>;
    staleState.failedAt = '2026-01-01T00:00:00.000Z';
    staleState.failureReason = 'stale failure';
    staleState.failurePhase = 'planning';
    await writeFile(statePath, JSON.stringify(staleState, null, 2), 'utf8');

    const resumed = await new InvestigationRunner({
      targetRef: targetPath,
      mode: 'declared',
      plannerAdapter: new QueueAdapter([]),
      judgeAdapter: new QueueAdapter([]),
      maxIterations: 0,
      maxCostUsd: 5,
      campaignDir,
      resumeCampaignId: initial.campaignId,
      resumeAt: 'verification',
      strictVerification: true,
      verifyVia: ['local-live'],
      liveTargetRef: liveTargetPath,
    }).run();

    assert.equal(resumed.status, 'completed');
    assert.equal(resumed.executionStatus, 'incomplete');
    assert.ok(resumed.verificationLanes?.localLive);
    assert.ok(resumed.coverageGaps?.some((gap) => /Missing required local-live identities/i.test(gap.message)));
    const resumedState = JSON.parse(await readFile(statePath, 'utf8')) as Record<string, unknown>;
    assert.equal(resumedState.failedAt, undefined);
    assert.equal(resumedState.failureReason, undefined);
    assert.equal(resumedState.failurePhase, undefined);
  } finally {
    delete process.env.RESUME_USER_A_TOKEN;
    await rm(root, { recursive: true, force: true });
  }
});

test('InvestigationRunner fails strict local-live resume before probe execution when verification transports are unavailable', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-resume-providerless-'));
  const server = await startVerificationServer();

  try {
    const { repoRoot, campaignDir } = await createFixtureRepo(root);
    const targetPath = join(root, 'providerless-static.yaml');
    const liveTargetPath = join(root, 'providerless-live.yaml');

    await writeFile(
      targetPath,
      `id: providerless-static
name: Providerless Static
kind: code
environment: sandbox
repoRoot: ${repoRoot}
strictVerification: true
requiredLanes:
  - local-live
verificationPolicy:
  expectedRepoMarkers:
    - package.json
    - src
  requireSourceScan: true
`,
      'utf8',
    );

    await writeFile(
      liveTargetPath,
      `id: providerless-live
name: Providerless Live
kind: http
environment: local_live
baseUrl: ${server.baseUrl}
repoRoot: ${repoRoot}
strictVerification: true
requiredLanes:
  - local-live
verificationPolicy:
  expectedRepoMarkers:
    - package.json
    - src
  requireSourceScan: true
identities:
  - id: guest
    kind: anonymous
canaries:
  - id: guest_private
    description: Guest attempts a protected route
    method: GET
    path: /private
    identityId: guest
    expectedWhenSafe:
      statusIn: [403]
    expectedWhenExploitable:
      status: 200
liveProbing:
  rateLimit:
    requestsPerSecond: 100
    requestsPerCampaign: 100
`,
      'utf8',
    );

    const initial = await new InvestigationRunner({
      targetRef: targetPath,
      mode: 'declared',
      plannerAdapter: new QueueAdapter([]),
      judgeAdapter: new QueueAdapter([]),
      maxIterations: 0,
      maxCostUsd: 5,
      campaignDir,
    }).run();

    const seededMemory = createEmptyMemory(initial.campaignId);
    seededMemory.signals.push({
      id: 'ws-verify-1',
      discoveredAt: new Date().toISOString(),
      iteration: 0,
      description: 'Potential auth boundary on admin agents route',
      surface: 'static:http',
      confidence: 0.7,
      novelty: 0.7,
      relatedAssets: ['src/api/app.ts', 'src/api/routes/admin.routes.ts'],
      potentialCapabilities: ['admin_read'],
      suggestedFollowUps: ['Probe /api/v1/admin/agents as guest'],
      status: 'active',
      correlatedWith: [],
      unresolvedCorrelations: [],
    });
    seededMemory.hypotheses.push({
      id: 'ph-session-1',
      synthesizedAt: new Date().toISOString(),
      iteration: 0,
      description: 'Guest access might reach the admin agents route if auth is mounted incorrectly.',
      severity: 'high',
      signalIds: ['ws-verify-1'],
      prerequisites: [],
      status: 'proposed',
      attempts: [],
    });
    await saveMemory(seededMemory, join(campaignDir, initial.campaignId, 'memory.json'));

    const resumed = await new InvestigationRunner({
      targetRef: targetPath,
      mode: 'declared',
      runMode: 'serious-local',
      plannerAdapter: new UnavailableAdapter('planner-missing', 'planner missing'),
      judgeAdapter: new UnavailableAdapter('judge-missing', 'judge missing'),
      maxIterations: 0,
      maxCostUsd: 5,
      campaignDir,
      resumeCampaignId: initial.campaignId,
      resumeAt: 'verification',
      strictVerification: true,
      verifyVia: ['local-live'],
      liveTargetRef: liveTargetPath,
    }).run();

    assert.equal(resumed.status, 'completed');
    assert.equal(resumed.executionStatus, 'incomplete');
    assert.equal(resumed.verificationLanes?.localLive?.attempted ?? 0, 0);
    assert.ok(resumed.coverageGaps?.some((gap) => /planner\/worker transport/i.test(gap.message)) || resumed.coverageGaps?.some((gap) => /required identities/i.test(gap.message)));

    const summary = JSON.parse(await readFile(join(resumed.runDir, 'summary.json'), 'utf8')) as {
      status?: string | null;
      executionStatus?: string | null;
      executiveVerdict?: string | null;
      assessmentVerdict?: string | null;
      localLive?: { attempted?: number } | null;
    };
    assert.equal(summary.status, 'completed');
    assert.equal(summary.executionStatus, 'incomplete');
    assert.ok(typeof summary.executiveVerdict === 'string' && summary.executiveVerdict.length > 0);
    assert.equal(summary.assessmentVerdict, summary.executiveVerdict);
    assert.equal(typeof summary.localLive?.attempted, 'number');
  } finally {
    await server.close();
    await rm(root, { recursive: true, force: true });
  }
});

test('InvestigationRunner defers Linux runtime availability to local startup for serious local-live targets', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-linux-startup-'));

  try {
    const { repoRoot, campaignDir } = await createFixtureRepo(root);
    const targetPath = join(root, 'linux-static.yaml');
    const liveTargetPath = join(root, 'linux-live.yaml');

    await writeFile(
      targetPath,
      `id: linux-static
name: Linux Static
kind: code
environment: sandbox
repoRoot: ${repoRoot}
strictVerification: true
requiredLanes:
  - local-live
verificationPolicy:
  expectedRepoMarkers:
    - package.json
    - src
  requireSourceScan: true
`,
      'utf8',
    );

    await writeFile(
      liveTargetPath,
      `id: linux-live
name: Linux Live
kind: http
environment: local_live
baseUrl: http://127.0.0.1:65535
repoRoot: ${repoRoot}
strictVerification: true
requiredLanes:
  - local-live
verificationPolicy:
  expectedRepoMarkers:
    - package.json
    - src
  requireSourceScan: true
linuxSidecar:
  enabled: true
  composeCwd: ${repoRoot}
  composeService: backend
localStartup:
  command: sh
  args:
    - -lc
    - echo bootstrap
`,
      'utf8',
    );

    const runner = new InvestigationRunner({
      targetRef: targetPath,
      mode: 'declared',
      plannerAdapter: new QueueAdapter([]),
      judgeAdapter: new QueueAdapter([]),
      maxIterations: 0,
      maxCostUsd: 5,
      campaignDir,
      strictVerification: true,
      verifyVia: ['local-live'],
      liveTargetRef: liveTargetPath,
      linuxRuntime: 'container',
    });

    const memory = createEmptyMemory('campaign-linux-startup');
    memory.signals.push({
      id: 'ws-1',
      discoveredAt: new Date().toISOString(),
      iteration: 0,
      description: 'runtime breadcrumb',
      surface: 'runtime',
      confidence: 0.5,
      novelty: 0.5,
      relatedAssets: ['src/app.ts'],
      potentialCapabilities: [],
      suggestedFollowUps: [],
      status: 'active',
      correlatedWith: [],
      unresolvedCorrelations: [],
    });

    const { gate, liveTarget } = await runner.evaluateVerificationMidPipelineReadiness({
      target: await loadInvestigationTarget(targetPath),
      memory,
      lanes: ['local-live'],
    });

    assert.equal(liveTarget?.id, 'linux-live');
    assert.equal(gate.passed, true);
    assert.equal(gate.shouldAbort, false);
    assert.ok(!gate.gaps.some((gap) => gap.code === 'linux_runtime_unavailable'));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('InvestigationRunner checkpoints native session ids during local-live verification', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-session-checkpoint-'));
  let server: ReturnType<typeof createServer> | undefined;

  try {
    const { repoRoot, campaignDir } = await createFixtureRepo(root);
    const targetPath = join(root, 'session-static.yaml');
    const liveTargetPath = join(root, 'session-live.yaml');

    await writeFile(
      targetPath,
      `id: session-static
name: Session Static
kind: code
environment: sandbox
repoRoot: ${repoRoot}
strictVerification: true
requiredLanes:
  - local-live
verificationPolicy:
  expectedRepoMarkers:
    - package.json
    - src
  requireSourceScan: true
`,
      'utf8',
    );

    server = createServer((_request, response) => {
      response.statusCode = 401;
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify({ ok: false }));
    });
    server.listen(0);
    await once(server, 'listening');
    const address = server.address();
    const port = typeof address === 'object' && address ? address.port : 0;

    await writeFile(
      liveTargetPath,
      `id: session-live
name: Session Live
kind: http
environment: local_live
baseUrl: http://127.0.0.1:${port}
repoRoot: ${repoRoot}
strictVerification: true
verificationPolicy:
  expectedRepoMarkers:
    - package.json
    - src
  requireSourceScan: true
  focusedLeadConfirmationEnabled: false
identities:
  - id: guest
    kind: anonymous
canaries:
  - id: auth-bypass-canary
    description: Admin list should reject unauthenticated guest access
    method: GET
    path: /api/v1/admin/agents
    identityId: guest
`,
      'utf8',
    );

    const initial = await new InvestigationRunner({
      targetRef: targetPath,
      mode: 'declared',
      plannerAdapter: new QueueAdapter([]),
      judgeAdapter: new QueueAdapter([]),
      maxIterations: 0,
      maxCostUsd: 5,
      campaignDir,
    }).run();

    const seededMemory = createEmptyMemory(initial.campaignId);
    seededMemory.signals.push({
      id: 'ws-session-1',
      discoveredAt: new Date().toISOString(),
      iteration: 0,
      description: 'Potential guest access to admin agents route.',
      surface: 'static:http',
      confidence: 0.7,
      novelty: 0.7,
      relatedAssets: ['src/api/app.ts', 'src/api/routes/admin.routes.ts'],
      potentialCapabilities: ['admin_read'],
      suggestedFollowUps: ['Probe /api/v1/admin/agents as guest'],
      status: 'active',
      correlatedWith: [],
      unresolvedCorrelations: [],
    });
    seededMemory.hypotheses.push({
      id: 'ph-session-1',
      synthesizedAt: new Date().toISOString(),
      iteration: 0,
      description: 'Guest access might reach the admin agents route if auth is mounted incorrectly.',
      severity: 'high',
      signalIds: ['ws-session-1'],
      prerequisites: [],
      status: 'proposed',
      attempts: [],
    });
    await saveMemory(seededMemory, join(campaignDir, initial.campaignId, 'memory.json'));

    const resumed = await new InvestigationRunner({
      targetRef: targetPath,
      mode: 'declared',
      plannerAdapter: new SessionQueueAdapter([
        {
          sessionId: 'sess-local-live-1',
          content: JSON.stringify({
            probes: [
              {
                probeKind: 'http',
                identityId: 'guest',
                http: { method: 'GET', path: '/api/v1/admin/agents' },
                rationale: 'probe auth boundary',
              },
            ],
            reasoning: 'single guest probe',
          }),
        },
      ]),
      judgeAdapter: new QueueAdapter([]),
      maxIterations: 0,
      maxCostUsd: 5,
      campaignDir,
      resumeCampaignId: initial.campaignId,
      resumeAt: 'verification',
      strictVerification: true,
      verifyVia: ['local-live'],
      liveTargetRef: liveTargetPath,
      verificationHypothesisLimit: 1,
      liveProbesPerHypothesis: 1,
      allowLocalMutations: false,
    }).run();

    assert.equal(resumed.status, 'completed');
    const statePath = join(campaignDir, initial.campaignId, 'state.json');
    const resumedState = JSON.parse(await readFile(statePath, 'utf8')) as {
      sessionIds?: Record<string, string>;
    };
    assert.ok(resumedState.sessionIds);
    assert.ok(Object.values(resumedState.sessionIds ?? {}).includes('sess-local-live-1'));
  } finally {
    if (server) {
      await new Promise<void>((resolveClose) => {
        server!.close(() => resolveClose());
      });
    }
    await rm(root, { recursive: true, force: true });
  }
});

test('InvestigationRunner prefers the dedicated local-live planner adapter during resumed verification', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-local-live-primary-'));
  let server: ReturnType<typeof createServer> | undefined;

  try {
    const { repoRoot, campaignDir } = await createFixtureRepo(root);
    const targetPath = join(root, 'local-live-primary-static.yaml');
    const liveTargetPath = join(root, 'local-live-primary-live.yaml');

    await writeFile(
      targetPath,
      `id: local-live-primary-static
name: Local Live Primary Static
kind: code
environment: sandbox
repoRoot: ${repoRoot}
strictVerification: true
requiredLanes:
  - local-live
verificationPolicy:
  expectedRepoMarkers:
    - package.json
    - src
  requireSourceScan: true
`,
      'utf8',
    );

    server = createServer((_request, response) => {
      response.statusCode = 401;
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify({ ok: false }));
    });
    server.listen(0);
    await once(server, 'listening');
    const address = server.address();
    const port = typeof address === 'object' && address ? address.port : 0;

    await writeFile(
      liveTargetPath,
      `id: local-live-primary-live
name: Local Live Primary Live
kind: http
environment: local_live
baseUrl: http://127.0.0.1:${port}
repoRoot: ${repoRoot}
strictVerification: true
verificationPolicy:
  expectedRepoMarkers:
    - package.json
    - src
  requireSourceScan: true
  focusedLeadConfirmationEnabled: false
identities:
  - id: guest
    kind: anonymous
canaries:
  - id: auth-bypass-canary
    description: Admin list should reject unauthenticated guest access
    method: GET
    path: /api/v1/admin/agents
    identityId: guest
`,
      'utf8',
    );

    const initial = await new InvestigationRunner({
      targetRef: targetPath,
      mode: 'declared',
      plannerAdapter: new QueueAdapter([]),
      judgeAdapter: new QueueAdapter([]),
      maxIterations: 0,
      maxCostUsd: 5,
      campaignDir,
    }).run();

    const seededMemory = createEmptyMemory(initial.campaignId);
    seededMemory.signals.push({
      id: 'ws-local-live-primary-1',
      discoveredAt: new Date().toISOString(),
      iteration: 0,
      description: 'Potential guest access to admin agents route.',
      surface: 'static:http',
      confidence: 0.7,
      novelty: 0.7,
      relatedAssets: ['src/api/app.ts', 'src/api/routes/admin.routes.ts'],
      potentialCapabilities: ['admin_read'],
      suggestedFollowUps: ['Probe /api/v1/admin/agents as guest'],
      status: 'active',
      correlatedWith: [],
      unresolvedCorrelations: [],
    });
    seededMemory.hypotheses.push({
      id: 'ph-local-live-primary-1',
      synthesizedAt: new Date().toISOString(),
      iteration: 0,
      description: 'Guest access might reach the admin agents route if auth is mounted incorrectly.',
      severity: 'high',
      signalIds: ['ws-local-live-primary-1'],
      prerequisites: [],
      status: 'proposed',
      attempts: [],
    });
    await saveMemory(seededMemory, join(campaignDir, initial.campaignId, 'memory.json'));

    const resumed = await new InvestigationRunner({
      targetRef: targetPath,
      mode: 'declared',
      plannerAdapter: new QueueAdapter([]),
      localLivePlannerAdapter: new SessionQueueAdapter([
        {
          sessionId: 'sess-local-live-primary-override',
          content: JSON.stringify({
            probes: [
              {
                probeKind: 'http',
                identityId: 'guest',
                http: { method: 'GET', path: '/api/v1/admin/agents' },
                rationale: 'probe auth boundary',
              },
            ],
            reasoning: 'single guest probe from dedicated local-live adapter',
          }),
        },
      ]),
      judgeAdapter: new QueueAdapter([]),
      maxIterations: 0,
      maxCostUsd: 5,
      campaignDir,
      resumeCampaignId: initial.campaignId,
      resumeAt: 'verification',
      strictVerification: true,
      verifyVia: ['local-live'],
      liveTargetRef: liveTargetPath,
      verificationHypothesisLimit: 1,
      liveProbesPerHypothesis: 1,
      allowLocalMutations: false,
    }).run();

    assert.equal(resumed.status, 'completed');
    const statePath = join(campaignDir, initial.campaignId, 'state.json');
    const resumedState = JSON.parse(await readFile(statePath, 'utf8')) as {
      sessionIds?: Record<string, string>;
    };
    assert.ok(resumedState.sessionIds);
    assert.ok(Object.values(resumedState.sessionIds ?? {}).includes('sess-local-live-primary-override'));
  } finally {
    if (server) {
      await new Promise<void>((resolveClose) => {
        server!.close(() => resolveClose());
      });
    }
    await rm(root, { recursive: true, force: true });
  }
});

test('InvestigationRunner local-live lane can carry an available counter planner without crashing', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-local-live-counter-'));
  const server = await startVerificationServer();

  try {
    const { repoRoot, campaignDir } = await createFixtureRepo(root);
    const targetPath = join(root, 'counter-static.yaml');
    const liveTargetPath = join(root, 'counter-live.yaml');

    await writeFile(
      targetPath,
      `id: counter-static
name: Counter Static
kind: code
environment: sandbox
repoRoot: ${repoRoot}
strictVerification: true
requiredLanes:
  - local-live
verificationPolicy:
  expectedRepoMarkers:
    - package.json
    - src
  requireSourceScan: true
`,
      'utf8',
    );

    await writeFile(
      liveTargetPath,
      `id: counter-live
name: Counter Live
kind: http
environment: local_live
baseUrl: ${server.baseUrl}
repoRoot: ${repoRoot}
strictVerification: true
requiredLanes:
  - local-live
verificationPolicy:
  expectedRepoMarkers:
    - package.json
    - src
  requireSourceScan: true
identities:
  - id: guest
    kind: anonymous
canaries:
  - id: auth_bypass_no_header
    description: Guest attempts a protected route
    method: GET
    path: /private
    identityId: guest
    expectedWhenSafe:
      statusIn: [403]
    expectedWhenExploitable:
      status: 200
liveProbing:
  rateLimit:
    requestsPerSecond: 100
    requestsPerCampaign: 100
`,
      'utf8',
    );

    const initial = await new InvestigationRunner({
      targetRef: targetPath,
      mode: 'declared',
      plannerAdapter: new QueueAdapter([]),
      judgeAdapter: new QueueAdapter([]),
      maxIterations: 0,
      maxCostUsd: 5,
      campaignDir,
    }).run();

    const resumed = await new InvestigationRunner({
      targetRef: targetPath,
      mode: 'declared',
      plannerAdapter: new QueueAdapter([
        JSON.stringify({
          probes: [
            {
              probeKind: 'http',
              identityId: 'guest',
              http: {
                method: 'GET',
                path: '/private',
              },
              rationale: 'Check that guest access remains blocked.',
            },
          ],
          reasoning: 'Use one direct probe.',
        }),
      ]),
      counterPlannerAdapter: new QueueAdapter([]),
      judgeAdapter: new UnavailableAdapter('judge-missing', 'judge missing'),
      maxIterations: 0,
      maxCostUsd: 5,
      campaignDir,
      resumeCampaignId: initial.campaignId,
      resumeAt: 'verification',
      strictVerification: true,
      verifyVia: ['local-live'],
      liveTargetRef: liveTargetPath,
    }).run();

    assert.equal(resumed.status, 'completed');
    assert.ok((resumed.verificationLanes?.localLive?.attempted ?? 0) > 0);
    assert.equal(resumed.verificationLanes?.localLive?.refuted, 1);
  } finally {
    await server.close();
    await rm(root, { recursive: true, force: true });
  }
});

test('InvestigationRunner marks test-synthesis incomplete instead of crashing when no synthesis model is available', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-test-synth-missing-'));

  try {
    const { repoRoot, campaignDir } = await createFixtureRepo(root);
    const targetPath = join(root, 'test-synth-static.yaml');

    await writeFile(
      targetPath,
      `id: test-synth-static
name: Test Synthesis Static
kind: code
environment: sandbox
repoRoot: ${repoRoot}
strictVerification: true
requiredLanes:
  - test-synthesis
verificationPolicy:
  expectedRepoMarkers:
    - package.json
    - src
  requireSourceScan: true
`,
      'utf8',
    );

    const memory = createEmptyMemory('campaign-test-synth');
    memory.signals.push({
      id: 'ws-1',
      discoveredAt: new Date().toISOString(),
      iteration: 0,
      description: 'Dynamic code clue in src/app.ts',
      surface: 'code',
      confidence: 0.8,
      novelty: 0.8,
      relatedAssets: ['src/app.ts'],
      potentialCapabilities: ['dynamic code execution'],
      suggestedFollowUps: ['read src/app.ts'],
      status: 'active',
      correlatedWith: [],
      unresolvedCorrelations: [],
    });
    memory.hypotheses.push({
      id: 'hyp-1',
      synthesizedAt: new Date().toISOString(),
      iteration: 0,
      description: 'Dynamic rendering in src/app.ts may make code execution reachable.',
      severity: 'high',
      signalIds: ['ws-1'],
      prerequisites: ['Inspect src/app.ts'],
      status: 'proposed',
      attempts: [],
    });

    const evidenceStore = new EvidenceStore('campaign-test-synth', join(campaignDir, 'runs'));
    await evidenceStore.prepare();

    const runner = new InvestigationRunner({
      targetRef: targetPath,
      mode: 'declared',
      plannerAdapter: new UnavailableAdapter('planner-missing', 'planner missing'),
      judgeAdapter: new UnavailableAdapter('judge-missing', 'judge missing'),
      maxIterations: 0,
      maxCostUsd: 5,
      campaignDir,
      strictVerification: true,
      verifyVia: ['test-synthesis'],
    });

    const summary = await (runner as any).runVerificationLanes({
      target: await (await import('./target-profile.js')).loadInvestigationTarget(targetPath),
      memory,
      stateStore: {} as any,
      evidenceStore,
      campaignDir: join(campaignDir, 'campaign-test-synth'),
      lanes: ['test-synthesis'],
    });

    assert.equal(summary.testSynthesis?.status, 'incomplete');
    assert.equal(summary.testSynthesis?.attempted, 0);
    assert.ok(summary.testSynthesis?.coverageGaps.some((gap: string) => /No usable model adapter is available for test synthesis/i.test(gap)));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('InvestigationRunner routes confirm-live through the integrated local-live lane', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-confirm-live-'));
  const server = await startVerificationServer();

  try {
    const { repoRoot, campaignDir } = await createFixtureRepo(root);
    const targetPath = join(root, 'confirm-static.yaml');
    const liveTargetPath = join(root, 'confirm-live.yaml');

    await writeFile(
      targetPath,
      `id: confirm-static
name: Confirm Static
kind: code
environment: sandbox
repoRoot: ${repoRoot}
verificationPolicy:
  expectedRepoMarkers:
    - package.json
    - src
  requireSourceScan: true
`,
      'utf8',
    );

    await writeFile(
      liveTargetPath,
      `id: confirm-live
name: Confirm Live
kind: http
environment: local_live
baseUrl: ${server.baseUrl}
repoRoot: ${repoRoot}
identities:
  - id: guest
    kind: anonymous
canaries:
  - id: auth_bypass_guest
    description: Guest must not access a protected route
    method: GET
    path: /private
    identityId: guest
    expectedWhenSafe:
      statusIn: [403]
    expectedWhenExploitable:
      status: 200
liveProbing:
  rateLimit:
    requestsPerSecond: 100
    requestsPerCampaign: 100
`,
      'utf8',
    );

    const result = await new InvestigationRunner({
      targetRef: targetPath,
      mode: 'declared',
      plannerAdapter: new QueueAdapter([]),
      judgeAdapter: new QueueAdapter([]),
      maxIterations: 0,
      maxCostUsd: 5,
      campaignDir,
      confirmLive: true,
      liveTargetRef: liveTargetPath,
    }).run();

    assert.equal(result.liveConfirmation?.enabled, true);
    assert.equal(result.liveConfirmation?.campaignId, result.campaignId);
    assert.equal(result.liveConfirmation?.confirmedFindings, 0);
    assert.ok((result.verificationLanes?.localLive?.attempted ?? 0) > 0);

    const summary = JSON.parse(await readFile(join(result.runDir, 'summary.json'), 'utf8')) as {
      childCampaigns?: Array<{ lane: string }>;
      verificationLanes?: { localLive?: { attempted: number } };
      liveConfirmation?: { campaignId?: string };
    };
    assert.equal(summary.liveConfirmation?.campaignId, result.campaignId);
    assert.ok((summary.verificationLanes?.localLive?.attempted ?? 0) > 0);
    assert.ok(!summary.childCampaigns?.some((campaign) => campaign.lane === 'live-confirmation'));
  } finally {
    await server.close();
    await rm(root, { recursive: true, force: true });
  }
});

test('InvestigationRunner verification orchestration exercises test, live, hosted, supply-chain, and monitoring lanes', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-verify-lanes-'));
  const server = await startVerificationServer();
  const originalConfirmationRun = SupplyChainConfirmationRunner.prototype.run;

  try {
    const { repoRoot, campaignDir } = await createFixtureRepo(root);
    const baselinePath = join(root, '.security-lab-baseline.json');
    const liveTargetPath = join(root, 'fixture-local-live.yaml');
    const hostedTargetPath = join(root, 'fixture-hosted.yaml');

    await writeFile(
      join(repoRoot, 'package.json'),
      JSON.stringify(
        {
          name: 'fixture-target',
          version: '1.0.0',
          securityLab: 'SECURITY_LAB_CANARY',
          dependencies: { 'fixture-dep': '1.0.0' },
        },
        null,
        2,
      ),
      'utf8',
    );
    await writeFile(
      join(repoRoot, 'package-lock.json'),
      JSON.stringify(
        {
          name: 'fixture-target',
          lockfileVersion: 3,
          packages: {
            '': {
              name: 'fixture-target',
              version: '1.0.0',
            },
            'node_modules/fixture-dep': {
              version: '1.0.0',
              integrity: 'sha512-baseline',
              resolved: 'https://registry.npmjs.org/fixture-dep/-/fixture-dep-1.0.0.tgz',
            },
          },
        },
        null,
        2,
      ),
      'utf8',
    );

    await runSentinel(repoRoot, baselinePath);

    await writeFile(
      join(repoRoot, 'package.json'),
      JSON.stringify(
        {
          name: 'fixture-target',
          version: '1.0.0',
          securityLab: 'SECURITY_LAB_CANARY',
          dependencies: { 'fixture-dep': '2.0.0' },
        },
        null,
        2,
      ),
      'utf8',
    );
    await writeFile(
      join(repoRoot, 'package-lock.json'),
      JSON.stringify(
        {
          name: 'fixture-target',
          lockfileVersion: 3,
          packages: {
            '': {
              name: 'fixture-target',
              version: '1.0.0',
            },
            'node_modules/fixture-dep': {
              version: '2.0.0',
              integrity: 'sha512-updated',
              resolved: 'https://registry.npmjs.org/fixture-dep/-/fixture-dep-2.0.0.tgz',
            },
          },
        },
        null,
        2,
      ),
      'utf8',
    );

    await writeFile(
      liveTargetPath,
      `id: fixture-local-live
name: Fixture Local Live
kind: http
environment: local_live
baseUrl: ${server.baseUrl}
repoRoot: ${repoRoot}
cwd: ${repoRoot}
identities:
  - id: guest
    kind: anonymous
canaries:
  - id: guest_private
    description: Guest attempts a protected route
    method: GET
    path: /private
    identityId: guest
    expectedWhenSafe:
      statusIn: [403]
    expectedWhenExploitable:
      status: 200
liveProbing:
  rateLimit:
    requestsPerSecond: 100
    requestsPerCampaign: 100
processDecoys:
  envMarkers:
    - SECURITY_LAB_DECOY
persistenceCanaries:
  startupFiles:
    - package.json
`,
      'utf8',
    );

    await writeFile(
      hostedTargetPath,
      `id: fixture-hosted
name: Fixture Hosted
kind: http
environment: hosted_authorized
baseUrl: ${server.baseUrl}
authSources:
  anonymous:
    source: anonymous
hostedIdentities:
  - id: guest
    description: Guest canary
    authSourceRef: anonymous
    expectedRole: anonymous
    forbiddenBoundaries:
      - protected_route
ingressChecks:
  - description: health
    method: GET
    path: /health
    expectStatusIn: [200]
rateLimit:
  requestsPerSecond: 100
  requestsPerCampaign: 100
  requestsPerDay: 100
cooldownSeconds: 0
`,
      'utf8',
    );

    process.env.SECURITY_LAB_DECOY = 'SECURITY_LAB_DECOY';

    const memory = createEmptyMemory('campaign-verify');
    memory.signals.push({
      id: 'ws-1',
      discoveredAt: new Date().toISOString(),
      iteration: 0,
      description: 'Dynamic-code clue in src/app.ts',
      surface: 'code',
      confidence: 0.8,
      novelty: 0.7,
      relatedAssets: ['src/app.ts'],
      potentialCapabilities: ['dynamic code execution'],
      suggestedFollowUps: ['read src/app.ts'],
      status: 'active',
      correlatedWith: [],
      unresolvedCorrelations: [],
    });
    memory.hypotheses.push({
      id: 'hyp-1',
      synthesizedAt: new Date().toISOString(),
      iteration: 0,
      description: 'Template rendering may make dynamic code execution reachable in src/app.ts',
      severity: 'high',
      signalIds: ['ws-1'],
      prerequisites: ['Inspect src/app.ts'],
      status: 'proposed',
      attempts: [],
    });

    const evidenceStore = new EvidenceStore('campaign-verify', join(campaignDir, 'runs'));
    await evidenceStore.prepare();

    SupplyChainConfirmationRunner.prototype.run = async function patchedRun(changeSet) {
      return [
        {
          experimentId: 'exp-supply-1',
          changeSetId: changeSet.changeSetId,
          packageName: 'fixture-dep',
          version: '2.0.0',
          startedAt: new Date().toISOString(),
          completedAt: new Date().toISOString(),
          inspection: {
            packageName: 'fixture-dep',
            version: '2.0.0',
            tarballSha256: 'sha',
            hasInstallScript: false,
            hasPostInstallScript: false,
            hasNativeBinaries: false,
            nativeBinaryPaths: [],
            hasObfuscatedSource: false,
            obfuscatedFiles: [],
            containsNetworkCalls: false,
            networkCallSummary: [],
            registryMatchesBaseline: true,
            signatureVerified: false,
            notes: [],
          },
          baselineComparison: {
            diffSummary: 'version changed',
            materiallyDifferent: true,
          },
          policyHash: 'policy-hash',
          verdict: 'needs_review',
          reasoning: 'Fixture dependency drift needs review.',
          evidenceRefs: ['fixture-dep@2.0.0'],
        },
      ];
    };

    const runner = new InvestigationRunner({
      targetRef: repoRoot,
      mode: 'declared',
      plannerAdapter: new PatternAdapter(),
      judgeAdapter: new PatternAdapter(),
      synthesizerAdapter: new QueueAdapter(["import test from 'node:test';\nimport assert from 'node:assert/strict';\ntest('safe', () => { console.log('SECURITY_LAB_SAFE'); assert.ok(true); });\n"]),
      maxIterations: 1,
      maxCostUsd: 20,
      campaignDir,
      verifyVia: ['test-synthesis', 'local-live', 'hosted', 'supply-chain'],
      liveTargetRef: liveTargetPath,
      hostedTargetRef: hostedTargetPath,
      authorizeHosted: true,
      baselinePath,
      monitoringStress: true,
      pairedModes: true,
      contextBand: 'baseline',
    });

    const summary = await (runner as any).runVerificationLanes({
      target: await (await import('./target-profile.js')).loadInvestigationTarget(repoRoot),
      memory,
      stateStore: {} as any,
      evidenceStore,
      campaignDir: join(campaignDir, 'campaign-verify'),
      lanes: ['test-synthesis', 'local-live', 'hosted', 'supply-chain'],
    });

    assert.equal(summary.testSynthesis?.attempted, 1);
    assert.ok((summary.localLive?.attempted ?? 0) > 0);
    assert.ok((summary.hosted?.attempted ?? 0) > 0);
    assert.equal(summary.supplyChain?.attempted, 1);
    // Section 8.2: monitoring stress is now a mode inside local-live.
    // When monitoringStress is enabled, runs/degraded/harmfulSeen are
    // populated on the localLive lane summary, not as a standalone lane.
    assert.ok((summary.localLive?.runs ?? 0) >= 0, 'monitoring stress runs should be tracked on localLive');
    assert.equal(summary.monitoringStress, undefined, 'standalone monitoring stress lane no longer exists');
    assert.match(summary.experimentsPath ?? '', /experiments\.jsonl$/);
  } finally {
    delete process.env.SECURITY_LAB_DECOY;
    SupplyChainConfirmationRunner.prototype.run = originalConfirmationRun;
    await server.close();
    await rm(root, { recursive: true, force: true });
  }
});

test('InvestigationRunner focused closure resolves basename references from repo files', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-focused-closure-'));

  try {
    const repoRoot = join(root, 'target');
    const campaignDir = join(root, 'campaigns');
    await mkdir(join(repoRoot, 'src', 'api', 'middleware'), {
      recursive: true,
    });
    await mkdir(join(repoRoot, 'src', 'api', 'routes'), { recursive: true });
    await mkdir(campaignDir, { recursive: true });
    await writeFile(join(repoRoot, 'src', 'api', 'middleware', 'jwt-auth.ts'), 'export const jwtAuth = true;\n', 'utf8');
    await writeFile(join(repoRoot, 'src', 'api', 'routes', 'admin-security.routes.ts'), 'export const adminSecurity = true;\n', 'utf8');

    const runner = new InvestigationRunner({
      targetRef: repoRoot,
      mode: 'declared',
      plannerAdapter: new PatternAdapter(),
      judgeAdapter: new PatternAdapter(),
      maxIterations: 1,
      maxCostUsd: 1,
      campaignDir,
    });

    const evidenceStore = new EvidenceStore('focused-closure', join(campaignDir, 'runs'));
    await evidenceStore.prepare();

    const assessment = {
      summary: 'Review jwt-auth.ts and admin-security.routes.ts before finalising.',
      validatedRisks: [],
      configurationRisks: [],
      unconfirmedLeads: [],
      nextActions: [],
    } as any;

    const result = await runner.runFocusedClosureLoop(
      {
        id: 'fixture-target',
        repoRoot,
      } as any,
      assessment,
      evidenceStore,
    );

    const repoFiles = await runner.listRepoFiles(repoRoot);
    assert.ok(repoFiles.some((file) => file.endsWith('src/api/middleware/jwt-auth.ts')));
    assert.ok(repoFiles.some((file) => file.endsWith('src/api/routes/admin-security.routes.ts')));
    assert.match(runner.resolveFocusedClosureReference('jwt-auth.ts', repoRoot, repoFiles) ?? '', /src\/api\/middleware\/jwt-auth\.ts$/);
    assert.match(runner.resolveFocusedClosureReference('admin-security.routes.ts', repoRoot, repoFiles) ?? '', /src\/api\/routes\/admin-security\.routes\.ts$/);
    assert.equal(result.coverageGaps.length, 0);
    if (result.notes) {
      assert.match(result.notes, /src\/api\/middleware\/jwt-auth\.ts/);
      assert.match(result.notes, /src\/api\/routes\/admin-security\.routes\.ts/);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
