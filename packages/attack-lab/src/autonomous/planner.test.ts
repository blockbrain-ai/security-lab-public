import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, dirname } from 'node:path';
import { plan } from './planner.js';
import { RoleSessionStore } from './role-session-store.js';
import { createEmptyMemory } from './contracts.js';
import type { CampaignMemory } from './contracts.js';
import type { ModelAdapter, ModelResponse, InvokeOptions } from '../providers/contracts.js';

// Stub adapter that captures the final prompt it was invoked with.
class CapturingAdapter implements ModelAdapter {
  readonly provider = 'stub';
  readonly model = 'stub-1';
  readonly supportsNativeSessionResume: boolean;
  lastInvokeOptions?: InvokeOptions<unknown>;
  lastPrompt?: string;
  lastBriefMode?: InvokeOptions<unknown>['briefMode'];

  constructor(supportsResume: boolean) {
    this.supportsNativeSessionResume = supportsResume;
  }

  async invoke<T = unknown>(options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    this.lastInvokeOptions = options as InvokeOptions<unknown>;
    this.lastPrompt = options.prompt;
    this.lastBriefMode = options.briefMode;
    return {
      content: JSON.stringify({
        newSignals: [],
        probeRequests: [],
        newChainHypotheses: [],
        markDormant: [],
        reactivations: [],
        reasoning: 'stub',
      }),
      structured: undefined,
      usage: { inputTokens: 10, outputTokens: 5, costUsd: 0.001 },
      durationMs: 1,
      provider: this.provider,
      model: this.model,
      sessionId: 'stub-session',
    } as ModelResponse<T>;
  }
}

function emptyMemory(iteration: number): CampaignMemory {
  const memory = createEmptyMemory('test');
  memory.iteration = iteration;
  return memory;
}

test('plan() on round 1 with a resume-capable adapter uses brief mode and offloads target-surface to disk', async () => {
  const campaignDir = await mkdtemp(resolve(tmpdir(), 'security-lab-planner-brief-r1-'));
  try {
    const store = new RoleSessionStore(campaignDir);
    await store.prepare();

    // Synthesise a deliberately large target surface so the regression
    // catches any accidental reintroduction of the inline path.
    const targetSurface = `# Target Surface Map: fixture\n${'route-line\n'.repeat(5000)}`;
    assert.ok(targetSurface.length > 50_000, 'target surface should be large enough to matter');

    const adapter = new CapturingAdapter(/*supportsResume*/ true);

    const invocation = await plan(
      emptyMemory(0),
      adapter,
      targetSurface,
      {
        mode: 'declared',
        iteration: 1,
        maxIterations: 5,
        maxCostUsd: 10,
        budgetRemainingUsd: 10,
      },
      {
        briefModeContext: {
          store,
          iteration: 1,
          roleLabel: 'planner',
        },
      },
    );

    // 1. The prompt sent to the adapter must be SHORT — a few hundred
    //    tokens at most. The big target surface lives on disk.
    assert.ok(
      adapter.lastPrompt != null && adapter.lastPrompt.length < 4000,
      `brief-mode prompt should be <4000 chars, got ${adapter.lastPrompt?.length}`,
    );

    // 2. The prompt must reference the brief by path (so the worker knows
    //    where to read from).
    assert.match(adapter.lastPrompt!, /Read your brief first:/);
    assert.match(adapter.lastPrompt!, /\.brief\.md/);

    // 3. Round-1 wording ("round 1; there is no prior session") must
    //    appear — not the round-N wording that says "iteration N > 0".
    assert.match(adapter.lastPrompt!, /round 1/i);
    assert.doesNotMatch(adapter.lastPrompt!, /iteration N > 0/);

    // 4. briefMode.briefPath should have been set on the invoke options.
    assert.ok(adapter.lastBriefMode);
    assert.ok(adapter.lastBriefMode!.briefPath.endsWith('iteration-1.brief.md'));

    // 5. target-surface.md must exist on disk inside the brief manifest
    //    directory AND contain the full target surface.
    const briefsDir = dirname(adapter.lastBriefMode!.briefPath);
    const targetSurfaceFile = resolve(briefsDir, 'iteration-1__target-surface.md');
    const contents = await readFile(targetSurfaceFile, 'utf8');
    assert.equal(contents, targetSurface);

    // 6. The returned invocation wrapper carries the parsed output.
    assert.ok(invocation.response);
    assert.equal(invocation.parseSuccess, true);
  } finally {
    await rm(campaignDir, { recursive: true, force: true });
  }
});

test('plan() on round 1 with an api-only adapter falls back to inline round-1 template', async () => {
  // Api-only adapters (no native session resume) still use the legacy
  // inline path. This test is the regression guard for that fallback —
  // the fix must not break Anthropic/OpenAI/Gemini planners.
  const campaignDir = await mkdtemp(resolve(tmpdir(), 'security-lab-planner-inline-r1-'));
  try {
    const store = new RoleSessionStore(campaignDir);
    await store.prepare();

    const targetSurface = 'TINY SURFACE MAP\nroute /a\nroute /b';
    const adapter = new CapturingAdapter(/*supportsResume*/ false);

    await plan(
      emptyMemory(0),
      adapter,
      targetSurface,
      {
        mode: 'declared',
        iteration: 1,
        maxIterations: 5,
        maxCostUsd: 10,
        budgetRemainingUsd: 10,
      },
      {
        // Even with briefModeContext supplied, the adapter's lack of
        // resume support forces the inline fallback.
        briefModeContext: {
          store,
          iteration: 1,
          roleLabel: 'planner',
        },
      },
    );

    // Inline template must have been used: the prompt contains the raw
    // target surface string.
    assert.ok(adapter.lastPrompt);
    assert.ok(
      adapter.lastPrompt!.includes('TINY SURFACE MAP'),
      'inline fallback should embed target surface directly in the prompt',
    );
    // And briefMode should NOT have been set on the invoke options.
    assert.equal(adapter.lastBriefMode, undefined);
  } finally {
    await rm(campaignDir, { recursive: true, force: true });
  }
});

test('plan() on round N preserves brief mode for resume-capable adapters (regression)', async () => {
  // Round-N brief mode is the original working path; this guards against
  // the round-1 refactor accidentally breaking it.
  const campaignDir = await mkdtemp(resolve(tmpdir(), 'security-lab-planner-brief-rn-'));
  try {
    const store = new RoleSessionStore(campaignDir);
    await store.prepare();

    const adapter = new CapturingAdapter(/*supportsResume*/ true);

    await plan(
      { ...emptyMemory(3) },
      adapter,
      'target surface (round N ignores this — reads campaign memory from brief instead)',
      {
        mode: 'declared',
        lastResults: 'Previous round produced 2 refuted hypotheses.',
        iteration: 4,
        maxIterations: 5,
        maxCostUsd: 10,
        budgetRemainingUsd: 6,
      },
      {
        retrievedContext: 'MEMORY: signals=5 hypotheses=2',
        briefModeContext: {
          store,
          iteration: 4,
          roleLabel: 'counter_planner',
        },
      },
    );

    assert.ok(adapter.lastBriefMode);
    assert.ok(adapter.lastBriefMode!.briefPath.endsWith('iteration-4.brief.md'));
    assert.match(adapter.lastPrompt!, /Read your brief first:/);
    // Round-N continuity wording (not round-1).
    assert.match(adapter.lastPrompt!, /iteration N > 0/);

    // Round-N evidence files are campaign-memory, attack-graph, etc. —
    // NOT target-surface.md.
    const briefsDir = dirname(adapter.lastBriefMode!.briefPath);
    const memoryFile = resolve(briefsDir, 'iteration-4__campaign-memory.md');
    const memoryContents = await readFile(memoryFile, 'utf8');
    assert.match(memoryContents, /MEMORY: signals=5 hypotheses=2/);
  } finally {
    await rm(campaignDir, { recursive: true, force: true });
  }
});
