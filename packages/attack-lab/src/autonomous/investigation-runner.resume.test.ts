/**
 * Integration test — exercises resume-at-stage paths, concurrent-resume
 * rejection, and stale-lock reclaim. Uses the campaign lock, state store,
 * evidence store, and stage vocabulary directly rather than running the
 * full InvestigationRunner (which requires model adapters).
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir, hostname } from 'node:os';
import { join, resolve } from 'node:path';
import { CampaignLock, WriterLockContentionError } from './campaign-lock.js';
import { StateStore, createInitialState } from './state.js';
import { STAGES, stageIndex, nextStageAfter, type Stage } from './contracts.js';
import { EvidenceStore } from '../../../evidence-plane/src/store.js';

test('stage vocabulary has eight stages in correct order', () => {
  assert.deepEqual([...STAGES], [
    'static',
    'verification_packet_build',
    'focused_lead_confirmation',
    'local_live',
    'test_synthesis',
    'focused_closure',
    'assessment',
    'reporting',
  ]);
});

test('nextStageAfter returns the correct next stage', () => {
  assert.equal(nextStageAfter('static'), 'verification_packet_build');
  assert.equal(nextStageAfter('assessment'), 'reporting');
  assert.equal(nextStageAfter('reporting'), null);
});

test('stageIndex returns the correct index', () => {
  assert.equal(stageIndex('static'), 0);
  assert.equal(stageIndex('reporting'), 7);
});

test('InvestigationState includes currentStage and lastCompletedStage defaulting to null', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-resume-'));
  try {
    const state = createInitialState({
      campaignId: 'test-resume',
      targetId: 'fixture',
      maxIterations: 5,
      maxCostUsd: 10,
      mode: 'declared',
      campaignDir: root,
    });

    assert.equal(state.currentStage, null);
    assert.equal(state.lastCompletedStage, null);

    const store = new StateStore(root, 'test-resume');
    await store.write(state);
    const reloaded = await store.read();
    assert.equal(reloaded.currentStage, null);
    assert.equal(reloaded.lastCompletedStage, null);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('stage boundaries persist through state writes', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-resume-'));
  try {
    const state = createInitialState({
      campaignId: 'test-stage-persist',
      targetId: 'fixture',
      maxIterations: 5,
      maxCostUsd: 10,
      mode: 'declared',
      campaignDir: root,
    });

    const store = new StateStore(root, 'test-stage-persist');
    await store.write(state);

    // Simulate walking through stages
    for (const stage of STAGES) {
      await store.update((s) => {
        s.currentStage = stage;
      });
      await store.update((s) => {
        s.lastCompletedStage = stage;
        s.currentStage = null;
      });
    }

    const final = await store.read();
    assert.equal(final.lastCompletedStage, 'reporting');
    assert.equal(final.currentStage, null);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('stage events are recorded in the evidence stream', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-resume-'));
  try {
    const evidenceStore = new EvidenceStore('test-evidence', resolve(root, 'runs'));
    await evidenceStore.prepare();

    // Emit stage events for all seven stages
    for (const stage of STAGES) {
      const startedAt = new Date().toISOString();
      await evidenceStore.appendEvent('stage_started', {
        stage,
        campaignId: 'test-evidence',
        startedAt,
      });
      await evidenceStore.appendEvent('stage_completed', {
        stage,
        campaignId: 'test-evidence',
        startedAt,
        completedAt: new Date().toISOString(),
        durationMs: 10,
      });
    }

    // Read and verify events
    const raw = await readFile(evidenceStore.paths.eventsPath, 'utf8');
    const events = raw.trim().split('\n').map((line) => JSON.parse(line));
    const stageStarted = events.filter((e: Record<string, unknown>) => e.stage === 'stage_started');
    const stageCompleted = events.filter((e: Record<string, unknown>) => e.stage === 'stage_completed');

    assert.equal(stageStarted.length, 8);
    assert.equal(stageCompleted.length, 8);

    // Verify ordering
    const startedStages = stageStarted.map((e: Record<string, unknown>) => (e.payload as Record<string, unknown>).stage);
    assert.deepEqual(startedStages, [...STAGES]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('resume-at skips prior stages based on lastCompletedStage', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-resume-'));
  try {
    const state = createInitialState({
      campaignId: 'test-skip',
      targetId: 'fixture',
      maxIterations: 5,
      maxCostUsd: 10,
      mode: 'declared',
      campaignDir: root,
    });

    // Simulate having completed 'static' and 'verification_packet_build'
    state.lastCompletedStage = 'verification_packet_build';

    const store = new StateStore(root, 'test-skip');
    await store.write(state);

    // Resuming at 'local_live' should skip static and verification_packet_build
    const resumeAtStage: Stage = 'local_live';
    const shouldSkip = (stage: Stage): boolean => {
      if (state.lastCompletedStage) {
        return stageIndex(stage) <= stageIndex(state.lastCompletedStage);
      }
      return false;
    };

    assert.ok(shouldSkip('static'));
    assert.ok(shouldSkip('verification_packet_build'));
    assert.ok(!shouldSkip('local_live'));
    assert.ok(!shouldSkip('assessment'));
    assert.ok(!shouldSkip('reporting'));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('shouldSkipStage gates stage events: only non-skipped stages emit events', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-resume-'));
  try {
    const evidenceStore = new EvidenceStore('test-skip-events', resolve(root, 'runs'));
    await evidenceStore.prepare();

    // Simulate the runner's shouldSkipStage for resuming at 'focused_closure'
    const resumeAtStage: Stage = 'focused_closure';
    const shouldSkipStage = (stage: Stage): boolean => {
      return stageIndex(stage) < stageIndex(resumeAtStage);
    };

    // Verify the skip logic matches expectations for all stages
    assert.ok(shouldSkipStage('static'), 'static should be skipped when resuming at focused_closure');
    assert.ok(shouldSkipStage('verification_packet_build'), 'verification_packet_build should be skipped');
    assert.ok(shouldSkipStage('local_live'), 'local_live should be skipped');
    assert.ok(shouldSkipStage('test_synthesis'), 'test_synthesis should be skipped');
    assert.ok(!shouldSkipStage('focused_closure'), 'focused_closure should NOT be skipped');
    assert.ok(!shouldSkipStage('assessment'), 'assessment should NOT be skipped');
    assert.ok(!shouldSkipStage('reporting'), 'reporting should NOT be skipped');

    // Simulate the runner's stage event emission pattern: only emit for non-skipped stages
    const emittedStages: Stage[] = [];
    for (const stage of STAGES) {
      if (!shouldSkipStage(stage)) {
        const startedAt = new Date().toISOString();
        await evidenceStore.appendEvent('stage_started', {
          stage,
          campaignId: 'test-skip-events',
          startedAt,
        });
        await evidenceStore.appendEvent('stage_completed', {
          stage,
          campaignId: 'test-skip-events',
          startedAt,
          completedAt: new Date().toISOString(),
          durationMs: 1,
        });
        emittedStages.push(stage);
      }
    }

    // Only stages from focused_closure onward should have events
    assert.deepEqual(emittedStages, ['focused_closure', 'assessment', 'reporting']);

    // Verify the evidence stream contains exactly the non-skipped stage events
    const raw = await readFile(evidenceStore.paths.eventsPath, 'utf8');
    const events = raw.trim().split('\n').map((line) => JSON.parse(line));
    const stageStarted = events.filter((e: Record<string, unknown>) => e.stage === 'stage_started');
    const stageCompleted = events.filter((e: Record<string, unknown>) => e.stage === 'stage_completed');

    assert.equal(stageStarted.length, 3, 'should have 3 stage_started events');
    assert.equal(stageCompleted.length, 3, 'should have 3 stage_completed events');

    const startedStageNames = stageStarted.map((e: Record<string, unknown>) => (e.payload as Record<string, unknown>).stage);
    assert.deepEqual(startedStageNames, ['focused_closure', 'assessment', 'reporting']);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('shouldSkipStage with lastCompletedStage skips completed and prior stages', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-resume-'));
  try {
    const state = createInitialState({
      campaignId: 'test-skip-completed',
      targetId: 'fixture',
      maxIterations: 5,
      maxCostUsd: 10,
      mode: 'declared',
      campaignDir: root,
    });

    // Test the runner's exact shouldSkipStage logic with lastCompletedStage set
    const resumeAtStage: Stage = 'assessment';

    // Align lastCompletedStage to the stage before resumeAtStage (as the runner does)
    const targetStageIdx = stageIndex(resumeAtStage);
    state.lastCompletedStage = targetStageIdx > 0 ? STAGES[targetStageIdx - 1]! : null;

    assert.equal(state.lastCompletedStage, 'focused_closure');

    // The runner's shouldSkipStage when lastCompletedStage is set
    const shouldSkipStage = (stage: Stage): boolean => {
      if (!resumeAtStage) return false;
      if (state.lastCompletedStage) {
        return stageIndex(stage) <= stageIndex(state.lastCompletedStage);
      }
      return false;
    };

    // Stages up to and including focused_closure should be skipped
    assert.ok(shouldSkipStage('static'));
    assert.ok(shouldSkipStage('verification_packet_build'));
    assert.ok(shouldSkipStage('local_live'));
    assert.ok(shouldSkipStage('test_synthesis'));
    assert.ok(shouldSkipStage('focused_closure'));
    assert.ok(!shouldSkipStage('assessment'), 'assessment should NOT be skipped — it is the resume target');
    assert.ok(!shouldSkipStage('reporting'), 'reporting should NOT be skipped');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('concurrent resume of the same campaign fails fast with writer_lock_contention', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-resume-'));
  try {
    const campaignDir = join(root, 'concurrent-test');
    await mkdir(campaignDir, { recursive: true });

    const lock1 = new CampaignLock({
      campaignDir,
      campaignId: 'concurrent-test',
    });
    const lock2 = new CampaignLock({
      campaignDir,
      campaignId: 'concurrent-test',
    });

    await lock1.acquire();

    const startTime = Date.now();
    await assert.rejects(
      () => lock2.acquire(),
      WriterLockContentionError,
    );
    const elapsed = Date.now() - startTime;
    // Should fail within 1 second
    assert.ok(elapsed < 1000, `Expected fast failure, took ${elapsed}ms`);

    await lock1.release();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('stale lock reclaim during resume allows the second process to proceed', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-resume-'));
  try {
    const campaignDir = join(root, 'stale-test');
    await mkdir(campaignDir, { recursive: true });

    // Write a stale lock with a dead PID
    const staleLock = {
      pid: 999999999,
      hostname: hostname(),
      acquiredAt: new Date(Date.now() - 120_000).toISOString(),
      campaignId: 'stale-test',
    };
    await writeFile(join(campaignDir, '.writer.lock'), JSON.stringify(staleLock), 'utf8');

    const events: Array<{ stage: string }> = [];
    const lock = new CampaignLock({
      campaignDir,
      campaignId: 'stale-test',
      staleLockMs: 30 * 60 * 1000,
      emitEvent: async (stage) => { events.push({ stage }); },
    });

    await lock.acquire();
    assert.ok(lock.isAcquired());
    assert.equal(events.length, 1);
    assert.equal(events[0]!.stage, 'writer_lock_reclaimed');

    await lock.release();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('old campaigns without stage fields are treated as fresh on resume', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-resume-'));
  try {
    // Write a state.json without stage fields (pre-1.1 format)
    const campaignDir = join(root, 'legacy-campaign');
    await mkdir(campaignDir, { recursive: true });
    const oldState = {
      campaignId: 'legacy-campaign',
      targetId: 'fixture',
      phase: 'completed',
      iteration: 5,
      maxIterations: 10,
      maxCostUsd: 10,
      mode: 'declared',
      startedAt: new Date().toISOString(),
      costUsd: 3.5,
      sessionIds: {},
      consecutiveDeadEnds: 0,
      memoryPath: join(campaignDir, 'memory.json'),
    };
    await writeFile(join(campaignDir, 'state.json'), JSON.stringify(oldState), 'utf8');

    const store = new StateStore(root, 'legacy-campaign');
    const state = await store.read();

    // Missing stage fields default to undefined (treated as null)
    assert.equal(state.currentStage ?? null, null);
    assert.equal(state.lastCompletedStage ?? null, null);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
