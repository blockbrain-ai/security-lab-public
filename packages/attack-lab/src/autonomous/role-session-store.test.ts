import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RoleSessionStore } from './role-session-store.js';

test('RoleSessionStore persists planner, judge, synthesizer, and reporter transcripts', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-sessions-'));

  try {
    const store = new RoleSessionStore(root);
    await store.prepare();

    const entry = {
      at: new Date().toISOString(),
      role: 'planner',
      iteration: 1,
      promptHash: 'p1',
      responseHash: 'r1',
      provider: 'anthropic',
      model: 'claude-sonnet-4-6',
      summary: 'Planner reopened a dormant auth clue.',
      evidenceRefs: ['ws-1', 'ws-2'],
      inputTokens: 10,
      outputTokens: 20,
      costUsd: 0.01,
    };

    await store.appendPlannerEntry(entry);
    await store.appendJudgeEntry('ph-1', { ...entry, role: 'judge', provider: 'openai', model: 'gpt-5.4' });
    await store.appendSynthesizerEntry('finding-1', { ...entry, role: 'synthesizer', provider: 'anthropic', model: 'claude-opus-4-6' });
    await store.appendReporterEntry({ ...entry, role: 'reporter', provider: 'anthropic', model: 'claude-opus-4-6' });

    const plannerHistory = await store.getPlannerHistory();
    const judgeHistory = await store.getJudgeHistory('ph-1');
    const synthesizerHistory = await store.getSynthesizerHistory();
    const reporterHistory = await store.getReporterHistory();

    assert.equal(plannerHistory.length, 1);
    assert.equal(judgeHistory.length, 1);
    assert.equal(synthesizerHistory.length, 1);
    assert.equal(reporterHistory.length, 1);
    assert.equal(judgeHistory[0]?.provider, 'openai');
    assert.equal(synthesizerHistory[0]?.role, 'synthesizer');
    assert.equal(reporterHistory[0]?.role, 'reporter');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
