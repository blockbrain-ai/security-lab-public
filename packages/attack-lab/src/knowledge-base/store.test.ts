import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  addDependencyDecision,
  addFinding,
  addFingerprint,
  addRefutedChain,
  addRegressionPack,
  createEmptyKnowledgeBase,
  loadKnowledgeBase,
  saveKnowledgeBase,
  summarizeKnowledgeBase,
} from './index.js';

test('knowledge base persists reusable findings, refutations, and dependency decisions', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-kb-'));

  try {
    const kb = createEmptyKnowledgeBase('fixture-workspace');
    addFingerprint(kb, {
      hash: 'abc123',
      computedAt: new Date().toISOString(),
      routeCount: 200,
      sourceFileCount: 1200,
      family: 'fixture-workspace',
    });
    addFinding(kb, {
      id: 'finding-1',
      campaignId: 'inv-1',
      confirmedAt: new Date().toISOString(),
      targetFingerprint: 'abc123',
      targetFamily: 'fixture-workspace',
      severity: 'high',
      description: 'Confirmed auth gap on approvals route.',
      reproductionSteps: ['Read route', 'Replay live request'],
      remediationSuggestion: 'Add middleware.',
      signalIds: ['ws-1', 'ws-2'],
      chainLength: 2,
      involvedDormantReactivation: true,
    });
    addRefutedChain(kb, {
      id: 'refuted-1',
      campaignId: 'inv-1',
      refutedAt: new Date().toISOString(),
      targetFingerprint: 'abc123',
      targetFamily: 'fixture-workspace',
      description: 'Public-proof route leaks internal config.',
      signalIds: ['ws-9'],
      refutationEvidence: 'Live route returned only redacted fields.',
      attemptCount: 2,
    });
    addRegressionPack(kb, {
      id: 'pack-1',
      campaignId: 'inv-1',
      createdAt: new Date().toISOString(),
      targetFingerprint: 'abc123',
      severity: 'high',
      description: 'Replay auth-gap route pack',
      filePath: '/tmp/replay.yaml',
    });
    addDependencyDecision(kb, {
      packageName: 'left-pad',
      version: '1.3.0',
      decision: 'rejected',
      decidedAt: new Date().toISOString(),
      targetFingerprint: 'abc123',
      reason: 'Unexpected postinstall script',
    });

    const path = join(root, 'knowledge.json');
    await saveKnowledgeBase(kb, path);
    const loaded = await loadKnowledgeBase(path);

    assert.ok(loaded);
    const summary = summarizeKnowledgeBase(loaded!, 'abc123');
    assert.match(summary, /Prior Confirmed Findings/);
    assert.match(summary, /Previously Refuted Chains/);
    assert.match(summary, /Confirmed auth gap on approvals route/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
