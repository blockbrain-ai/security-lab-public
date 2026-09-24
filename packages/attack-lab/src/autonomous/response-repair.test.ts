import test from 'node:test';
import assert from 'node:assert/strict';
import { z } from 'zod';
import { detectFailureKind, parseWithRepair, repairStructuredOutput } from './response-repair.js';

const PlannerSchema = z.object({
  newSignals: z.array(z.object({
    description: z.string(),
    surface: z.string(),
    confidence: z.number(),
    relatedAssets: z.array(z.string()),
    potentialCapabilities: z.array(z.string()),
    suggestedFollowUps: z.array(z.string()),
  })),
  probeRequests: z.array(z.unknown()),
  newChainHypotheses: z.array(z.unknown()),
  markDormant: z.array(z.string()),
  reactivations: z.array(z.unknown()),
  reasoning: z.string(),
});

test('parseWithRepair repairs alias drift into the planner schema', () => {
  const raw = JSON.stringify({
    weak_signals: [
      {
        description: 'Auth clue',
        surface: 'code',
        confidence: 0.6,
        source_location: 'src/app.ts',
        tags: ['auth'],
      },
    ],
    probes: [],
    new_hypotheses: [],
    mark_dormant: [],
  });

  const parsed = parseWithRepair(raw, PlannerSchema);
  assert.equal(parsed.success, true);
  assert.equal(parsed.failureKind, 'alias_drift');
  assert.equal(parsed.repairAttempted, true);
  assert.equal(parsed.repairSucceeded, true);
  assert.equal(parsed.output?.newSignals[0]?.relatedAssets[0], 'src/app.ts');
  assert.equal(parsed.output?.newSignals[0]?.potentialCapabilities[0], 'auth');
});

test('repairStructuredOutput closes truncated JSON without inventing fields', () => {
  const raw = '{"newSignals":[{"description":"x","surface":"code","confidence":0.4,"relatedAssets":[],"potentialCapabilities":[],"suggestedFollowUps":[]}],"probeRequests":[';

  assert.equal(detectFailureKind(raw), 'truncated');
  const repaired = repairStructuredOutput(raw);
  assert.ok(repaired);

  const parsed = parseWithRepair(raw, PlannerSchema);
  assert.equal(parsed.success, true);
  assert.equal(parsed.failureKind, 'truncated');
  assert.equal(parsed.output?.probeRequests.length, 0);
});
