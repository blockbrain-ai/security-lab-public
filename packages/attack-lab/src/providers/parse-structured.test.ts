import test from 'node:test';
import assert from 'node:assert/strict';
import { z } from 'zod';
import { tryParseStructured } from './parse-structured.js';

const JudgeSchema = z.object({
  verdict: z.enum(['continue', 'confirmed_finding', 'dead_end', 'merge_with_existing', 'needs_dormant_review']),
  finding: z.object({
    description: z.string(),
    severity: z.enum(['low', 'medium', 'high', 'critical']),
    reproductionSteps: z.array(z.string()),
    remediationSuggestion: z.string(),
    involvedDormantReactivation: z.boolean().default(false),
  }).optional(),
  promoteSignals: z.array(z.string()).default([]),
  dismissSignals: z.array(z.string()).default([]),
  reactivateSignals: z.array(z.object({ signalId: z.string(), reason: z.string() })).default([]),
  newCorrelations: z.array(z.object({ signalIdA: z.string(), signalIdB: z.string(), resolved: z.boolean() })).default([]),
  partialProgress: z.boolean().default(false),
  reasoning: z.string(),
});

test('strict parse: well-formed API model output parses directly', () => {
  const content = '```json\n{"verdict":"continue","promoteSignals":["ws-1"],"dismissSignals":[],"reactivateSignals":[],"newCorrelations":[],"partialProgress":true,"reasoning":"test"}\n```';
  const result = tryParseStructured(content, JudgeSchema);
  assert.ok(result);
  assert.equal(result!.verdict, 'continue');
  assert.deepEqual(result!.promoteSignals, ['ws-1']);
});

test('coercion: promoteSignals as objects with signalId are coerced to strings', () => {
  const content = '```json\n{"verdict":"continue","promoteSignals":[{"signalId":"ws-0-6","newConfidence":0.65,"reason":"confirmed"}],"dismissSignals":[],"reactivateSignals":[],"newCorrelations":[],"partialProgress":true,"reasoning":"test"}\n```';
  const result = tryParseStructured(content, JudgeSchema);
  assert.ok(result, 'should parse after coercion');
  assert.deepEqual(result!.promoteSignals, ['ws-0-6']);
});

test('coercion: newCorrelations with {signals:[a,b]} format are coerced to {signalIdA, signalIdB, resolved}', () => {
  const content = JSON.stringify({
    verdict: 'continue',
    promoteSignals: [],
    dismissSignals: [],
    reactivateSignals: [],
    newCorrelations: [{ signals: ['ws-0-2', 'ws-0-6'], reasoning: 'related auth patterns' }],
    partialProgress: true,
    reasoning: 'test',
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const result = tryParseStructured(content, JudgeSchema) as any;
  assert.ok(result, 'should parse after coercion');
  assert.equal(result.newCorrelations.length, 1);
  assert.equal(result.newCorrelations[0].signalIdA, 'ws-0-2');
  assert.equal(result.newCorrelations[0].signalIdB, 'ws-0-6');
  assert.equal(result.newCorrelations[0].resolved, false);
});

test('coercion: both promoteSignals objects and newCorrelations signals format together', () => {
  const content = '```json\n' + JSON.stringify({
    verdict: 'continue',
    promoteSignals: [{ signalId: 'ws-0-4', newConfidence: 0.7, reason: 'confirmed' }],
    dismissSignals: [],
    reactivateSignals: [],
    newCorrelations: [{ signals: ['ws-0-1', 'ws-0-4'], reasoning: 'both relate to pass-through' }],
    partialProgress: true,
    reasoning: 'pass-through surface confirmed',
  }) + '\n```';
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const result = tryParseStructured(content, JudgeSchema) as any;
  assert.ok(result, 'should parse after coercion');
  assert.deepEqual(result.promoteSignals, ['ws-0-4']);
  assert.equal(result.newCorrelations[0].signalIdA, 'ws-0-1');
});

test('no JSON in output returns undefined', () => {
  const content = 'The hypothesis needs more investigation before a verdict can be given.';
  const result = tryParseStructured(content, JudgeSchema);
  assert.equal(result, undefined);
});

test('bare JSON without fences parses correctly', () => {
  const content = 'Here is my analysis:\n{"verdict":"dead_end","promoteSignals":[],"dismissSignals":["ws-1"],"reactivateSignals":[],"newCorrelations":[],"partialProgress":false,"reasoning":"no evidence"}\nEnd.';
  const result = tryParseStructured(content, JudgeSchema);
  assert.ok(result);
  assert.equal(result!.verdict, 'dead_end');
});

test('dismissSignals as objects with signalId are coerced to strings', () => {
  const content = JSON.stringify({
    verdict: 'continue',
    promoteSignals: [],
    dismissSignals: [{ signalId: 'ws-0-3', reason: 'not exploitable' }],
    reactivateSignals: [],
    newCorrelations: [],
    partialProgress: false,
    reasoning: 'dismissed',
  });
  const result = tryParseStructured(content, JudgeSchema);
  assert.ok(result, 'should parse after coercion');
  assert.deepEqual(result!.dismissSignals, ['ws-0-3']);
});

test('coercion: explicit null values for optional fields are stripped', () => {
  const content = JSON.stringify({
    verdict: 'continue',
    finding: null,
    promoteSignals: [],
    dismissSignals: [],
    reactivateSignals: [],
    newCorrelations: [{ signals: ['ws-0-4', 'ws-0-7'], correlation: 'related patterns' }],
    partialProgress: true,
    reasoning: 'test',
  });
  const result = tryParseStructured(content, JudgeSchema);
  assert.ok(result, 'should parse after coercion — null finding stripped');
  assert.equal(result!.finding, undefined);
  assert.equal(result!.newCorrelations.length, 1);
});

test('returns undefined when no schema is provided', () => {
  const result = tryParseStructured('{"foo":"bar"}');
  assert.equal(result, undefined);
});
