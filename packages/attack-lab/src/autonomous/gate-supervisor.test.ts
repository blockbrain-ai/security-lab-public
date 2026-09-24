import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { z } from 'zod';
import {
  classifyFailure,
  classifyTranscriptFailure,
  executeGate,
  POLICY_MAP,
  type GateFailureClass,
} from './gate-supervisor.js';
import { parseWithGenericRepair } from './response-repair.js';
import type { ToolTranscriptEntry } from '../providers/contracts.js';

const TestSchema = z.object({
  candidateId: z.string(),
  claim: z.string(),
  status: z.enum(['supported', 'refuted']),
  confidence: z.number(),
});

// ---------------------------------------------------------------------------
// Classification tests — pure, no model calls
// ---------------------------------------------------------------------------

test('classifyFailure returns format_truncated for truncated JSON', () => {
  const raw = '{"candidateId":"a","claim":"test","status":"supported","confidence":0.';
  const result = parseWithGenericRepair(raw, TestSchema);
  const classification = classifyFailure(raw, result);
  assert.ok(classification);
  assert.equal(classification!.failureClass, 'format_truncated');
  assert.equal(classification!.policy, 'structural_reparse');
});

test('classifyFailure returns format_no_json for prose-only response', () => {
  const raw = 'I looked at the code and found some issues but cannot produce JSON.';
  const result = parseWithGenericRepair(raw, TestSchema);
  const classification = classifyFailure(raw, result);
  assert.ok(classification);
  assert.equal(classification!.failureClass, 'format_no_json');
  assert.equal(classification!.policy, 'synthesis_retry');
});

test('classifyFailure returns format_schema_mismatch for valid JSON rejected by Zod', () => {
  const raw = JSON.stringify({ candidateId: 'a', claim: 'test', wrong_field: true });
  const result = parseWithGenericRepair(raw, TestSchema);
  const classification = classifyFailure(raw, result);
  assert.ok(classification);
  assert.equal(classification!.failureClass, 'format_schema_mismatch');
  assert.equal(classification!.policy, 'synthesis_retry');
});

test('classifyFailure returns format_invalid_json for malformed JSON', () => {
  const raw = '{candidateId: "a", claim: "test}';
  const result = parseWithGenericRepair(raw, TestSchema);
  const classification = classifyFailure(raw, result);
  assert.ok(classification);
  assert.equal(classification!.failureClass, 'format_invalid_json');
  assert.equal(classification!.policy, 'structural_reparse');
});

test('classifyTranscriptFailure returns context_exhaustion for budget markers', () => {
  const raw = 'BUDGET_EXHAUSTED: ran out of turns';
  const transcript: ToolTranscriptEntry[] = [
    { tool: 'read_file', args: { path: 'a.py' }, output: 'content' },
  ];
  const classification = classifyTranscriptFailure(raw, transcript);
  assert.ok(classification);
  assert.equal(classification!.failureClass, 'context_exhaustion');
  assert.equal(classification!.policy, 'synthesis_retry');
});

test('classifyTranscriptFailure returns tool_loop_stall for 3+ identical tool calls', () => {
  const raw = 'some output';
  const transcript: ToolTranscriptEntry[] = [
    { tool: 'read_file', args: { path: 'a.py' }, output: 'content' },
    { tool: 'read_file', args: { path: 'a.py' }, output: 'content' },
    { tool: 'read_file', args: { path: 'a.py' }, output: 'content' },
  ];
  const classification = classifyTranscriptFailure(raw, transcript);
  assert.ok(classification);
  assert.equal(classification!.failureClass, 'tool_loop_stall');
  assert.equal(classification!.policy, 'synthesis_retry');
});

test('classifyTranscriptFailure returns null for normal transcript', () => {
  const raw = 'normal output';
  const transcript: ToolTranscriptEntry[] = [
    { tool: 'read_file', args: { path: 'a.py' }, output: 'content a' },
    { tool: 'read_file', args: { path: 'b.py' }, output: 'content b' },
  ];
  const classification = classifyTranscriptFailure(raw, transcript);
  assert.equal(classification, null);
});

test('classifyFailure returns evidence_fabricated for validation notes with fabrication rules', () => {
  const raw = JSON.stringify({ candidateId: 'a', claim: 'test', status: 'supported', confidence: 0.9 });
  const result = parseWithGenericRepair(raw, TestSchema);
  const classification = classifyFailure(raw, result, {
    validationNotes: [
      { rule: 'reproducer_output_not_in_transcript', detail: 'output not found' },
    ],
  });
  assert.ok(classification);
  assert.equal(classification!.failureClass, 'evidence_fabricated');
  assert.equal(classification!.policy, 'downgrade_only');
});

test('classifyFailure returns weak_source_grounding for empty sourceRefs on supported result', () => {
  const raw = JSON.stringify({ candidateId: 'a', claim: 'test', status: 'supported', confidence: 0.8 });
  const result = parseWithGenericRepair(raw, TestSchema);
  const classification = classifyFailure(raw, result, {
      sourceResult: {
        candidateId: 'a',
        claim: 'SSRF in proxy',
        status: 'supported',
        rootCause: 'No URL validation somewhere',
        sourceRefs: [],
        preconditions: [],
        defenseMechanismsObserved: [],
        assumptions: [],
        validationNotes: [],
        confidence: 0.8,
      },
  });
  assert.ok(classification);
  assert.equal(classification!.failureClass, 'weak_source_grounding');
  assert.equal(classification!.policy, 'targeted_followup');
});

test('classifyFailure returns null for clean well-formed output', () => {
  const raw = JSON.stringify({ candidateId: 'a', claim: 'test', status: 'supported', confidence: 0.9 });
  const result = parseWithGenericRepair(raw, TestSchema);
  const classification = classifyFailure(raw, result);
  assert.equal(classification, null);
});

test('classifyFailure returns null for supported result with good source grounding', () => {
  const raw = JSON.stringify({ candidateId: 'a', claim: 'test', status: 'supported', confidence: 0.9 });
  const result = parseWithGenericRepair(raw, TestSchema);
  const classification = classifyFailure(raw, result, {
      sourceResult: {
        candidateId: 'a',
        claim: 'SSRF',
        status: 'supported',
        rootCause: 'No URL validation in proxy.py:42',
        sourceRefs: [{ file: 'proxy.py', line: 42, snippet: 'httpx.request(url)' }],
        preconditions: [],
        defenseMechanismsObserved: [],
        assumptions: [],
        validationNotes: [],
        confidence: 0.9,
      },
  });
  assert.equal(classification, null);
});

// ---------------------------------------------------------------------------
// Policy mapping tests
// ---------------------------------------------------------------------------

test('POLICY_MAP maps each GateFailureClass to expected RepairPolicy', () => {
  const expected: Record<GateFailureClass, string> = {
    format_truncated: 'structural_reparse',
    format_invalid_json: 'structural_reparse',
    format_alias_drift: 'structural_reparse',
    format_no_json: 'synthesis_retry',
    format_schema_mismatch: 'synthesis_retry',
    context_exhaustion: 'synthesis_retry',
    tool_loop_stall: 'synthesis_retry',
    evidence_fabricated: 'downgrade_only',
    weak_source_grounding: 'targeted_followup',
  };
  for (const [cls, policy] of Object.entries(expected)) {
    assert.equal(POLICY_MAP[cls as GateFailureClass], policy, `${cls} should map to ${policy}`);
  }
});

// ---------------------------------------------------------------------------
// Structural repair tests — no model calls
// ---------------------------------------------------------------------------

test('executeGate with truncated JSON succeeds after structural repair', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'gs-'));
  const logPath = join(dir, 'session.jsonl');
  try {
    // Truncated JSON that generic repair can close and Zod can parse
    const raw = '{"candidateId":"a","claim":"test","status":"supported","confidence":0.9,"extra":[';
    const gateResult = await executeGate(TestSchema, {
      gateId: 'test:trunc',
      rawContent: raw,
      originalPrompt: 'test',
      originalSystemPrompt: 'test',
      model: 'test',
      sessionLogPath: logPath,
    });
    // Generic repair transparently succeeds — gate sees no failure
    assert.equal(gateResult.success, true);
    assert.ok(gateResult.output);
    assert.equal(gateResult.output!.candidateId, 'a');
    assert.equal(gateResult.repairCostUsd, 0);
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('executeGate with alias drift succeeds when aliasMap provided', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'gs-'));
  const logPath = join(dir, 'session.jsonl');
  try {
    const raw = JSON.stringify({ candidate_id: 'a', claim: 'test', status: 'supported', confidence: 0.9 });
    const gateResult = await executeGate(TestSchema, {
      gateId: 'test:alias',
      rawContent: raw,
      originalPrompt: 'test',
      originalSystemPrompt: 'test',
      model: 'test',
      sessionLogPath: logPath,
    }, {
      aliasMap: { candidate_id: 'candidateId' },
    });
    assert.equal(gateResult.success, true);
    assert.equal(gateResult.output?.candidateId, 'a');
  } finally {
    await rm(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// Downgrade tests
// ---------------------------------------------------------------------------

test('executeGate with fabricated evidence returns downgraded output unchanged', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'gs-'));
  const logPath = join(dir, 'session.jsonl');
  try {
    const raw = JSON.stringify({ candidateId: 'a', claim: 'test', status: 'supported', confidence: 0.9 });
    const gateResult = await executeGate(TestSchema, {
      gateId: 'test:fab',
      rawContent: raw,
      originalPrompt: 'test',
      originalSystemPrompt: 'test',
      model: 'test',
      sessionLogPath: logPath,
    }, {
      validationNotes: [
        { rule: 'reproducer_output_not_in_transcript', detail: 'fabricated output' },
      ],
    });
    assert.equal(gateResult.success, true);
    assert.equal(gateResult.classification?.failureClass, 'evidence_fabricated');
    assert.equal(gateResult.classification?.policy, 'downgrade_only');
    assert.equal(gateResult.repairAttempted, false);
    assert.ok(gateResult.output);
  } finally {
    await rm(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// Archival tests
// ---------------------------------------------------------------------------

test('executeGate appends gate_repair entry to session JSONL', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'gs-'));
  const logPath = join(dir, 'session.jsonl');
  try {
    const raw = 'no json here at all, just prose';
    await executeGate(TestSchema, {
      gateId: 'test:archive',
      rawContent: raw,
      originalPrompt: 'test',
      originalSystemPrompt: 'test',
      model: 'test',
      sessionLogPath: logPath,
    });
    const logContent = await readFile(logPath, 'utf8');
    const entry = JSON.parse(logContent.trim());
    assert.equal(entry.type, 'gate_repair');
    assert.equal(entry.gateId, 'test:archive');
    assert.equal(entry.failureClass, 'format_no_json');
    assert.equal(entry.policy, 'synthesis_retry');
    assert.ok(entry.at);
  } finally {
    await rm(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// Boundary tests
// ---------------------------------------------------------------------------

test('structural repair failure does not trigger a model call', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'gs-'));
  const logPath = join(dir, 'session.jsonl');
  try {
    // Invalid JSON that can't be structurally repaired — classified as
    // truncated (has opening brace) or invalid_json, either way repair
    // policy is structural_reparse with $0 cost.
    const raw = '{candidateId: bad json';
    const gateResult = await executeGate(TestSchema, {
      gateId: 'test:no-model',
      rawContent: raw,
      originalPrompt: 'test',
      originalSystemPrompt: 'test',
      model: 'test',
      sessionLogPath: logPath,
    });
    assert.ok(gateResult.classification);
    assert.equal(gateResult.classification!.policy, 'structural_reparse');
    assert.equal(gateResult.repairCostUsd, 0);
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('non-bounded_local provider skips model-based repair gracefully', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'gs-'));
  const logPath = join(dir, 'session.jsonl');
  try {
    const raw = 'prose response with no json';
    const gateResult = await executeGate(TestSchema, {
      gateId: 'test:non-local',
      rawContent: raw,
      originalPrompt: 'test',
      originalSystemPrompt: 'test',
      model: 'test',
      sessionLogPath: logPath,
    }, {
      provider: 'claude_code',
    });
    assert.equal(gateResult.classification?.failureClass, 'format_no_json');
    assert.equal(gateResult.repairAttempted, false);
    assert.equal(gateResult.repairCostUsd, 0);
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('executeGate returns success for clean well-formed input', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'gs-'));
  const logPath = join(dir, 'session.jsonl');
  try {
    const raw = JSON.stringify({ candidateId: 'a', claim: 'test', status: 'supported', confidence: 0.95 });
    const gateResult = await executeGate(TestSchema, {
      gateId: 'test:clean',
      rawContent: raw,
      originalPrompt: 'test',
      originalSystemPrompt: 'test',
      model: 'test',
      sessionLogPath: logPath,
    });
    assert.equal(gateResult.success, true);
    assert.equal(gateResult.output?.candidateId, 'a');
    assert.equal(gateResult.classification, undefined);
    assert.equal(gateResult.repairAttempted, false);
  } finally {
    await rm(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// Generic repair layer tests
// ---------------------------------------------------------------------------

test('parseWithGenericRepair detects schema_mismatch for valid JSON with wrong shape', () => {
  const raw = JSON.stringify({ foo: 'bar', baz: 42 });
  const result = parseWithGenericRepair(raw, TestSchema);
  assert.equal(result.success, false);
  assert.equal(result.failureKind, 'schema_mismatch');
});

test('parseWithGenericRepair succeeds with alias map', () => {
  const raw = JSON.stringify({ candidate_id: 'a', claim: 'test', status: 'supported', confidence: 0.8 });
  const result = parseWithGenericRepair(raw, TestSchema, { candidate_id: 'candidateId' });
  assert.equal(result.success, true);
  assert.equal(result.output?.candidateId, 'a');
});

test('parseWithGenericRepair strips null values before Zod validation', () => {
  const raw = JSON.stringify({
    candidateId: 'a', claim: 'test', status: 'supported', confidence: 0.9,
    extra_field: null,
  });
  const result = parseWithGenericRepair(raw, TestSchema);
  assert.equal(result.success, true);
  assert.equal(result.output?.candidateId, 'a');
});

test('parseWithGenericRepair repairs truncated JSON', () => {
  const raw = '{"candidateId":"a","claim":"test","status":"refuted","confidence":0.5,"extra":[';
  const result = parseWithGenericRepair(raw, TestSchema);
  assert.equal(result.success, true);
  assert.equal(result.failureKind, 'truncated');
  assert.equal(result.repairAttempted, true);
  assert.equal(result.repairSucceeded, true);
});
