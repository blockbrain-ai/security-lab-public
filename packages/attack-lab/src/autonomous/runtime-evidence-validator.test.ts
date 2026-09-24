import test from 'node:test';
import assert from 'node:assert/strict';
import { validateRuntimeResult, extractNamedControls } from './runtime-evidence-validator.js';
import type { RuntimeVerificationResult } from './runtime-verify-schemas.js';
import type { ToolTranscriptEntry } from '../providers/contracts.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeResult(overrides: Partial<RuntimeVerificationResult> = {}): RuntimeVerificationResult {
  return {
    candidateId: 'test-1',
    claim: 'SSRF via pass-through endpoint',
    status: 'confirmed',
    rootCause: 'No URL validation in pass_through_request()',
    reproducerCommands: ['curl -X POST http://localhost:4000/pass_through'],
    reproducerOutput: '{"error":"connection refused to 169.254.169.254"}',
    httpEvidence: [
      { url: 'http://localhost:4000/pass_through', method: 'POST', statusCode: 500, snippet: 'connection refused to 169.254.169.254' },
    ],
    severity: 'high',
    pvrReady: true,
    confidence: 0.9,
    ...overrides,
  };
}

function makeTranscript(entries: Partial<ToolTranscriptEntry>[]): ToolTranscriptEntry[] {
  return entries.map((e) => ({
    tool: e.tool ?? 'http_request',
    args: e.args ?? {},
    output: e.output ?? '',
    ...e,
  }));
}

// ---------------------------------------------------------------------------
// Skip non-confirmed results
// ---------------------------------------------------------------------------

test('validateRuntimeResult passes through non-confirmed results without validation', () => {
  const result = makeResult({ status: 'blocked', pvrReady: false });
  const validated = validateRuntimeResult(result, []);
  assert.equal(validated.wasDowngraded, false);
  assert.equal(validated.validatedResult.status, 'blocked');
  assert.equal(validated.validationNotes.length, 0);
});

test('validateRuntimeResult passes through not_reproducible without validation', () => {
  const result = makeResult({ status: 'not_reproducible', pvrReady: false });
  const validated = validateRuntimeResult(result, []);
  assert.equal(validated.wasDowngraded, false);
});

// ---------------------------------------------------------------------------
// Rule 1: confirmed requires runtime tool call
// ---------------------------------------------------------------------------

test('validateRuntimeResult downgrades confirmed with no runtime tool calls', () => {
  const result = makeResult({ status: 'confirmed', pvrReady: true });
  const transcript = makeTranscript([
    { tool: 'read_file', output: 'some source code' },
    { tool: 'grep', output: 'match found' },
  ]);
  const validated = validateRuntimeResult(result, transcript);
  assert.equal(validated.wasDowngraded, true);
  assert.equal(validated.validatedResult.status, 'partially_confirmed');
  assert.equal(validated.validatedResult.pvrReady, false);
  assert.ok(validated.validationNotes.some((n) => n.rule === 'runtime_tool_required'));
  assert.equal(validated.modelResult.status, 'confirmed');
  assert.equal(validated.modelResult.pvrReady, true);
});

test('validateRuntimeResult does not flag runtime_tool_required when http_request present', () => {
  const result = makeResult();
  const transcript = makeTranscript([
    { tool: 'http_request', output: 'HTTP 200 OK\nBody:\n{"error":"connection refused to 169.254.169.254"}' },
  ]);
  const validated = validateRuntimeResult(result, transcript);
  assert.ok(!validated.validationNotes.some((n) => n.rule === 'runtime_tool_required'));
});

test('validateRuntimeResult does not flag runtime_tool_required when shell_exec present', () => {
  const result = makeResult();
  const transcript = makeTranscript([
    { tool: 'shell_exec', output: 'Exit code: 0\nSTDOUT:\n{"error":"connection refused to 169.254.169.254"}' },
  ]);
  const validated = validateRuntimeResult(result, transcript);
  assert.ok(!validated.validationNotes.some((n) => n.rule === 'runtime_tool_required'));
});

// ---------------------------------------------------------------------------
// Rule 2: reproducerOutput must appear in transcript
// ---------------------------------------------------------------------------

test('validateRuntimeResult downgrades when reproducerOutput not in any transcript', () => {
  const result = makeResult({
    reproducerOutput: 'HTTP/1.1 200 OK\n{"message":"Fixture Proxy Server"}',
  });
  const transcript = makeTranscript([
    { tool: 'http_request', output: 'HTTP 200 OK\nHeaders: {"content-type":"text/html"}\nBody:\n<html>Swagger UI</html>' },
  ]);
  const validated = validateRuntimeResult(result, transcript);
  assert.equal(validated.wasDowngraded, true);
  assert.ok(validated.validationNotes.some((n) => n.rule === 'reproducer_output_not_in_transcript'));
});

test('validateRuntimeResult passes when reproducerOutput matches transcript output', () => {
  const result = makeResult({
    reproducerOutput: 'connection refused to 169.254.169.254',
  });
  const transcript = makeTranscript([
    { tool: 'http_request', output: 'HTTP 500 Error\nBody:\n{"error": "connection refused to 169.254.169.254"}' },
  ]);
  const validated = validateRuntimeResult(result, transcript);
  assert.ok(!validated.validationNotes.some((n) => n.rule === 'reproducer_output_not_in_transcript'));
});

test('validateRuntimeResult checks httpEvidence snippets against transcript', () => {
  const result = makeResult({
    httpEvidence: [
      { url: 'http://localhost:4000/', method: 'GET', statusCode: 200, snippet: 'totally made up response' },
    ],
    reproducerOutput: '',
  });
  const transcript = makeTranscript([
    { tool: 'http_request', output: 'HTTP 200 OK\nBody:\n<html>Real HTML</html>' },
  ]);
  const validated = validateRuntimeResult(result, transcript);
  assert.ok(validated.validationNotes.some((n) => n.rule === 'http_evidence_snippet_not_in_transcript'));
});

test('validateRuntimeResult passes when httpEvidence snippet found in transcript', () => {
  const result = makeResult({
    httpEvidence: [
      { url: 'http://localhost:4000/', method: 'GET', statusCode: 200, snippet: 'Real HTML' },
    ],
  });
  const transcript = makeTranscript([
    { tool: 'http_request', output: 'HTTP 200 OK\nBody:\n<html>Real HTML</html>' },
  ]);
  const validated = validateRuntimeResult(result, transcript);
  assert.ok(!validated.validationNotes.some((n) => n.rule === 'http_evidence_snippet_not_in_transcript'));
});

test('validateRuntimeResult ignores short httpEvidence snippets', () => {
  const result = makeResult({
    httpEvidence: [
      { url: 'http://localhost:4000/', method: 'GET', statusCode: 200, snippet: 'OK' },
    ],
  });
  const transcript = makeTranscript([
    { tool: 'http_request', output: 'HTTP 200 OK' },
  ]);
  const validated = validateRuntimeResult(result, transcript);
  assert.ok(!validated.validationNotes.some((n) => n.rule === 'http_evidence_snippet_not_in_transcript'));
});

// ---------------------------------------------------------------------------
// Rule 3: named controls must appear in evidence
// ---------------------------------------------------------------------------

test('validateRuntimeResult downgrades when claim names a control not in transcript', () => {
  const result = makeResult({
    claim: 'SSRF via x-fixture-target header',
    rootCause: 'The x-fixture-target header is forwarded without validation',
  });
  const transcript = makeTranscript([
    { tool: 'http_request', output: 'HTTP 200 OK\nBody:\nSwagger UI' },
    { tool: 'read_file', output: 'def pass_through_request(request):' },
  ]);
  const validated = validateRuntimeResult(result, transcript);
  assert.equal(validated.wasDowngraded, true);
  assert.ok(validated.validationNotes.some((n) => n.rule === 'named_control_not_in_evidence'));
  assert.ok(validated.validationNotes.some((n) => n.detail.includes('x-fixture-target')));
});

test('validateRuntimeResult passes when named control appears in transcript', () => {
  const result = makeResult({
    claim: 'SSRF via pass_through_request function',
    rootCause: 'pass_through_request forwards target URL without IP validation',
  });
  const transcript = makeTranscript([
    { tool: 'http_request', output: 'HTTP 500 Error\nBody:\nconnection refused to 169.254.169.254' },
    { tool: 'read_file', output: 'async def pass_through_request(request, target):' },
  ]);
  const validated = validateRuntimeResult(result, transcript);
  assert.ok(!validated.validationNotes.some((n) => n.rule === 'named_control_not_in_evidence'));
});

// ---------------------------------------------------------------------------
// Composite: multiple failures combine
// ---------------------------------------------------------------------------

test('validateRuntimeResult accumulates multiple validation failures', () => {
  const result = makeResult({
    status: 'confirmed',
    pvrReady: true,
    claim: 'SSRF via x-custom-target header',
    reproducerOutput: 'Completely fabricated response body',
    httpEvidence: [
      { url: 'http://localhost:4000/', method: 'POST', statusCode: 500, snippet: 'Also fabricated' },
    ],
  });
  const transcript = makeTranscript([
    { tool: 'read_file', output: 'some source code' },
  ]);
  const validated = validateRuntimeResult(result, transcript);
  assert.equal(validated.wasDowngraded, true);
  assert.equal(validated.validatedResult.status, 'partially_confirmed');
  assert.equal(validated.validatedResult.pvrReady, false);
  assert.ok(validated.validationNotes.length >= 3);
  const rules = validated.validationNotes.map((n) => n.rule);
  assert.ok(rules.includes('runtime_tool_required'));
  assert.ok(rules.includes('reproducer_output_not_in_transcript'));
  assert.ok(rules.includes('named_control_not_in_evidence'));
});

// ---------------------------------------------------------------------------
// Preserves model result
// ---------------------------------------------------------------------------

test('validateRuntimeResult preserves original model result when downgrading', () => {
  const result = makeResult({ status: 'confirmed', pvrReady: true, confidence: 0.95 });
  const transcript = makeTranscript([{ tool: 'read_file', output: 'source' }]);
  const validated = validateRuntimeResult(result, transcript);
  assert.equal(validated.modelResult.status, 'confirmed');
  assert.equal(validated.modelResult.pvrReady, true);
  assert.equal(validated.modelResult.confidence, 0.95);
  assert.equal(validated.validatedResult.status, 'partially_confirmed');
  assert.equal(validated.validatedResult.pvrReady, false);
});

// ---------------------------------------------------------------------------
// pvrReady triggers validation even if status is not confirmed
// ---------------------------------------------------------------------------

test('validateRuntimeResult validates pvrReady even with partially_confirmed status', () => {
  const result = makeResult({ status: 'partially_confirmed', pvrReady: true });
  const transcript = makeTranscript([{ tool: 'read_file', output: 'source' }]);
  const validated = validateRuntimeResult(result, transcript);
  assert.equal(validated.wasDowngraded, true);
  assert.equal(validated.validatedResult.pvrReady, false);
});

// ---------------------------------------------------------------------------
// Confirmed with full evidence passes
// ---------------------------------------------------------------------------

test('validateRuntimeResult passes confirmed with matching runtime evidence', () => {
  const result = makeResult({
    status: 'confirmed',
    pvrReady: true,
    claim: 'SSRF in pass_through_request allows reaching internal services',
    rootCause: 'pass_through_request forwards to target without IP filtering',
    reproducerOutput: 'connection refused to 169.254.169.254',
    httpEvidence: [
      { url: 'http://localhost:4000/pass_through', method: 'POST', statusCode: 500, snippet: 'connection refused to 169.254.169.254' },
    ],
  });
  const transcript = makeTranscript([
    { tool: 'read_file', output: 'async def pass_through_request(request, target):\n    response = await client.request(target)' },
    { tool: 'http_request', args: { url: 'http://localhost:4000/pass_through' }, output: 'HTTP 500 Error\nBody:\n{"error": "connection refused to 169.254.169.254"}' },
  ]);
  const validated = validateRuntimeResult(result, transcript);
  assert.equal(validated.wasDowngraded, false);
  assert.equal(validated.validatedResult.status, 'confirmed');
  assert.equal(validated.validatedResult.pvrReady, true);
  assert.equal(validated.validationNotes.length, 0);
});

// ---------------------------------------------------------------------------
// extractNamedControls
// ---------------------------------------------------------------------------

test('extractNamedControls extracts X- headers', () => {
  const controls = extractNamedControls('The x-fixture-target header allows SSRF');
  assert.ok(controls.includes('x-fixture-target'));
});

test('extractNamedControls extracts URL paths', () => {
  const controls = extractNamedControls('The /api/pass-through endpoint is vulnerable');
  assert.ok(controls.includes('/api/pass-through'));
});

test('extractNamedControls extracts config keys', () => {
  const controls = extractNamedControls('base_target_url is user-controlled');
  assert.ok(controls.includes('base_target_url'));
});

test('extractNamedControls ignores common headers', () => {
  const controls = extractNamedControls('Set content-type and authorization headers');
  assert.ok(!controls.includes('content-type'));
  assert.ok(!controls.includes('authorization'));
});

// ---------------------------------------------------------------------------
// Whitespace normalization in matching
// ---------------------------------------------------------------------------

test('validateRuntimeResult matches reproducerOutput with whitespace differences', () => {
  const result = makeResult({
    reproducerOutput: 'connection   refused to  169.254.169.254',
  });
  const transcript = makeTranscript([
    { tool: 'http_request', output: 'HTTP 500\nBody:\nconnection refused to 169.254.169.254' },
  ]);
  const validated = validateRuntimeResult(result, transcript);
  assert.ok(!validated.validationNotes.some((n) => n.rule === 'reproducer_output_not_in_transcript'));
});

// ---------------------------------------------------------------------------
// Validation note in filingNotes
// ---------------------------------------------------------------------------

test('validateRuntimeResult appends override notes to filingNotes', () => {
  const result = makeResult({
    filingNotes: 'Original filing notes from model',
  });
  const transcript = makeTranscript([{ tool: 'read_file', output: 'source' }]);
  const validated = validateRuntimeResult(result, transcript);
  assert.ok(validated.validatedResult.filingNotes!.includes('Original filing notes from model'));
  assert.ok(validated.validatedResult.filingNotes!.includes('VALIDATION OVERRIDE'));
  assert.ok(validated.validatedResult.filingNotes!.includes('runtime_tool_required'));
});
