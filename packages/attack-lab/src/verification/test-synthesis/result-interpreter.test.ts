import test from 'node:test';
import assert from 'node:assert/strict';
import { interpretResult } from './result-interpreter.js';
import type { SynthesisRequest, TestExecutionResult } from './contracts.js';

const baseRequest: SynthesisRequest = {
  findingId: 'finding-1',
  hypothesis: 'hostile input reaches dangerous sink',
  suspectFile: 'src/suspect.ts',
  suspectSymbol: 'dangerousFn',
  hostileInputPattern: 'DROP TABLE users',
  dangerousBehaviour: 'unsanitized SQL execution',
  testFramework: 'node-test',
};

const baseResult: TestExecutionResult = {
  testId: 'test-1',
  compiled: true,
  ran: true,
  exitCode: 1,
  stdout: '',
  stderr: '',
  durationMs: 10,
  timedOut: false,
  timeoutMs: 120000,
  stalled: false,
  networkBlocked: false,
  fsViolation: false,
};

test('interpretResult handles compile errors and timeouts', () => {
  const compileError = interpretResult(
    { ...baseResult, compiled: false, compileErrors: 'TS2304: name not found' },
    baseRequest,
  );
  assert.equal(compileError.verdict, 'compile_error');

  const timeout = interpretResult(
    { ...baseResult, timedOut: true, exitCode: null },
    baseRequest,
  );
  assert.equal(timeout.verdict, 'timeout');
});

test('interpretResult treats sandbox escapes and missing symbols as inconclusive', () => {
  const networkBlocked = interpretResult(
    { ...baseResult, networkBlocked: true, stderr: 'ECONNREFUSED' },
    baseRequest,
  );
  assert.equal(networkBlocked.verdict, 'inconclusive');
  assert.match(networkBlocked.reasoning, /network access/i);

  const missingSymbol = interpretResult(
    { ...baseResult, stdout: 'FUNCTION_NOT_FOUND' },
    baseRequest,
  );
  assert.equal(missingSymbol.verdict, 'inconclusive');
  assert.match(missingSymbol.reasoning, /could not locate/i);
});

test('interpretResult distinguishes confirmed, refuted, and ambiguous markers', () => {
  const confirmed = interpretResult(
    { ...baseResult, stdout: 'SECURITY_LAB_VULNERABLE' },
    baseRequest,
  );
  assert.equal(confirmed.verdict, 'confirmed');
  assert.equal(confirmed.dangerousBehaviourObserved, true);

  const refuted = interpretResult(
    { ...baseResult, stdout: 'SECURITY_LAB_SAFE', exitCode: 0 },
    baseRequest,
  );
  assert.equal(refuted.verdict, 'refuted');
  assert.equal(refuted.hostileInputRejected, true);

  const ambiguous = interpretResult(
    { ...baseResult, stdout: 'SAFE and SECURITY_LAB_VULNERABLE' },
    baseRequest,
  );
  assert.equal(ambiguous.verdict, 'inconclusive');
  assert.equal(ambiguous.dangerousBehaviourObserved, true);
  assert.equal(ambiguous.hostileInputRejected, true);
});

test('interpretResult falls back to exit-code heuristics and runtime error', () => {
  const cleanExit = interpretResult(
    { ...baseResult, exitCode: 0 },
    baseRequest,
  );
  assert.equal(cleanExit.verdict, 'refuted');

  const failedExit = interpretResult(
    { ...baseResult, exitCode: 2 },
    baseRequest,
  );
  assert.equal(failedExit.verdict, 'inconclusive');

  const runtimeError = interpretResult(
    { ...baseResult, exitCode: null, ran: false },
    baseRequest,
  );
  assert.equal(runtimeError.verdict, 'runtime_error');
});
