/**
 * Result interpreter — converts raw test execution output into a
 * verification verdict.
 */

import type { TestExecutionResult, InterpretedResult, SynthesisRequest } from './contracts.js';

const VULNERABLE_MARKERS = [
  'VULNERABLE',
  'EXPLOIT_CONFIRMED',
  'DANGEROUS_BEHAVIOUR_OBSERVED',
  'SECURITY_LAB_VULNERABLE',
];

const SAFE_MARKERS = [
  'SAFE',
  'INPUT_REJECTED',
  'BEHAVIOUR_BLOCKED',
  'SECURITY_LAB_SAFE',
];

const NOT_FOUND_MARKERS = [
  'FUNCTION_NOT_FOUND',
  'SYMBOL_NOT_FOUND',
  'FILE_NOT_FOUND',
];

export function interpretResult(
  result: TestExecutionResult,
  request: SynthesisRequest,
): InterpretedResult {
  // Compile error
  if (!result.compiled) {
    return {
      verdict: 'compile_error',
      reasoning: `Generated test failed to compile. Error: ${(result.compileErrors ?? '').slice(0, 500)}`,
      confidence: 0.9,
      dangerousBehaviourObserved: false,
      hostileInputRejected: false,
    };
  }

  // Timeout
  if (result.timedOut) {
    if (result.stalled) {
      return {
        verdict: 'timeout',
        reasoning: `Test made no observable progress before the ${result.timeoutMs}ms timeout. This suggests a stuck harness, hung import graph, or blocked startup path rather than a clean refutation.`,
        confidence: 0.75,
        dangerousBehaviourObserved: false,
        hostileInputRejected: false,
      };
    }
    return {
      verdict: 'timeout',
      reasoning: `Test exceeded the ${result.timeoutMs}ms timeout. May indicate infinite loop, blocking I/O, or an overloaded test harness.`,
      confidence: 0.8,
      dangerousBehaviourObserved: false,
      hostileInputRejected: false,
    };
  }

  // Filesystem or network violation — the test tried to escape the sandbox
  if (result.fsViolation || result.networkBlocked) {
    const what = result.networkBlocked ? 'network access' : 'filesystem write';
    return {
      verdict: 'inconclusive',
      reasoning: `Test attempted ${what} which the sandbox blocked. The test cannot reach a verdict.`,
      confidence: 0.5,
      dangerousBehaviourObserved: false,
      hostileInputRejected: false,
    };
  }

  // Function not found
  const combined = `${result.stdout} ${result.stderr}`.toUpperCase();
  if (NOT_FOUND_MARKERS.some((m) => combined.includes(m))) {
    return {
      verdict: 'inconclusive',
      reasoning: 'The synthesized test could not locate the suspect function or file.',
      confidence: 0.7,
      dangerousBehaviourObserved: false,
      hostileInputRejected: false,
    };
  }

  // Vulnerable marker present
  const sawVulnerable = VULNERABLE_MARKERS.some((m) => combined.includes(m));
  const sawSafe = SAFE_MARKERS.some((m) => combined.includes(m));

  if (sawVulnerable && !sawSafe) {
    return {
      verdict: 'confirmed',
      reasoning: `Test confirmed dangerous behaviour. Hostile input "${request.hostileInputPattern}" triggered "${request.dangerousBehaviour}".`,
      confidence: 0.85,
      dangerousBehaviourObserved: true,
      hostileInputRejected: false,
    };
  }

  if (sawSafe && !sawVulnerable) {
    return {
      verdict: 'refuted',
      reasoning: `Test confirmed the input was rejected or behaviour was blocked. Hostile input "${request.hostileInputPattern}" did not trigger the dangerous behaviour.`,
      confidence: 0.85,
      dangerousBehaviourObserved: false,
      hostileInputRejected: true,
    };
  }

  if (sawVulnerable && sawSafe) {
    return {
      verdict: 'inconclusive',
      reasoning: 'Test produced both VULNERABLE and SAFE markers. Test design is ambiguous.',
      confidence: 0.4,
      dangerousBehaviourObserved: true,
      hostileInputRejected: true,
    };
  }

  // Test ran cleanly with no explicit markers — fall back to exit code
  if (result.exitCode === 0) {
    return {
      verdict: 'refuted',
      reasoning: 'Test passed (exit 0) without explicit vulnerability markers. Treating as refuted.',
      confidence: 0.5,
      dangerousBehaviourObserved: false,
      hostileInputRejected: true,
    };
  }

  if (result.exitCode !== null && result.exitCode > 0) {
    return {
      verdict: 'inconclusive',
      reasoning: `Test failed (exit ${result.exitCode}) without clear markers. Cannot determine vulnerability status.`,
      confidence: 0.4,
      dangerousBehaviourObserved: false,
      hostileInputRejected: false,
    };
  }

  return {
    verdict: 'runtime_error',
    reasoning: 'Test could not be interpreted. No exit code, no markers, no clear failure mode.',
    confidence: 0.3,
    dangerousBehaviourObserved: false,
    hostileInputRejected: false,
  };
}
