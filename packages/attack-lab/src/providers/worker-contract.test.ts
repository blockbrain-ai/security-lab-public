import test from 'node:test';
import assert from 'node:assert/strict';
import { WORKER_CONTRACT } from './worker-contract.js';

test('worker contract contains rule 1 (no recursive Security Lab invocation)', () => {
  assert.match(WORKER_CONTRACT, /must not invoke Security Lab recursively/i);
  assert.match(WORKER_CONTRACT, /npm run investigate/);
  assert.match(WORKER_CONTRACT, /npm run verify:from-campaign/);
});

test('worker contract contains rule 2 (no authorized live/hosted bypass)', () => {
  assert.match(WORKER_CONTRACT, /must not send probes to authorized live or hosted targets outside the Security Lab gate/i);
  assert.match(WORKER_CONTRACT, /must go through the Security Lab runner/i);
});

test('worker contract grants explicit freedom to read, mutate, exec, and explore', () => {
  assert.match(WORKER_CONTRACT, /free to read any file/i);
  assert.match(WORKER_CONTRACT, /mutate scratch files/i);
  assert.match(WORKER_CONTRACT, /run shell commands/i);
  assert.match(WORKER_CONTRACT, /start and stop local containers/i);
  assert.match(WORKER_CONTRACT, /explore directories/i);
});

test('worker contract contains no restriction language beyond the two rules', () => {
  const forbidden = [
    'prefer bounded',
    'do not mutate',
    'allowlist',
    'narrow set of tools',
    'do not start or stop long-running services',
    'propose probes in your response instead',
    'targeted test-file reads',
  ];
  for (const phrase of forbidden) {
    assert.ok(
      !WORKER_CONTRACT.toLowerCase().includes(phrase.toLowerCase()),
      `worker contract must not contain the re-tightening phrase: "${phrase}"`,
    );
  }
});

test('worker contract exposes exactly the two orchestrator-protection rules', () => {
  // Sanity: Rule 1 and Rule 2 are labeled; there is no "Rule 3".
  assert.match(WORKER_CONTRACT, /Rule 1 \(no recursion\)/);
  assert.match(WORKER_CONTRACT, /Rule 2 \(no live\/hosted bypass\)/);
  assert.ok(!/Rule 3/.test(WORKER_CONTRACT), 'worker contract must not introduce a third rule');
});
