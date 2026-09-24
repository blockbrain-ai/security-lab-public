import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SecurityRuntime } from './runtime.js';

test('SecurityRuntime enforces staging restrictions', () => {
  const runtime = new SecurityRuntime({ repoRoot: process.cwd() });

  const blockedShell = runtime.authorizeProbe(
    'declared',
    { id: 'staging-http', kind: 'http', environment: 'staging' },
    { kind: 'shell_command', timeoutMs: 1000, command: ['echo', 'hello'] },
  );
  assert.equal(blockedShell.allowed, false);

  const blockedCode = runtime.authorizeProbe(
    'declared',
    { id: 'staging-code', kind: 'code', environment: 'staging' },
    { kind: 'code_read', timeoutMs: 1000 },
  );
  assert.equal(blockedCode.allowed, false);

  const blockedPost = runtime.authorizeProbe(
    'declared',
    { id: 'staging-http', kind: 'http', environment: 'staging' },
    { kind: 'http_request', timeoutMs: 1000, method: 'POST', body: '{"x":1}' },
  );
  assert.equal(blockedPost.allowed, false);

  const allowedGet = runtime.authorizeProbe(
    'declared',
    { id: 'staging-http', kind: 'http', environment: 'staging' },
    { kind: 'http_request', timeoutMs: 1000, method: 'GET' },
  );
  assert.equal(allowedGet.allowed, true);
});

test('SecurityRuntime blocks destructive shell fragments in sandbox mode', () => {
  const runtime = new SecurityRuntime({ repoRoot: process.cwd() });

  const decision = runtime.authorizeProbe(
    'declared',
    { id: 'sandbox-shell', kind: 'shell', environment: 'sandbox' },
    { kind: 'shell_command', timeoutMs: 1000, command: ['bash', '-lc', 'rm -rf /tmp/fixture'] },
  );

  assert.equal(decision.allowed, false);
  assert.match(decision.reason ?? '', /blocked fragment/i);
});

test('SecurityRuntime allows benign shell-adjacent probes in sandbox with default policy', () => {
  const runtime = new SecurityRuntime();

  const decision = runtime.authorizeProbe(
    'declared',
    { id: 'sandbox-process', kind: 'shell', environment: 'sandbox' },
    { kind: 'process_check', timeoutMs: 1000, command: ['ps', 'aux'] },
  );

  assert.equal(decision.allowed, true);
  assert.equal(decision.observedSafetyState, 'allowed');
});

test('SecurityRuntime applies production-shadow restrictions to HTTP and code-adjacent probes', () => {
  const runtime = new SecurityRuntime({ repoRoot: process.cwd() });

  const blockedPost = runtime.authorizeProbe(
    'blind',
    { id: 'prod-http', kind: 'http', environment: 'production_shadow' },
    { kind: 'http_request', timeoutMs: 1000, method: 'POST', body: '{"probe":true}' },
  );
  assert.equal(blockedPost.allowed, false);

  const blockedCode = runtime.authorizeProbe(
    'blind',
    { id: 'prod-code', kind: 'code', environment: 'production_shadow' },
    { kind: 'evidence_check', timeoutMs: 1000 },
  );
  assert.equal(blockedCode.allowed, false);

  const allowedHead = runtime.authorizeProbe(
    'blind',
    { id: 'prod-http', kind: 'http', environment: 'production_shadow' },
    { kind: 'http_request', timeoutMs: 1000, method: 'HEAD' },
  );
  assert.equal(allowedHead.allowed, true);
});

test('SecurityRuntime blocks state and evidence checks in protected environments', () => {
  const runtime = new SecurityRuntime({ repoRoot: process.cwd() });

  const blockedState = runtime.authorizeProbe(
    'declared',
    { id: 'staging-state', kind: 'code', environment: 'staging' },
    { kind: 'state_check', timeoutMs: 1000 },
  );
  assert.equal(blockedState.allowed, false);
  assert.match(blockedState.reason ?? '', /Code-adjacent probes are disabled/i);

  const blockedEvidence = runtime.authorizeProbe(
    'declared',
    { id: 'hosted-evidence', kind: 'http', environment: 'hosted_authorized' },
    { kind: 'evidence_check', timeoutMs: 1000 },
  );
  assert.equal(blockedEvidence.allowed, false);
  assert.match(blockedEvidence.reason ?? '', /Code-adjacent probes are disabled/i);
});

test('SecurityRuntime blocks hosted-authorized shell and code probes but allows recognized HTTP methods', () => {
  const runtime = new SecurityRuntime({ repoRoot: process.cwd() });

  const blockedShell = runtime.authorizeProbe(
    'blind',
    { id: 'hosted-shell', kind: 'http', environment: 'hosted_authorized' },
    { kind: 'process_check', timeoutMs: 1000, command: ['echo', 'nope'] },
  );
  assert.equal(blockedShell.allowed, false);

  const blockedCode = runtime.authorizeProbe(
    'blind',
    { id: 'hosted-code', kind: 'http', environment: 'hosted_authorized' },
    { kind: 'dependency_read', timeoutMs: 1000 },
  );
  assert.equal(blockedCode.allowed, false);

  const allowedPatch = runtime.authorizeProbe(
    'blind',
    { id: 'hosted-http', kind: 'http', environment: 'hosted_authorized' },
    { kind: 'http_request', timeoutMs: 1000, method: 'PATCH', body: '{"probe":true}' },
  );
  assert.equal(allowedPatch.allowed, true);
});

test('SecurityRuntime blocks staging request bodies and rejects unknown hosted HTTP methods', () => {
  const runtime = new SecurityRuntime({ repoRoot: process.cwd() });

  const blockedBody = runtime.authorizeProbe(
    'blind',
    { id: 'staging-http-body', kind: 'http', environment: 'staging' },
    { kind: 'http_request', timeoutMs: 1000, method: 'GET', body: '{"probe":true}' },
  );
  assert.equal(blockedBody.allowed, false);
  assert.match(blockedBody.reason ?? '', /HTTP bodies are not allowed/i);

  const blockedHostedMethod = runtime.authorizeProbe(
    'blind',
    { id: 'hosted-weird-method', kind: 'http', environment: 'hosted_authorized' },
    { kind: 'prompt_injection', timeoutMs: 1000, method: 'TRACE' },
  );
  assert.equal(blockedHostedMethod.allowed, false);
  assert.match(blockedHostedMethod.reason ?? '', /not recognised for hosted_authorized tier/i);
});

test('SecurityRuntime enforces timeout caps even in sandbox', () => {
  const runtime = new SecurityRuntime({ repoRoot: process.cwd(), maxTimeoutMs: 500 });

  const decision = runtime.authorizeProbe(
    'declared',
    { id: 'sandbox-http', kind: 'http', environment: 'sandbox' },
    { kind: 'http_request', timeoutMs: 600, method: 'GET' },
  );

  assert.equal(decision.allowed, false);
  assert.match(decision.reason ?? '', /exceeds policy maximum/i);
});

test('SecurityRuntime blocks prompt-injection bodies in protected environments', () => {
  const runtime = new SecurityRuntime({ repoRoot: process.cwd() });

  const decision = runtime.authorizeProbe(
    'blind',
    { id: 'prod-prompt', kind: 'http', environment: 'production_shadow' },
    { kind: 'prompt_injection', timeoutMs: 1000, method: 'POST', body: '{"payload":"INJECT"}' },
  );

  assert.equal(decision.allowed, false);
  assert.match(decision.reason ?? '', /HTTP method POST is not allowed/i);
});

test('SecurityRuntime kill switch blocks all probes immediately', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-runtime-'));

  try {
    await writeFile(join(root, '.security-lab-stop'), 'stop', 'utf8');
    const runtime = new SecurityRuntime({ repoRoot: root });

    const decision = runtime.authorizeProbe(
      'declared',
      { id: 'sandbox-http', kind: 'http', environment: 'sandbox' },
      { kind: 'http_request', timeoutMs: 1000, method: 'GET' },
    );

    assert.equal(decision.allowed, false);
    assert.match(decision.reason ?? '', /kill switch/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('SecurityRuntime fails closed on an unrecognised probe kind', () => {
  const runtime = new SecurityRuntime({ repoRoot: process.cwd() });

  const decision = runtime.authorizeProbe(
    'declared',
    { id: 'sandbox', kind: 'shell', environment: 'sandbox' },
    { kind: 'definitely_not_a_kind' as never, timeoutMs: 1000 },
  );
  assert.equal(decision.allowed, false);
  assert.match(String(decision.reason), /Unrecognised probe kind/);
});

test('SecurityRuntime fails closed on a missing or non-finite timeout', () => {
  const runtime = new SecurityRuntime({ repoRoot: process.cwd() });
  const target = { id: 'sandbox', kind: 'shell' as const, environment: 'sandbox' as const };

  for (const timeoutMs of [Number.NaN, 0, -1, Number.POSITIVE_INFINITY]) {
    const decision = runtime.authorizeProbe('declared', target, { kind: 'http_request', timeoutMs });
    assert.equal(decision.allowed, false, String(timeoutMs));
    assert.match(String(decision.reason), /timeout is missing or invalid/i);
  }
});

test('SecurityRuntime denies executable probes that declare no command', () => {
  const runtime = new SecurityRuntime({ repoRoot: process.cwd() });

  for (const kind of ['shell_command', 'process_check', 'persistence_check'] as const) {
    const decision = runtime.authorizeProbe(
      'declared',
      { id: 'sandbox', kind: 'shell', environment: 'sandbox' },
      { kind, timeoutMs: 5000 },
    );
    assert.equal(decision.allowed, false, kind);
    assert.match(String(decision.reason), /did not declare a command/);
  }
});
