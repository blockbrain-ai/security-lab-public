import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  DockerSetupResultSchema,
  RuntimeVerificationResultSchema,
  RuntimeVerificationArtifactSchema,
} from './runtime-verify-schemas.js';
import {
  buildDockerSetupPrompt,
  buildPerCandidateRuntimePrompt,
} from './runtime-verify-prompts.js';
import {
  determineServicePrecheckPorts,
  ensureDockerRunning,
  extractComposePublishedPorts,
  extractPortFromBaseUrl,
} from './runtime-verify-runner.js';

// ---------------------------------------------------------------------------
// Docker setup prompt
// ---------------------------------------------------------------------------

test('buildDockerSetupPrompt includes project name and repo root', () => {
  const prompt = buildDockerSetupPrompt('/repo/target', 'fixture-target', 'securitylab-fixture-12345');
  assert.match(prompt, /\/repo\/target/);
  assert.match(prompt, /fixture-target/);
  assert.match(prompt, /securitylab-fixture-12345/);
  assert.match(prompt, /docker info/);
  assert.match(prompt, /docker compose/);
  assert.match(prompt, /COMPOSE_PROJECT_NAME/);
});

test('buildDockerSetupPrompt does not ask for host package installs', () => {
  const prompt = buildDockerSetupPrompt('/repo', 'target', 'proj-1');
  assert.match(prompt, /Do NOT install packages on the host/);
  assert.match(prompt, /Do NOT edit files/);
});

// ---------------------------------------------------------------------------
// Per-candidate runtime prompt
// ---------------------------------------------------------------------------

test('buildPerCandidateRuntimePrompt includes candidate and service info', () => {
  const prompt = buildPerCandidateRuntimePrompt(
    { id: 'ws-1-11', claim: 'SSRF via pass-through' },
    '/repo/target', 'fixture-target',
    { baseUrl: 'http://localhost:4000', ports: ['4000'], composeCwd: '.', composeFiles: ['docker-compose.yml'] },
  );
  assert.match(prompt, /ws-1-11/);
  assert.match(prompt, /SSRF via pass-through/);
  assert.match(prompt, /localhost:4000/);
  assert.match(prompt, /reproducerCommands/);
  assert.match(prompt, /pvrReady/);
});

test('buildPerCandidateRuntimePrompt includes source verification context', () => {
  const prompt = buildPerCandidateRuntimePrompt(
    {
      id: 'ws-1-11',
      claim: 'SSRF',
      sourceVerification: {
        candidateId: 'ws-1-11',
        claim: 'SSRF',
        status: 'supported',
        rootCause: 'No URL validation in pass_through_request()',
        sourceRefs: [{ file: 'proxy/pass_through.py', line: 42, snippet: 'httpx.request(url)' }],
        preconditions: ['Attacker controls base_target_url'],
        defenseMechanismsObserved: [],
        assumptions: [],
        validationNotes: [],
        confidence: 0.85,
        exploitPath: 'POST /api/pass-through with crafted URL',
        runtimePlan: 'Send POST to /api/pass-through with internal URL',
      },
    },
    '/repo', 'target',
    { baseUrl: 'http://localhost:4000', ports: ['4000'], composeFiles: [], composeCwd: '.' },
  );
  assert.match(prompt, /Source Verification Evidence/);
  assert.match(prompt, /No URL validation/);
  assert.match(prompt, /pass_through\.py:42/);
  assert.match(prompt, /Attacker controls/);
  assert.match(prompt, /POST \/api\/pass-through/);
  assert.match(prompt, /Send POST to/);
});

test('buildPerCandidateRuntimePrompt prohibits source re-exploration', () => {
  const prompt = buildPerCandidateRuntimePrompt(
    { id: 'test-1', claim: 'test' },
    '/repo', 'target',
    { baseUrl: 'http://localhost:4000', ports: ['4000'], composeFiles: [], composeCwd: '.' },
  );
  assert.match(prompt, /do NOT re-explore source code/i);
  assert.match(prompt, /5 shell commands and 5 HTTP requests/);
});

test('buildPerCandidateRuntimePrompt requires raw evidence and source cross-check', () => {
  const prompt = buildPerCandidateRuntimePrompt(
    { id: 'test-1', claim: 'test' },
    '/repo', 'target',
    { baseUrl: 'http://localhost:4000', ports: ['4000'], composeFiles: [], composeCwd: '.' },
  );
  assert.match(prompt, /NOT your summary/);
  assert.match(prompt, /Source cross-check/);
  assert.match(prompt, /Do NOT invent header names/);
  assert.match(prompt, /EXACT raw output/);
});

// ---------------------------------------------------------------------------
// Schema validation
// ---------------------------------------------------------------------------

test('DockerSetupResultSchema parses successful setup', () => {
  const input = {
    success: true,
    baseUrl: 'http://localhost:4000',
    ports: ['4000', '5432'],
    composeCwd: '.',
    composeFiles: ['docker-compose.yml'],
    projectName: 'securitylab-test-123',
    log: 'Services started successfully',
  };
  const result = DockerSetupResultSchema.parse(input);
  assert.equal(result.success, true);
  assert.equal(result.ports.length, 2);
  assert.equal(result.projectName, 'securitylab-test-123');
});

test('DockerSetupResultSchema parses failed setup with defaults', () => {
  const input = {
    success: false,
    log: 'Docker not available',
  };
  const result = DockerSetupResultSchema.parse(input);
  assert.equal(result.success, false);
  assert.deepEqual(result.ports, []);
  assert.deepEqual(result.composeFiles, []);
});

test('RuntimeVerificationResultSchema parses confirmed finding with PVR', () => {
  const input = {
    candidateId: 'ws-1-11',
    claim: 'SSRF via pass-through',
    status: 'confirmed',
    rootCause: 'No URL validation in pass_through_request()',
    reproducerCommands: ['curl -X POST http://localhost:4000/api/pass-through -d \'{"url":"http://169.254.169.254"}\''],
    reproducerOutput: '{"metadata":"ec2-instance-id"}',
    httpEvidence: [
      { url: 'http://localhost:4000/api/pass-through', method: 'POST', statusCode: 200, snippet: 'metadata response' },
    ],
    severity: 'critical',
    pvrReady: true,
    filingNotes: 'Distinct from existing SSRF advisories — different endpoint',
    suggestedFix: 'Add URL allowlist validation to pass_through_request()',
    regressionTest: 'Test that pass_through_request rejects internal URLs',
    confidence: 0.95,
  };
  const result = RuntimeVerificationResultSchema.parse(input);
  assert.equal(result.status, 'confirmed');
  assert.equal(result.pvrReady, true);
  assert.equal(result.severity, 'critical');
  assert.equal(result.reproducerCommands.length, 1);
  assert.equal(result.httpEvidence.length, 1);
});

test('RuntimeVerificationResultSchema parses blocked finding', () => {
  const input = {
    candidateId: 'test-1',
    claim: 'test claim',
    status: 'blocked',
    rootCause: 'Cannot verify',
    reproducerCommands: [],
    httpEvidence: [],
    blocker: 'Docker setup failed',
    confidence: 0,
  };
  const result = RuntimeVerificationResultSchema.parse(input);
  assert.equal(result.status, 'blocked');
  assert.equal(result.pvrReady, false);
  assert.equal(result.blocker, 'Docker setup failed');
});

test('RuntimeVerificationResultSchema defaults pvrReady to false', () => {
  const input = {
    candidateId: 'test-1',
    claim: 'test',
    status: 'not_reproducible',
    rootCause: 'not found',
    reproducerCommands: [],
    httpEvidence: [],
    confidence: 0.1,
  };
  const result = RuntimeVerificationResultSchema.parse(input);
  assert.equal(result.pvrReady, false);
});

// ---------------------------------------------------------------------------
// ensureDockerRunning
// ---------------------------------------------------------------------------

test('ensureDockerRunning resolves quickly when Docker is already running', async () => {
  // This test exercises the fast path. If Docker Desktop is running it
  // succeeds immediately; if not it will attempt to start Docker Desktop
  // (which is the intended behavior we're testing). Either way, it should
  // not hang or throw with a reasonable timeout.
  // On CI without Docker, this will throw with a clear message — that's fine,
  // we just verify the error is actionable.
  try {
    await ensureDockerRunning(30_000);
  } catch (err) {
    assert.ok(err instanceof Error);
    assert.match(err.message, /Docker/i, 'Error message should mention Docker');
  }
});

test('ensureDockerRunning is exported and callable', () => {
  assert.equal(typeof ensureDockerRunning, 'function');
});

// ---------------------------------------------------------------------------
// Service pre-detection helpers
// ---------------------------------------------------------------------------

test('extractPortFromBaseUrl returns explicit ports and defaults', () => {
  assert.equal(extractPortFromBaseUrl('http://127.0.0.1:8080/v1'), '8080');
  assert.equal(extractPortFromBaseUrl('https://example.com/path'), '443');
  assert.equal(extractPortFromBaseUrl('http://example.com/path'), '80');
  assert.equal(extractPortFromBaseUrl(undefined), null);
  assert.equal(extractPortFromBaseUrl('not-a-url'), null);
});

test('extractComposePublishedPorts reads published host ports from compose files', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'sl-compose-'));
  try {
    await writeFile(join(dir, 'docker-compose.yml'), `
services:
  app:
    ports:
      - "4000:4000"
      - "127.0.0.1:5435:5432"
  worker:
    ports:
      - 8081
`, 'utf8');

    const ports = await extractComposePublishedPorts(dir);
    assert.deepEqual(ports.sort(), ['4000', '5435', '8081']);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('determineServicePrecheckPorts prefers compose-declared ports and excludes model ports', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'sl-compose-'));
  try {
    await writeFile(join(dir, 'docker-compose.yml'), `
services:
  proxy:
    ports:
      - "4000:4000"
      - "8080:8080"
`, 'utf8');

    const ports = await determineServicePrecheckPorts(dir, ['http://127.0.0.1:8080/v1']);
    assert.deepEqual(ports, ['4000']);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('determineServicePrecheckPorts returns empty when no compose file exists', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'sl-compose-'));
  try {
    const ports = await determineServicePrecheckPorts(dir, ['http://127.0.0.1:8080/v1']);
    assert.deepEqual(ports, []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Schema validation: full artifact
// ---------------------------------------------------------------------------

test('RuntimeVerificationArtifactSchema parses full artifact', () => {
  const input = {
    campaignId: 'test-campaign',
    targetId: 'fixture-target',
    timestamp: '2026-04-26T10:00:00Z',
    dockerSetupSuccess: true,
    dockerSetupLog: 'Started OK',
    serviceInfo: {
      baseUrl: 'http://localhost:4000',
      ports: ['4000'],
      composeCwd: '/repo/target',
      composeFiles: ['docker-compose.yml'],
      projectName: 'securitylab-test-123',
    },
    candidates: [
      {
        modelResult: {
          candidateId: 'ws-1-11',
          claim: 'SSRF',
          status: 'confirmed',
          rootCause: 'No URL validation',
          reproducerCommands: ['curl ...'],
          httpEvidence: [],
          severity: 'high',
          pvrReady: true,
          confidence: 0.9,
        },
        validatedResult: {
          candidateId: 'ws-1-11',
          claim: 'SSRF',
          status: 'confirmed',
          rootCause: 'No URL validation',
          reproducerCommands: ['curl ...'],
          httpEvidence: [],
          severity: 'high',
          pvrReady: true,
          confidence: 0.9,
        },
        wasDowngraded: false,
        validationNotes: [],
      },
      {
        modelResult: {
          candidateId: 'ws-3-17',
          claim: 'JWT bypass',
          status: 'blocked',
          rootCause: 'Cannot verify',
          reproducerCommands: [],
          httpEvidence: [],
          blocker: 'Endpoint not found',
          confidence: 0,
        },
        validatedResult: {
          candidateId: 'ws-3-17',
          claim: 'JWT bypass',
          status: 'blocked',
          rootCause: 'Cannot verify',
          reproducerCommands: [],
          httpEvidence: [],
          blocker: 'Endpoint not found',
          confidence: 0,
        },
        wasDowngraded: false,
        validationNotes: [],
      },
    ],
  };
  const result = RuntimeVerificationArtifactSchema.parse(input);
  assert.equal(result.candidates.length, 2);
  assert.equal(result.dockerSetupSuccess, true);
  assert.ok(result.serviceInfo);
  assert.equal(result.serviceInfo.projectName, 'securitylab-test-123');
});
