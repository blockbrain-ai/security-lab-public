import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { scanTarget, summarizeForModel } from './index.js';

const FIXTURES_DIR = resolve(import.meta.dirname, 'target-scanner.fixtures');

// ---------------------------------------------------------------------------
// Node fixture → coverage: full
// ---------------------------------------------------------------------------

test('scanTarget returns coverage: full for a Node.js project with routes', async () => {
  const root = join(FIXTURES_DIR, 'node-minimal');
  const result = await scanTarget(root, 'node-fixture');

  assert.equal(result.coverage, 'full');
  assert.ok(result.supportedProbeKinds.length > 0);
  assert.ok(result.supportedProbeKinds.includes('code_read'));
  assert.ok(result.supportedProbeKinds.includes('dependency_read'));
  assert.equal(result.detectedStack, undefined);

  const summary = summarizeForModel(result);
  assert.match(summary, /Coverage: full/);
});

// ---------------------------------------------------------------------------
// Python fixture → coverage: full (Flask routes extracted + deps parsed)
// ---------------------------------------------------------------------------

test('scanTarget returns coverage: full for a Python/Flask project with routes and deps', async () => {
  const root = join(FIXTURES_DIR, 'python-minimal');
  const result = await scanTarget(root, 'python-fixture');

  assert.equal(result.coverage, 'full');
  assert.ok(result.supportedProbeKinds.includes('http_request'));
  assert.ok(result.supportedProbeKinds.includes('code_read'));
  assert.ok(result.supportedProbeKinds.includes('dependency_read'));
  assert.ok(result.supportedProbeKinds.includes('dependency_scan'));
  assert.ok(result.detectedStack);
  assert.equal(result.detectedStack!.language, 'python');
  assert.ok(result.detectedStack!.manifestFiles.includes('requirements.txt'));

  // Parsed dependencies
  const flask = result.dependencies.find((d) => d.name === 'flask');
  assert.ok(flask, 'flask dependency should be parsed');
  assert.equal(flask!.version, '==3.0.0');

  const pydantic = result.dependencies.find((d) => d.name === 'pydantic');
  assert.ok(pydantic, 'pydantic dependency should be parsed');
  assert.ok(pydantic!.riskIndicators.includes('floating-version'));

  // Flask @app.route('/') decorator should be extracted
  assert.ok(result.routes.length >= 1, 'Flask route should be extracted');
  const rootRoute = result.routes.find((r) => r.path === '/');
  assert.ok(rootRoute, 'root route "/" should be in extracted routes');
  // Flask's @app.route without a methods= kwarg resolves as method ANY here
  assert.ok(['ANY', 'GET'].includes(rootRoute!.method), 'method should be ANY or GET');

  // Stack runtime should flip to python once FastAPI/Flask/etc. detected
  assert.equal(result.stack.runtime, 'python');
  assert.equal(result.stack.framework, 'flask');

  const summary = summarizeForModel(result);
  assert.match(summary, /Coverage: full/);
});

// ---------------------------------------------------------------------------
// Go fixture → coverage: full (after multi-language scanner upgrade)
// ---------------------------------------------------------------------------

test('scanTarget returns coverage: full for a Go project with go.mod and deps', async () => {
  const root = join(FIXTURES_DIR, 'go-minimal');
  const result = await scanTarget(root, 'go-fixture');

  // After the multi-language scanner upgrade, Go projects with parsed deps
  // reach full (code-only) coverage — same shape as the Python path.
  assert.equal(result.coverage, 'full');
  assert.ok(result.supportedProbeKinds.includes('code_read'));
  assert.ok(result.supportedProbeKinds.includes('dependency_read'));
  assert.ok(result.supportedProbeKinds.includes('dependency_scan'));
  assert.ok(result.detectedStack);
  assert.equal(result.detectedStack!.language, 'go');
  assert.ok(result.detectedStack!.manifestFiles.includes('go.mod'));

  // Stack detection flips runtime to go + framework=gin once gin is
  // listed in go.mod.
  assert.equal(result.stack.runtime, 'go');
  assert.equal(result.stack.framework, 'gin');

  // Verify parsed dependencies still come through.
  const gin = result.dependencies.find((d) => d.name === 'github.com/gin-gonic/gin');
  assert.ok(gin, 'gin dependency should be parsed');
  assert.equal(gin!.version, 'v1.9.1');
  assert.equal(gin!.isDirectDependency, true);

  const crypto = result.dependencies.find((d) => d.name === 'golang.org/x/crypto');
  assert.ok(crypto, 'crypto dependency should be parsed');
  assert.equal(crypto!.isDirectDependency, false, 'indirect dependency should be marked');

  // main.go in the fixture is a Hello World; no routes expected.
  assert.equal(result.routes.length, 0);
});

// ---------------------------------------------------------------------------
// Rust fixture → coverage: partial
// ---------------------------------------------------------------------------

test('scanTarget returns coverage: partial for a Rust project with Cargo.toml', async () => {
  const root = join(FIXTURES_DIR, 'rust-minimal');
  const result = await scanTarget(root, 'rust-fixture');

  assert.equal(result.coverage, 'partial');
  assert.ok(result.detectedStack);
  assert.equal(result.detectedStack!.language, 'rust');
  assert.ok(result.detectedStack!.manifestFiles.includes('Cargo.toml'));

  // Verify parsed dependencies
  const actix = result.dependencies.find((d) => d.name === 'actix-web');
  assert.ok(actix, 'actix-web dependency should be parsed');

  const serde = result.dependencies.find((d) => d.name === 'serde');
  assert.ok(serde, 'serde dependency should be parsed');

  const sqlx = result.dependencies.find((d) => d.name === 'sqlx');
  assert.ok(sqlx, 'sqlx dependency should be parsed');
  assert.ok(sqlx!.riskIndicators.includes('remote-source'), 'git source should be flagged');

  assert.equal(result.routes.length, 0);
});

// ---------------------------------------------------------------------------
// Java fixture → coverage: partial
// ---------------------------------------------------------------------------

test('scanTarget returns coverage: partial for a Java project with pom.xml', async () => {
  const root = join(FIXTURES_DIR, 'java-minimal');
  const result = await scanTarget(root, 'java-fixture');

  assert.equal(result.coverage, 'partial');
  assert.ok(result.detectedStack);
  assert.equal(result.detectedStack!.language, 'java');
  assert.ok(result.detectedStack!.manifestFiles.includes('pom.xml'));

  // Verify parsed dependencies
  const spring = result.dependencies.find((d) => d.name === 'org.springframework.boot:spring-boot-starter-web');
  assert.ok(spring, 'spring-boot-starter-web dependency should be parsed');
  assert.equal(spring!.version, '3.2.0');

  assert.equal(result.routes.length, 0);
});

// ---------------------------------------------------------------------------
// Empty fixture → coverage: none
// ---------------------------------------------------------------------------

test('scanTarget returns coverage: none for an empty directory', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-empty-'));

  try {
    const result = await scanTarget(root, 'empty-fixture');

    assert.equal(result.coverage, 'none');
    assert.equal(result.supportedProbeKinds.length, 0);
    assert.equal(result.detectedStack, undefined);
    assert.equal(result.routes.length, 0);
    assert.equal(result.dependencies.length, 0);

    const summary = summarizeForModel(result);
    assert.match(summary, /Coverage: none/);
    assert.match(summary, /no recognizable stack/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Target profile loading — example templates load without errors
// ---------------------------------------------------------------------------

test('example-code.yaml fixture loads and scans the Python fixture as full coverage', async () => {
  // Simulate loading the example-code template pointing at the Python fixture.
  // After the multi-language scanner upgrade, Python projects with routes or
  // parsed dependencies now reach full coverage (previously partial).
  const root = join(FIXTURES_DIR, 'python-minimal');
  const result = await scanTarget(root, 'example-code-test');

  assert.equal(result.coverage, 'full');
  assert.ok(result.supportedProbeKinds.length > 0);
  assert.ok(result.dependencies.length > 0, 'Should have parsed Python dependencies');
});

// ---------------------------------------------------------------------------
// Report rendering — coverage section appears for non-full coverage
// ---------------------------------------------------------------------------

test('renderInvestigationReport includes target coverage for partial coverage', async () => {
  // Lazy import to avoid pulling in the entire evidence-plane at module level
  const { renderInvestigationReport } = await import(
    '../../../evidence-plane/src/investigation-report.js'
  );

  const report = renderInvestigationReport({
    campaignId: 'test-campaign',
    status: 'completed',
    targetId: 'python-target',
    targetLabel: 'Python Target',
    targetKind: 'code',
    environment: 'sandbox',
    mode: 'declared',
    startedAt: '2026-04-11T00:00:00Z',
    completedAt: '2026-04-11T00:01:00Z',
    iterations: 1,
    totalCostUsd: 0.01,
    signalsFound: 0,
    signalsDormant: 0,
    signalsReactivated: 0,
    hypothesesTested: 0,
    chainHypothesesTested: 0,
    directHypothesesTested: 0,
    hypothesesConfirmed: 0,
    hypothesesRefuted: 0,
    maxChainLength: 0,
    chainLengthDistribution: {},
    findings: [],
    topSignals: [],
    refutedHypotheses: [],
    telemetrySummary: 'test',
    targetCoverage: {
      coverage: 'partial',
      supportedProbeKinds: ['code_read', 'dependency_read', 'dependency_scan'],
      detectedStack: {
        language: 'python',
        framework: 'unknown',
        manifestFiles: ['requirements.txt'],
      },
    },
  });

  assert.match(report, /Target Coverage/);
  assert.match(report, /Coverage: partial/);
  assert.match(report, /python/);
  assert.match(report, /dependency_read/);
  assert.match(report, /non-Node target/);
});

test('renderInvestigationReport omits target coverage section for full coverage', async () => {
  const { renderInvestigationReport } = await import(
    '../../../evidence-plane/src/investigation-report.js'
  );

  const report = renderInvestigationReport({
    campaignId: 'test-campaign',
    status: 'completed',
    targetId: 'node-target',
    targetLabel: 'Node Target',
    targetKind: 'code',
    environment: 'sandbox',
    mode: 'declared',
    startedAt: '2026-04-11T00:00:00Z',
    completedAt: '2026-04-11T00:01:00Z',
    iterations: 1,
    totalCostUsd: 0.01,
    signalsFound: 0,
    signalsDormant: 0,
    signalsReactivated: 0,
    hypothesesTested: 0,
    chainHypothesesTested: 0,
    directHypothesesTested: 0,
    hypothesesConfirmed: 0,
    hypothesesRefuted: 0,
    maxChainLength: 0,
    chainLengthDistribution: {},
    findings: [],
    topSignals: [],
    refutedHypotheses: [],
    telemetrySummary: 'test',
    targetCoverage: {
      coverage: 'full',
      supportedProbeKinds: ['http_request', 'code_read', 'dependency_read'],
    },
  });

  assert.doesNotMatch(report, /Target Coverage/);
});
