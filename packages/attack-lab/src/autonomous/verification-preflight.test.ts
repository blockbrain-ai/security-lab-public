import test from 'node:test';
import assert from 'node:assert/strict';
import {
  PreflightCheckSchema,
  VerificationPreflightReportSchema,
  runPreflight,
  formatPreflightReport,
} from './verification-preflight.js';
import { resolveVerificationProfile } from './verification-profiles.js';

// ---------------------------------------------------------------------------
// Schema validation
// ---------------------------------------------------------------------------

test('PreflightCheckSchema validates pass', () => {
  const check = PreflightCheckSchema.parse({
    stage: 'source',
    name: 'endpoint_reachable',
    status: 'pass',
    detail: 'Endpoint responded 200',
  });
  assert.equal(check.status, 'pass');
});

test('PreflightCheckSchema validates fail', () => {
  const check = PreflightCheckSchema.parse({
    stage: 'runtimeSetup',
    name: 'runtime_tools',
    status: 'fail',
    detail: 'Connection refused',
  });
  assert.equal(check.status, 'fail');
});

test('PreflightCheckSchema validates skip', () => {
  const check = PreflightCheckSchema.parse({
    stage: 'source',
    name: 'read_only_tools',
    status: 'skip',
    detail: 'Skipped in preflight',
  });
  assert.equal(check.status, 'skip');
});

test('VerificationPreflightReportSchema validates full report', () => {
  const report = VerificationPreflightReportSchema.parse({
    profileId: 'qwen_default',
    checks: [
      { stage: 'source', name: 'endpoint_reachable', status: 'pass', detail: 'ok' },
      { stage: 'source', name: 'structured_json', status: 'pass', detail: 'ok' },
      { stage: 'source', name: 'read_only_tools', status: 'skip', detail: 'skipped' },
    ],
    passed: true,
  });
  assert.equal(report.passed, true);
  assert.equal(report.checks.length, 3);
});

test('VerificationPreflightReportSchema validates null profileId', () => {
  const report = VerificationPreflightReportSchema.parse({
    profileId: null,
    checks: [],
    passed: true,
  });
  assert.equal(report.profileId, null);
});

// ---------------------------------------------------------------------------
// Report logic: passed computation
// ---------------------------------------------------------------------------

test('report with all pass/skip is passed', () => {
  const report = VerificationPreflightReportSchema.parse({
    profileId: 'test',
    checks: [
      { stage: 'source', name: 'endpoint_reachable', status: 'pass', detail: 'ok' },
      { stage: 'source', name: 'read_only_tools', status: 'skip', detail: 'skipped' },
    ],
    passed: true,
  });
  assert.equal(report.passed, true);
});

// ---------------------------------------------------------------------------
// runPreflight against unreachable endpoint
// ---------------------------------------------------------------------------

test('runPreflight fails for unreachable endpoint', async () => {
  const resolved = resolveVerificationProfile(null, {
    sourceBaseUrl: 'http://127.0.0.1:1/v1',
    runtimeBaseUrl: 'http://127.0.0.1:1/v1',
  });
  const report = await runPreflight(resolved, { skipStructuredJson: true });
  assert.equal(report.passed, false);
  const failedChecks = report.checks.filter((c) => c.status === 'fail');
  assert.ok(failedChecks.length > 0);
  assert.ok(failedChecks.some((c) => c.name === 'endpoint_reachable'));
});

// ---------------------------------------------------------------------------
// formatPreflightReport
// ---------------------------------------------------------------------------

test('formatPreflightReport includes result line', () => {
  const report = {
    profileId: 'test_profile',
    checks: [
      { stage: 'source' as const, name: 'endpoint_reachable' as const, status: 'pass' as const, detail: 'ok' },
    ],
    passed: true,
  };
  const output = formatPreflightReport(report);
  assert.ok(output.includes('PASS'));
  assert.ok(output.includes('test_profile'));
});

test('formatPreflightReport shows FAIL for failed report', () => {
  const report = {
    profileId: null,
    checks: [
      { stage: 'source' as const, name: 'endpoint_reachable' as const, status: 'fail' as const, detail: 'Connection refused' },
    ],
    passed: false,
  };
  const output = formatPreflightReport(report);
  assert.ok(output.includes('FAIL'));
  assert.ok(output.includes('Connection refused'));
});

// ---------------------------------------------------------------------------
// Deduplication: shared baseUrl+model only checked once
// ---------------------------------------------------------------------------

test('runPreflight deduplicates endpoint checks for shared baseUrl+model', async () => {
  const resolved = resolveVerificationProfile(null, {
    sourceBaseUrl: 'http://127.0.0.1:1/v1',
    runtimeBaseUrl: 'http://127.0.0.1:1/v1',
  });

  const report = await runPreflight(resolved, { skipStructuredJson: true });
  const endpointChecks = report.checks.filter((c) => c.name === 'endpoint_reachable');
  // Source and runtime share the same default model+baseUrl, so should be checked once
  assert.equal(endpointChecks.length, 1);
});

test('runPreflight checks separate endpoints for different baseUrls', async () => {
  const resolved = resolveVerificationProfile(null, {
    sourceBaseUrl: 'http://127.0.0.1:1/v1',
    runtimeBaseUrl: 'http://127.0.0.1:2/v1',
  });

  const report = await runPreflight(resolved, { skipStructuredJson: true });
  const endpointChecks = report.checks.filter((c) => c.name === 'endpoint_reachable');
  assert.ok(endpointChecks.length >= 2);
});
