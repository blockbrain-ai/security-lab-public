/**
 * Section 3.2 integration tests — verify that the InvestigationRunner honors
 * the run-mode split: smoke degrades honestly, serious modes fail closed on
 * required-lane coverage gaps.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { InvokeOptions, ModelAdapter, ModelResponse } from '../providers/contracts.js';
import { InvestigationRunner } from './investigation-runner.js';

class EmptyAdapter implements ModelAdapter {
  readonly provider = 'test';
  readonly model = 'empty-adapter';
  async invoke<T = unknown>(_options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    return {
      content: '{}',
      usage: { inputTokens: 0, outputTokens: 0, costUsd: 0 },
      durationMs: 0,
      provider: this.provider,
      model: this.model,
    };
  }
}

async function writeFixtureTargets(
  root: string,
  { requiredLanes }: { requiredLanes: string[] },
): Promise<{ targetPath: string; liveTargetPath: string; repoRoot: string; campaignDir: string }> {
  const repoRoot = join(root, 'target');
  const campaignDir = join(root, 'campaigns');
  const targetPath = join(root, 'mode-static.yaml');
  const liveTargetPath = join(root, 'mode-local-live.yaml');

  await mkdir(join(repoRoot, 'src'), { recursive: true });
  await writeFile(
    join(repoRoot, 'package.json'),
    JSON.stringify({ name: 'mode-target', version: '1.0.0' }, null, 2),
    'utf8',
  );
  await writeFile(join(repoRoot, 'src', 'index.ts'), 'export const ok = true;\n', 'utf8');

  const requiredLanesYaml = requiredLanes.length
    ? `requiredLanes:\n${requiredLanes.map((lane) => `  - ${lane}`).join('\n')}\n`
    : '';

  await writeFile(
    targetPath,
    `id: mode-static
name: Mode Static
kind: code
environment: sandbox
repoRoot: ${repoRoot}
${requiredLanesYaml}verificationPolicy:
  expectedRepoMarkers:
    - package.json
    - src
  requireSourceScan: true
`,
    'utf8',
  );

  await writeFile(
    liveTargetPath,
    `id: mode-local-live
name: Mode Local Live
kind: http
environment: local_live
baseUrl: http://127.0.0.1:65535
repoRoot: ${repoRoot}
requiredIdentities:
  - user_a_low
verificationPolicy:
  expectedRepoMarkers:
    - package.json
    - src
  requireSourceScan: true
identities:
  - id: user_a_low
    kind: bearer_token
    tokenEnv: MODE_TEST_USER_A_TOKEN
    organizationId: org_a
`,
    'utf8',
  );

  return { targetPath, liveTargetPath, repoRoot, campaignDir };
}

test('smoke mode: missing required local-live identity finishes as degraded', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-mode-smoke-'));
  try {
    const { targetPath, liveTargetPath, campaignDir } = await writeFixtureTargets(root, {
      requiredLanes: ['local-live'],
    });
    delete process.env.MODE_TEST_USER_A_TOKEN;

    const runner = new InvestigationRunner({
      targetRef: targetPath,
      mode: 'declared',
      runMode: 'smoke',
      plannerAdapter: new EmptyAdapter(),
      judgeAdapter: new EmptyAdapter(),
      maxIterations: 0,
      maxCostUsd: 5,
      campaignDir,
      verifyVia: ['local-live'],
      liveTargetRef: liveTargetPath,
    });

    const result = await runner.run();
    // Smoke mode never fails closed: it MUST NOT be 'incomplete'.
    assert.notEqual(result.executionStatus, 'incomplete');
    assert.ok(result.executionStatus === 'degraded' || result.executionStatus === 'complete');

    const summary = JSON.parse(await readFile(join(result.runDir, 'summary.json'), 'utf8')) as {
      runMode?: string;
      executionStatus?: string;
    };
    assert.equal(summary.runMode, 'smoke');
    assert.notEqual(summary.executionStatus, 'incomplete');

    const reportPath = join(result.runDir, 'report.md');
    const report = await readFile(reportPath, 'utf8');
    assert.match(report, /Run mode.*smoke/);
  } finally {
    delete process.env.MODE_TEST_USER_A_TOKEN;
    await rm(root, { recursive: true, force: true });
  }
});

test('serious-local mode: missing required local-live identity fails closed as incomplete', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-mode-serious-local-'));
  try {
    const { targetPath, liveTargetPath, campaignDir } = await writeFixtureTargets(root, {
      requiredLanes: ['local-live'],
    });
    delete process.env.MODE_TEST_USER_A_TOKEN;

    const runner = new InvestigationRunner({
      targetRef: targetPath,
      mode: 'declared',
      runMode: 'serious-local',
      plannerAdapter: new EmptyAdapter(),
      judgeAdapter: new EmptyAdapter(),
      maxIterations: 0,
      maxCostUsd: 5,
      campaignDir,
      verifyVia: ['local-live'],
      liveTargetRef: liveTargetPath,
    });

    const result = await runner.run();
    assert.equal(result.executionStatus, 'incomplete');
    assert.ok((result.coverageGaps ?? []).length > 0);

    const summary = JSON.parse(await readFile(join(result.runDir, 'summary.json'), 'utf8')) as {
      runMode?: string;
      executionStatus?: string;
    };
    assert.equal(summary.runMode, 'serious-local');
    assert.equal(summary.executionStatus, 'incomplete');

    const report = await readFile(join(result.runDir, 'report.md'), 'utf8');
    assert.match(report, /Run mode.*serious-local/);
    assert.match(report, /Execution status.*incomplete/);
    assert.match(report, /What's missing/);
  } finally {
    delete process.env.MODE_TEST_USER_A_TOKEN;
    await rm(root, { recursive: true, force: true });
  }
});

test('serious-local mode aborts before verification lanes run when the mid-pipeline gate fails', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-mode-serious-local-gate-'));
  try {
    const { targetPath, liveTargetPath, campaignDir } = await writeFixtureTargets(root, {
      requiredLanes: ['local-live'],
    });
    delete process.env.MODE_TEST_USER_A_TOKEN;

    const runner = new InvestigationRunner({
      targetRef: targetPath,
      mode: 'declared',
      runMode: 'serious-local',
      plannerAdapter: new EmptyAdapter(),
      judgeAdapter: new EmptyAdapter(),
      maxIterations: 0,
      maxCostUsd: 5,
      campaignDir,
      verifyVia: ['local-live'],
      liveTargetRef: liveTargetPath,
    });

    let verificationLanesCalled = false;
    (runner as any).runVerificationLanes = async () => {
      verificationLanesCalled = true;
      throw new Error('runVerificationLanes should not be called when the mid-pipeline gate aborts');
    };

    const result = await runner.run();
    assert.equal(verificationLanesCalled, false);
    assert.equal(result.executionStatus, 'incomplete');

    const events = await readFile(join(result.runDir, 'events.jsonl'), 'utf8');
    assert.match(events, /verification_mid_pipeline_gate_failed/);
  } finally {
    delete process.env.MODE_TEST_USER_A_TOKEN;
    await rm(root, { recursive: true, force: true });
  }
});

test('serious-end-to-end mode: hosted in requiredLanes without hosted auth fails closed', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-mode-serious-e2e-'));
  try {
    const { targetPath, liveTargetPath, campaignDir } = await writeFixtureTargets(root, {
      requiredLanes: ['local-live', 'hosted'],
    });
    delete process.env.MODE_TEST_USER_A_TOKEN;

    const runner = new InvestigationRunner({
      targetRef: targetPath,
      mode: 'declared',
      runMode: 'serious-end-to-end',
      plannerAdapter: new EmptyAdapter(),
      judgeAdapter: new EmptyAdapter(),
      maxIterations: 0,
      maxCostUsd: 5,
      campaignDir,
      // Intentionally NOT including 'hosted' in verifyVia / not authorizing hosted
      verifyVia: ['local-live'],
      liveTargetRef: liveTargetPath,
    });

    const result = await runner.run();
    assert.equal(result.executionStatus, 'incomplete');

    const summary = JSON.parse(await readFile(join(result.runDir, 'summary.json'), 'utf8')) as {
      runMode?: string;
      executionStatus?: string;
    };
    assert.equal(summary.runMode, 'serious-end-to-end');
    assert.equal(summary.executionStatus, 'incomplete');
  } finally {
    delete process.env.MODE_TEST_USER_A_TOKEN;
    await rm(root, { recursive: true, force: true });
  }
});
