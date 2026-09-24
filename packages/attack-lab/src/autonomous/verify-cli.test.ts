import test from 'node:test';
import assert from 'node:assert/strict';
import { execSync } from 'node:child_process';
import { mkdtemp, rm, writeFile, mkdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const CLI = resolve(import.meta.dirname, 'verify-cli.ts');

test('verify-cli --help exits 0 and prints usage', () => {
  const output = execSync(`node --import tsx ${CLI} --help`, {
    encoding: 'utf8',
    timeout: 15000,
  });
  assert.match(output, /Verification Agent/);
  assert.match(output, /--report/);
  assert.match(output, /--target/);
  assert.match(output, /--repo-slug/);
  assert.match(output, /--dry-run/);
  assert.match(output, /--runtime-provider <name>\s+bounded_local \| claude_code \| codex_cli \(default: bounded_local\)/);
});

test('verify-cli with no args shows help (same as --help)', () => {
  // No args → prints usage and exits 0 (same as --help)
  const output = execSync(`node --import tsx ${CLI}`, { encoding: 'utf8', timeout: 15000 });
  assert.match(output, /Verification Agent/);
});

test('verify-cli exits 1 when report file does not exist', () => {
  assert.throws(
    () => execSync(
      `node --import tsx ${CLI} --report /nonexistent/report.md --target /nonexistent/target.yaml`,
      { encoding: 'utf8', timeout: 15000 },
    ),
  );
});

test('verify-cli --dry-run produces a brief-mode prompt without inline report content', async () => {
  const tmpDir = await mkdtemp(join(tmpdir(), 'verify-cli-test-'));
  const reportPath = join(tmpDir, 'report.md');
  const targetDir = join(tmpDir, 'target-repo');

  try {
    await mkdir(targetDir, { recursive: true });

    // Write a fake report
    await writeFile(reportPath, [
      '# Fake Report',
      '',
      'This sentence should stay out of the prompt body.',
      '',
      '## Evidence Leads',
      '- **[ws-1]** (conf=0.95) Some findings here. | assets=src/app.py',
      '',
      '---',
    ].join('\n'));

    // Write a minimal target YAML
    const targetPath = join(tmpDir, 'target.yaml');
    await writeFile(targetPath, [
      'id: test-target',
      'name: Test Target',
      'kind: code',
      'environment: sandbox',
      `repoRoot: ${targetDir}`,
    ].join('\n'));

    // Init a git repo so slug derivation doesn't crash
    execSync('git init && git remote add origin https://github.com/test-owner/test-repo.git', {
      cwd: targetDir,
      encoding: 'utf8',
      timeout: 5000,
    });

    const output = execSync(
      `node --import tsx ${CLI} --dry-run --verification-mode source --report ${reportPath} --target ${targetPath}`,
      { encoding: 'utf8', timeout: 15000 },
    );

    // The dry-run should build a source-verification prompt for the extracted candidate
    assert.match(output, /DRY RUN/);
    assert.match(output, new RegExp(reportPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    assert.match(output, /Extracted 1 candidates:/);
    assert.match(output, /You are a source-code verification agent/);

    // The prompt should NOT contain the actual report content inline
    assert.doesNotMatch(output, /This sentence should stay out of the prompt body\./,
      'The report content should not be embedded inline — the agent should read it from disk');

    // The repo slug should be derived from the git remote
    assert.match(output, /test-owner\/test-repo/);
    assert.match(output, /Slug:\s+test-owner\/test-repo/);

    // Prompt should be brief (well under the 28K char threshold the reviewer flagged)
    const promptLength = parseInt(output.match(/Prompt length: (\d+)/)?.[1] ?? '0', 10);
    assert.ok(promptLength > 100, 'Prompt should be non-empty');
    assert.ok(promptLength < 10000,
      `Prompt should be brief-mode (<10K chars), got ${promptLength} chars`);

  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
});

test('verify-cli derives slug from SSH remote URL', async () => {
  const tmpDir = await mkdtemp(join(tmpdir(), 'verify-cli-ssh-'));
  const reportPath = join(tmpDir, 'report.md');
  const targetDir = join(tmpDir, 'target-repo');

  try {
    await mkdir(targetDir, { recursive: true });
    await writeFile(reportPath, [
      '# Fake',
      '',
      '## Evidence Leads',
      '- **[ws-1]** (conf=0.95) SSH lead | assets=src/app.py',
      '',
      '---',
    ].join('\n'));
    const targetPath = join(tmpDir, 'target.yaml');
    await writeFile(targetPath, [
      'id: ssh-test',
      'name: SSH Test',
      'kind: code',
      'environment: sandbox',
      `repoRoot: ${targetDir}`,
    ].join('\n'));

    execSync('git init && git remote add origin git@github.com:myorg/myrepo.git', {
      cwd: targetDir,
      encoding: 'utf8',
      timeout: 5000,
    });

    const output = execSync(
      `node --import tsx ${CLI} --dry-run --report ${reportPath} --target ${targetPath}`,
      { encoding: 'utf8', timeout: 15000 },
    );

    assert.match(output, /myorg\/myrepo/);
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
});

test('verify-cli --repo-slug overrides auto-derived slug', async () => {
  const tmpDir = await mkdtemp(join(tmpdir(), 'verify-cli-slug-'));
  const reportPath = join(tmpDir, 'report.md');
  const targetDir = join(tmpDir, 'target-repo');

  try {
    await mkdir(targetDir, { recursive: true });
    await writeFile(reportPath, [
      '# Fake',
      '',
      '## Evidence Leads',
      '- **[ws-1]** (conf=0.95) Slug override lead | assets=src/app.py',
      '',
      '---',
    ].join('\n'));
    const targetPath = join(tmpDir, 'target.yaml');
    await writeFile(targetPath, [
      'id: slug-override-test',
      'name: Slug Override',
      'kind: code',
      'environment: sandbox',
      `repoRoot: ${targetDir}`,
    ].join('\n'));

    // No git init — slug derivation would fail, but --repo-slug overrides
    const output = execSync(
      `node --import tsx ${CLI} --dry-run --verification-mode source --report ${reportPath} --target ${targetPath} --repo-slug custom-org/custom-repo`,
      { encoding: 'utf8', timeout: 15000 },
    );

    assert.match(output, /Slug:\s+custom-org\/custom-repo/);
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
});

test('verify-cli full dry-run defaults both source and runtime to bounded_local qwen', async () => {
  const tmpDir = await mkdtemp(join(tmpdir(), 'verify-cli-defaults-'));
  const reportPath = join(tmpDir, 'report.md');
  const targetDir = join(tmpDir, 'target-repo');

  try {
    await mkdir(targetDir, { recursive: true });
    await writeFile(reportPath, [
      '# Fake',
      '',
      '## Evidence Leads',
      '- **[ws-1]** (conf=0.95) Defaults lead | assets=src/app.py',
      '',
      '---',
    ].join('\n'));
    const targetPath = join(tmpDir, 'target.yaml');
    await writeFile(targetPath, [
      'id: defaults-test',
      'name: Defaults Test',
      'kind: code',
      'environment: sandbox',
      `repoRoot: ${targetDir}`,
    ].join('\n'));

    execSync('git init && git remote add origin https://github.com/test-owner/test-repo.git', {
      cwd: targetDir,
      encoding: 'utf8',
      timeout: 5000,
    });

    const output = execSync(
      `node --import tsx ${CLI} --dry-run --verification-mode full --report ${reportPath} --target ${targetPath}`,
      { encoding: 'utf8', timeout: 15000 },
    );

    assert.match(output, /Source:\s+bounded_local \/ qwen3\.6-27b/);
    assert.match(output, /Runtime:\s+bounded_local \/ qwen3\.6-27b/);
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
});

test('verify-cli finalizes manifest and run monitor on post-start failure', async () => {
  const tmpDir = await mkdtemp(join(tmpdir(), 'verify-cli-failure-'));
  const reportPath = join(tmpDir, 'report.md');
  const targetDir = join(tmpDir, 'target-repo');
  const outputDir = join(tmpDir, 'out');

  try {
    await mkdir(targetDir, { recursive: true });
    await writeFile(reportPath, [
      '# Fake',
      '',
      '## Evidence Leads',
      '- **[ws-1]** (conf=0.95) Failure-path lead | assets=src/app.py',
      '',
      '---',
    ].join('\n'));
    const targetPath = join(tmpDir, 'target.yaml');
    await writeFile(targetPath, [
      'id: failure-test',
      'name: Failure Test',
      'kind: code',
      'environment: sandbox',
      `repoRoot: ${targetDir}`,
    ].join('\n'));

    execSync('git init && git remote add origin https://github.com/test-owner/test-repo.git', {
      cwd: targetDir,
      encoding: 'utf8',
      timeout: 5000,
    });

    assert.throws(
      () => execSync(
        `node --import tsx ${CLI} --verification-mode source --report ${reportPath} --target ${targetPath} --output ${outputDir} --source-provider invalid-provider --source-model fake-model`,
        { encoding: 'utf8', timeout: 15000 },
      ),
      /Verification agent failed/,
    );

    const manifest = JSON.parse(await readFile(join(outputDir, 'manifest.json'), 'utf8'));
    assert.equal(manifest.exitStatus, 'failure');
    assert.ok(manifest.finalizedAt);
    assert.ok(typeof manifest.durationMs === 'number');

    const snapshots = (await readFile(join(outputDir, 'monitoring', 'snapshots.jsonl'), 'utf8'))
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line));
    assert.equal(snapshots[0].kind, 'run_start');
    assert.ok(snapshots.some((event) => event.kind === 'stage_enter' && event.stage === 'source'));
    assert.ok(snapshots.some((event) => event.kind === 'stage_exit' && event.stage === 'source'));
    assert.equal(snapshots.at(-1)?.kind, 'run_end');
    assert.equal(snapshots.at(-1)?.detail?.exitStatus, 'failure');

    const anomalies = (await readFile(join(outputDir, 'monitoring', 'anomalies.jsonl'), 'utf8'))
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line));
    assert.ok(anomalies.some((entry) => entry.kind === 'run_failure'));
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
});

test('verify-cli writes profileId into manifest when using a verification profile', async () => {
  const tmpDir = await mkdtemp(join(tmpdir(), 'verify-cli-profile-manifest-'));
  const reportPath = join(tmpDir, 'report.md');
  const targetDir = join(tmpDir, 'target-repo');
  const outputDir = join(tmpDir, 'out');

  try {
    await mkdir(targetDir, { recursive: true });
    await writeFile(reportPath, [
      '# Fake',
      '',
      '## Evidence Leads',
      '- **[ws-1]** (conf=0.95) Profile manifest lead | assets=src/app.py',
      '',
      '---',
    ].join('\n'));
    const targetPath = join(tmpDir, 'target.yaml');
    await writeFile(targetPath, [
      'id: profile-manifest-test',
      'name: Profile Manifest Test',
      'kind: code',
      'environment: sandbox',
      `repoRoot: ${targetDir}`,
    ].join('\n'));

    execSync('git init && git remote add origin https://github.com/test-owner/test-repo.git', {
      cwd: targetDir,
      encoding: 'utf8',
      timeout: 5000,
    });

    assert.throws(
      () => execSync(
        `node --import tsx ${CLI} --verification-profile qwen_source_r1_critic --verification-mode source --report ${reportPath} --target ${targetPath} --output ${outputDir} --source-provider invalid-provider --source-model fake-model`,
        { encoding: 'utf8', timeout: 15000 },
      ),
      /Verification agent failed/,
    );

    const manifest = JSON.parse(await readFile(join(outputDir, 'manifest.json'), 'utf8'));
    assert.equal(manifest.profileId, 'qwen_source_r1_critic');
    assert.equal(manifest.lanes.sourceCritic.model, 'deepseek-r1:14b');
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
});

test('verify-cli rejects unsupported runtime setup/probe provider split', async () => {
  const tmpDir = await mkdtemp(join(tmpdir(), 'verify-cli-runtime-split-'));
  const reportPath = join(tmpDir, 'report.md');
  const targetDir = join(tmpDir, 'target-repo');

  try {
    await mkdir(targetDir, { recursive: true });
    await writeFile(reportPath, [
      '# Fake',
      '',
      '## Evidence Leads',
      '- **[ws-1]** (conf=0.95) Runtime split lead | assets=src/app.py',
      '',
      '---',
    ].join('\n'));
    const targetPath = join(tmpDir, 'target.yaml');
    await writeFile(targetPath, [
      'id: runtime-split-test',
      'name: Runtime Split Test',
      'kind: code',
      'environment: sandbox',
      `repoRoot: ${targetDir}`,
    ].join('\n'));

    execSync('git init && git remote add origin https://github.com/test-owner/test-repo.git', {
      cwd: targetDir,
      encoding: 'utf8',
      timeout: 5000,
    });

    assert.throws(
      () => execSync(
        `node --import tsx ${CLI} --dry-run --verification-mode runtime --report ${reportPath} --target ${targetPath} --runtime-setup-provider codex_cli`,
        { encoding: 'utf8', timeout: 15000 },
      ),
      /runtime setup\/probe provider splits are not implemented/,
    );
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
});

test('verify-cli requires --benchmark-label when promoting a baseline', async () => {
  const tmpDir = await mkdtemp(join(tmpdir(), 'verify-cli-benchmark-promote-'));
  const reportPath = join(tmpDir, 'report.md');
  const targetDir = join(tmpDir, 'target-repo');

  try {
    await mkdir(targetDir, { recursive: true });
    await writeFile(reportPath, [
      '# Fake',
      '',
      '## Evidence Leads',
      '- **[ws-1]** (conf=0.95) Benchmark promote lead | assets=src/app.py',
      '',
      '---',
    ].join('\n'));
    const targetPath = join(tmpDir, 'target.yaml');
    await writeFile(targetPath, [
      'id: benchmark-promote-test',
      'name: Benchmark Promote Test',
      'kind: code',
      'environment: sandbox',
      `repoRoot: ${targetDir}`,
    ].join('\n'));

    execSync('git init && git remote add origin https://github.com/test-owner/test-repo.git', {
      cwd: targetDir,
      encoding: 'utf8',
      timeout: 5000,
    });

    assert.throws(
      () => execSync(
        `node --import tsx ${CLI} --dry-run --verification-mode source --report ${reportPath} --target ${targetPath} --promote-benchmark-baseline`,
        { encoding: 'utf8', timeout: 15000 },
      ),
      /--promote-benchmark-baseline requires --benchmark-label/,
    );
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
});
