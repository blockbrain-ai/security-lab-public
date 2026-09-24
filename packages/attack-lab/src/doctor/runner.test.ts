import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { runDoctor } from './runner.js';

async function createFakeBinary(binDir: string, name: string, body: string): Promise<void> {
  const filePath = resolve(binDir, name);
  await writeFile(filePath, `#!/bin/sh\n${body}\n`, 'utf8');
  await chmod(filePath, 0o755);
}

test('runDoctor passes serious-local prerequisites with fake CLIs, docker, and fixture auth bootstrap', { concurrency: false }, async () => {
  const tempRoot = await mkdtemp(resolve(tmpdir(), 'security-lab-doctor-pass-'));
  const fakeBin = resolve(tempRoot, 'bin');
  await mkdir(fakeBin, { recursive: true });

  await createFakeBinary(
    fakeBin,
    'claude',
    `
if [ "$1" = "--version" ]; then
  echo "claude 9.9.9"
  exit 0
fi
if [ "$1" = "auth" ] && [ "$2" = "status" ]; then
  echo "authenticated"
  exit 0
fi
exit 1
`,
  );
  await createFakeBinary(
    fakeBin,
    'codex',
    `
if [ "$1" = "--version" ]; then
  echo "codex 9.9.9"
  exit 0
fi
if [ "$1" = "login" ] && [ "$2" = "status" ]; then
  echo "logged in"
  exit 0
fi
exit 1
`,
  );
  await createFakeBinary(
    fakeBin,
    'docker',
    `
if [ "$1" = "info" ]; then
  echo "docker ok"
  exit 0
fi
exit 1
`,
  );

  const originalEnv = {
    PATH: process.env['PATH'],
    OPENAI_API_KEY: process.env['OPENAI_API_KEY'],
    GOOGLE_AI_API_KEY: process.env['GOOGLE_AI_API_KEY'],
    GEMINI_API_KEY: process.env['GEMINI_API_KEY'],
    TARGET_REPO_ROOT: process.env['TARGET_REPO_ROOT'],
  };

  process.env['PATH'] = `${fakeBin}:${originalEnv.PATH ?? ''}`;
  process.env['OPENAI_API_KEY'] = 'test-openai';
  process.env['GOOGLE_AI_API_KEY'] = 'test-gemini';
  process.env['TARGET_REPO_ROOT'] = '/tmp/fake-fixture-workspace';

  try {
    const result = await runDoctor({
      preset: 'serious-local',
      targetRef: 'targets/fixture-static.yaml',
      liveTargetRef: 'targets/fixture-local-live-linux.yaml',
      linuxRuntime: 'container',
    });

    assert.equal(result.ok, true);
    assert.equal(result.checks.every((check) => check.status !== 'fail'), true);
    assert.ok(result.checks.find((check) => check.id === 'claude_binary' && check.status === 'pass'));
    assert.ok(result.checks.find((check) => check.id === 'codex_binary' && check.status === 'pass'));
    assert.ok(result.checks.find((check) => check.id === 'docker_daemon' && check.status === 'pass'));
    assert.ok(result.checks.find((check) => check.id === 'openai_api_key' && check.status === 'pass'));
    assert.ok(result.checks.find((check) => check.id === 'google_ai_api_key' && check.status === 'pass'));
    const bootstrap = result.checks.find((check) => check.id === 'local_auth_bootstrap');
    assert.ok(bootstrap);
    assert.equal(bootstrap?.status, 'pass');
    assert.match(bootstrap?.details ?? '', /user_a_low/);
    assert.equal(result.liveTarget?.id, 'fixture-local-live-linux');
  } finally {
    for (const [key, value] of Object.entries(originalEnv)) {
      if (value == null) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
});

test('runDoctor fails serious-local checks when keys are missing and docker is unavailable', { concurrency: false }, async () => {
  const tempRoot = await mkdtemp(resolve(tmpdir(), 'security-lab-doctor-fail-'));
  const fakeBin = resolve(tempRoot, 'bin');
  await mkdir(fakeBin, { recursive: true });

  await createFakeBinary(
    fakeBin,
    'claude',
    `
if [ "$1" = "--version" ]; then
  echo "claude 9.9.9"
  exit 0
fi
if [ "$1" = "auth" ] && [ "$2" = "status" ]; then
  echo "authenticated"
  exit 0
fi
exit 1
`,
  );
  await createFakeBinary(
    fakeBin,
    'codex',
    `
if [ "$1" = "--version" ]; then
  echo "codex 9.9.9"
  exit 0
fi
if [ "$1" = "login" ] && [ "$2" = "status" ]; then
  echo "logged in"
  exit 0
fi
exit 1
`,
  );
  await createFakeBinary(
    fakeBin,
    'docker',
    `
exit 1
`,
  );

  const originalEnv = {
    PATH: process.env['PATH'],
    OPENAI_API_KEY: process.env['OPENAI_API_KEY'],
    GOOGLE_AI_API_KEY: process.env['GOOGLE_AI_API_KEY'],
    GEMINI_API_KEY: process.env['GEMINI_API_KEY'],
    TARGET_REPO_ROOT: process.env['TARGET_REPO_ROOT'],
  };

  process.env['PATH'] = `${fakeBin}:${originalEnv.PATH ?? ''}`;
  delete process.env['OPENAI_API_KEY'];
  delete process.env['GOOGLE_AI_API_KEY'];
  delete process.env['GEMINI_API_KEY'];
  process.env['TARGET_REPO_ROOT'] = '/tmp/fake-fixture-workspace';

  try {
    const result = await runDoctor({
      preset: 'serious-local',
      liveTargetRef: 'targets/fixture-local-live-linux.yaml',
      linuxRuntime: 'container',
    });

    assert.equal(result.ok, false);
    assert.ok(result.checks.find((check) => check.id === 'openai_api_key' && check.status === 'fail'));
    assert.ok(result.checks.find((check) => check.id === 'google_ai_api_key' && check.status === 'fail'));
    assert.ok(result.checks.find((check) => check.id === 'docker_daemon' && check.status === 'fail'));
  } finally {
    for (const [key, value] of Object.entries(originalEnv)) {
      if (value == null) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
});
