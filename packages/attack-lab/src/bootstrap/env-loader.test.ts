import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { loadSecurityLabEnvironment } from './env-loader.js';

test('loadSecurityLabEnvironment applies file precedence and normalizes Gemini aliases', async () => {
  const rootDir = await mkdtemp(resolve(tmpdir(), 'security-lab-env-'));
  const explicitEnv = resolve(rootDir, 'explicit.env');

  const originalEnv = {
    SECURITY_LAB_ENV_FILE: process.env['SECURITY_LAB_ENV_FILE'],
    GEMINI_API_KEY: process.env['GEMINI_API_KEY'],
    GOOGLE_AI_API_KEY: process.env['GOOGLE_AI_API_KEY'],
    SECURITY_LAB_TEST_VALUE: process.env['SECURITY_LAB_TEST_VALUE'],
  };

  await writeFile(resolve(rootDir, '.env.local'), 'SECURITY_LAB_TEST_VALUE=from_env_local\nGEMINI_API_KEY=gemini-alias\n', 'utf8');
  await writeFile(resolve(rootDir, '.env.security-lab.local'), 'SECURITY_LAB_TEST_VALUE=from_security_lab_local\n', 'utf8');
  await writeFile(resolve(rootDir, 'security-lab.env'), 'SECURITY_LAB_TEST_VALUE=from_security_lab_env_file\n', 'utf8');
  await writeFile(explicitEnv, 'SECURITY_LAB_TEST_VALUE=from_explicit_env_file\n', 'utf8');

  process.env['SECURITY_LAB_ENV_FILE'] = resolve(rootDir, 'security-lab.env');
  delete process.env['GEMINI_API_KEY'];
  delete process.env['GOOGLE_AI_API_KEY'];

  try {
    const loaded = await loadSecurityLabEnvironment({
      rootDir,
      envFile: explicitEnv,
    });

    assert.equal(process.env['SECURITY_LAB_TEST_VALUE'], 'from_explicit_env_file');
    assert.equal(process.env['GOOGLE_AI_API_KEY'], 'gemini-alias');
    assert.equal(process.env['GEMINI_API_KEY'], 'gemini-alias');
    assert.deepEqual(
      loaded.filesLoaded.map((file) => file.path),
      [
        resolve(rootDir, '.env.local'),
        resolve(rootDir, '.env.security-lab.local'),
        resolve(rootDir, 'security-lab.env'),
        explicitEnv,
      ],
    );
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
