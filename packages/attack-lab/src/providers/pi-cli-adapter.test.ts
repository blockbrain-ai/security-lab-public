import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { PiCliAdapter } from './pi-cli-adapter.js';

test('PiCliAdapter returns final text from Pi print mode output', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'pi-cli-basic-'));
  const binaryPath = resolve(dir, 'pi');
  await writeFile(
    binaryPath,
    `#!/bin/sh
echo '{"answer":"hello"}'
`,
    'utf8',
  );
  await chmod(binaryPath, 0o755);

  const adapter = new PiCliAdapter({
    provider: 'pi_cli',
    model: 'qwen3.6-27b',
    binaryPath,
    baseUrl: 'http://localhost:8080/v1',
  });

  const result = await adapter.invoke({ prompt: 'Say hello.' });

  assert.equal(result.provider, 'pi_cli');
  assert.equal(result.model, 'qwen3.6-27b');
  assert.equal(result.content, '{"answer":"hello"}');
  assert.equal(result.usage.costUsd, 0);
});

test('PiCliAdapter generates isolated config dir with models.json', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'pi-cli-config-'));
  const binaryPath = resolve(dir, 'pi');
  const configCapturePath = resolve(dir, 'config-dir.txt');
  await writeFile(
    binaryPath,
    `#!/bin/sh
echo "$PI_CODING_AGENT_DIR" > ${JSON.stringify(configCapturePath)}
echo "ok"
`,
    'utf8',
  );
  await chmod(binaryPath, 0o755);

  const adapter = new PiCliAdapter({
    provider: 'pi_cli',
    model: 'test-model-id',
    binaryPath,
    baseUrl: 'http://localhost:9999/v1',
    piProviderName: 'test-provider',
  });

  await adapter.invoke({ prompt: 'Test config.' });

  const configDir = (await readFile(configCapturePath, 'utf8')).trim();
  assert.ok(configDir.length > 0, 'PI_CODING_AGENT_DIR should be set');

  const modelsJson = JSON.parse(await readFile(join(configDir, 'models.json'), 'utf8'));
  assert.ok(modelsJson.providers['test-provider'], 'provider should match piProviderName');
  assert.equal(modelsJson.providers['test-provider'].baseUrl, 'http://localhost:9999/v1');
  assert.equal(modelsJson.providers['test-provider'].models[0].id, 'test-model-id');
});

test('PiCliAdapter injects the worker contract into the prompt', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'pi-cli-contract-'));
  const binaryPath = resolve(dir, 'pi');
  const promptCapturePath = resolve(dir, 'prompt.txt');
  await writeFile(
    binaryPath,
    `#!/bin/sh
last=""
for arg in "$@"; do
  last="$arg"
done
printf '%s' "$last" > ${JSON.stringify(promptCapturePath)}
echo "ok"
`,
    'utf8',
  );
  await chmod(binaryPath, 0o755);

  const adapter = new PiCliAdapter({
    provider: 'pi_cli',
    model: 'qwen3.6-27b',
    binaryPath,
  });

  await adapter.invoke({
    systemPrompt: 'Return JSON.',
    prompt: 'Inspect the repo.',
  });

  const prompt = await readFile(promptCapturePath, 'utf8');
  assert.match(prompt, /must not invoke Security Lab recursively/i);
  assert.match(prompt, /must not send probes to authorized live or hosted targets/i);
  assert.match(prompt, /Return JSON/);
  assert.match(prompt, /Inspect the repo/);
});

test('PiCliAdapter reports zero cost for local inference', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'pi-cli-cost-'));
  const binaryPath = resolve(dir, 'pi');
  await writeFile(
    binaryPath,
    `#!/bin/sh
echo "response text"
`,
    'utf8',
  );
  await chmod(binaryPath, 0o755);

  const adapter = new PiCliAdapter({
    provider: 'pi_cli',
    model: 'qwen3.6-27b',
    binaryPath,
    localInference: true,
  });

  const result = await adapter.invoke({ prompt: 'Test.' });
  assert.equal(result.usage.costUsd, 0);
});

test('PiCliAdapter propagates timeout to subprocess', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'pi-cli-timeout-'));
  const binaryPath = resolve(dir, 'pi');
  await writeFile(
    binaryPath,
    `#!/bin/sh
sleep 60
echo "should not reach"
`,
    'utf8',
  );
  await chmod(binaryPath, 0o755);

  const adapter = new PiCliAdapter({
    provider: 'pi_cli',
    model: 'qwen3.6-27b',
    binaryPath,
    requestTimeoutMs: 500,
  });

  await assert.rejects(
    adapter.invoke({ prompt: 'Timeout test.' }),
    (err: Error) => {
      // execFile timeout kills the process
      return err !== undefined;
    },
  );
});

test('PiCliAdapter throws clear error when Pi binary is missing', async () => {
  const adapter = new PiCliAdapter({
    provider: 'pi_cli',
    model: 'qwen3.6-27b',
    binaryPath: '/nonexistent/pi-binary',
  });

  await assert.rejects(
    adapter.invoke({ prompt: 'Test.' }),
    /Pi binary not found/,
  );
});

test('PiCliAdapter passes --tools flag when piToolAllowlist is set', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'pi-cli-tools-'));
  const binaryPath = resolve(dir, 'pi');
  const argsCapturePath = resolve(dir, 'args.txt');
  await writeFile(
    binaryPath,
    `#!/bin/sh
printf '%s\\n' "$@" > ${JSON.stringify(argsCapturePath)}
echo "ok"
`,
    'utf8',
  );
  await chmod(binaryPath, 0o755);

  const adapter = new PiCliAdapter({
    provider: 'pi_cli',
    model: 'qwen3.6-27b',
    binaryPath,
    piToolAllowlist: ['read', 'grep', 'find', 'ls', 'bash'],
  });

  await adapter.invoke({ prompt: 'Test tools.' });

  const args = await readFile(argsCapturePath, 'utf8');
  assert.match(args, /--tools/);
  assert.match(args, /read,grep,find,ls,bash/);
});

test('PiCliAdapter uses piMaxTokens in generated models.json', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'pi-cli-maxtok-'));
  const binaryPath = resolve(dir, 'pi');
  const configCapturePath = resolve(dir, 'config-dir.txt');
  await writeFile(
    binaryPath,
    `#!/bin/sh
echo "$PI_CODING_AGENT_DIR" > ${JSON.stringify(configCapturePath)}
echo "ok"
`,
    'utf8',
  );
  await chmod(binaryPath, 0o755);

  const adapter = new PiCliAdapter({
    provider: 'pi_cli',
    model: 'qwen3.6-27b',
    binaryPath,
    piMaxTokens: 8192,
  });

  await adapter.invoke({ prompt: 'Test tokens.' });

  const configDir = (await readFile(configCapturePath, 'utf8')).trim();
  const modelsJson = JSON.parse(await readFile(join(configDir, 'models.json'), 'utf8'));
  const modelEntry = Object.values(modelsJson.providers as Record<string, { models: Array<{ maxTokens: number }> }>)[0].models[0];
  assert.equal(modelEntry.maxTokens, 8192);
});

test('PiCliAdapter defaults piMaxTokens to 16384', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'pi-cli-deftok-'));
  const binaryPath = resolve(dir, 'pi');
  const configCapturePath = resolve(dir, 'config-dir.txt');
  await writeFile(
    binaryPath,
    `#!/bin/sh
echo "$PI_CODING_AGENT_DIR" > ${JSON.stringify(configCapturePath)}
echo "ok"
`,
    'utf8',
  );
  await chmod(binaryPath, 0o755);

  const adapter = new PiCliAdapter({
    provider: 'pi_cli',
    model: 'qwen3.6-27b',
    binaryPath,
  });

  await adapter.invoke({ prompt: 'Test default tokens.' });

  const configDir = (await readFile(configCapturePath, 'utf8')).trim();
  const modelsJson = JSON.parse(await readFile(join(configDir, 'models.json'), 'utf8'));
  const modelEntry = Object.values(modelsJson.providers as Record<string, { models: Array<{ maxTokens: number }> }>)[0].models[0];
  assert.equal(modelEntry.maxTokens, 16384);
});

test('PiCliAdapter uses --mode json when piOutputMode is json', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'pi-cli-mode-'));
  const binaryPath = resolve(dir, 'pi');
  const argsCapturePath = resolve(dir, 'args.txt');
  await writeFile(
    binaryPath,
    `#!/bin/sh
printf '%s\\n' "$@" > ${JSON.stringify(argsCapturePath)}
echo "ok"
`,
    'utf8',
  );
  await chmod(binaryPath, 0o755);

  const adapter = new PiCliAdapter({
    provider: 'pi_cli',
    model: 'qwen3.6-27b',
    binaryPath,
    piOutputMode: 'json',
  });

  await adapter.invoke({ prompt: 'Test mode.' });

  const args = await readFile(argsCapturePath, 'utf8');
  assert.match(args, /--mode/);
  assert.match(args, /json/);
  // Should NOT contain -p (print mode) when using json mode
  const lines = args.split('\n').filter(Boolean);
  assert.ok(!lines.includes('-p'), 'should not use -p in json mode');
});
