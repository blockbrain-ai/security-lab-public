import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveRoleConfig } from './cli-role-config.js';

test('resolveRoleConfig preserves local transport defaults when the role stays unchanged', () => {
  const config = resolveRoleConfig(
    {
      provider: 'openai',
      model: 'qwen3.6-27b',
      baseUrl: 'http://localhost:8080/v1',
      maxTokens: 16_384,
      requestTimeoutMs: 180_000,
    },
    {
      workingDirectory: '/tmp/work',
      additionalDirectories: ['/tmp/campaigns'],
    },
  );

  assert.equal(config.provider, 'openai');
  assert.equal(config.model, 'qwen3.6-27b');
  assert.equal(config.baseUrl, 'http://localhost:8080/v1');
  assert.equal(config.maxTokens, 16_384);
  assert.equal(config.workingDirectory, '/tmp/work');
  assert.deepEqual(config.additionalDirectories, ['/tmp/campaigns']);
});

test('resolveRoleConfig clears local transport defaults when provider/model overrides change the role', () => {
  const config = resolveRoleConfig(
    {
      provider: 'openai',
      model: 'qwen3.6-27b',
      baseUrl: 'http://localhost:8080/v1',
      maxTokens: 16_384,
      requestTimeoutMs: 180_000,
    },
    {
      providerOverride: 'anthropic',
      modelOverride: 'claude-sonnet-4-6',
      workingDirectory: '/tmp/work',
      additionalDirectories: ['/tmp/campaigns'],
    },
  );

  assert.equal(config.provider, 'anthropic');
  assert.equal(config.model, 'claude-sonnet-4-6');
  assert.equal(config.baseUrl, undefined);
  assert.equal(config.maxTokens, undefined);
  assert.equal(config.requestTimeoutMs, 180_000);
});

test('resolveRoleConfig keeps explicit transport overrides for alternate local models', () => {
  const config = resolveRoleConfig(
    {
      provider: 'openai',
      model: 'qwen3.6-27b',
      baseUrl: 'http://localhost:8080/v1',
      maxTokens: 16_384,
    },
    {
      modelOverride: 'qwen3.6-32b',
      baseUrlOverride: 'http://localhost:9000/v1',
      maxTokensOverride: 32_768,
      workingDirectory: '/tmp/work',
      additionalDirectories: ['/tmp/campaigns'],
    },
  );

  assert.equal(config.provider, 'openai');
  assert.equal(config.model, 'qwen3.6-32b');
  assert.equal(config.baseUrl, 'http://localhost:9000/v1');
  assert.equal(config.maxTokens, 32_768);
});

test('resolveRoleConfig preserves Codex local transport defaults when the role stays unchanged', () => {
  const config = resolveRoleConfig(
    {
      provider: 'codex_cli',
      model: 'qwen3.6:27b',
      localInference: true,
      cliLocalProvider: 'ollama',
      cliProfile: 'local-qwen',
      requestTimeoutMs: 900_000,
    },
    {
      workingDirectory: '/tmp/work',
      additionalDirectories: ['/tmp/campaigns'],
    },
  );

  assert.equal(config.provider, 'codex_cli');
  assert.equal(config.model, 'qwen3.6:27b');
  assert.equal(config.localInference, true);
  assert.equal(config.cliLocalProvider, 'ollama');
  assert.equal(config.cliProfile, 'local-qwen');
});

test('resolveRoleConfig clears Codex local transport defaults when provider/model overrides change the role', () => {
  const config = resolveRoleConfig(
    {
      provider: 'codex_cli',
      model: 'qwen3.6:27b',
      localInference: true,
      cliLocalProvider: 'ollama',
      cliProfile: 'local-qwen',
      requestTimeoutMs: 900_000,
    },
    {
      providerOverride: 'anthropic',
      modelOverride: 'claude-sonnet-4-6',
      workingDirectory: '/tmp/work',
      additionalDirectories: ['/tmp/campaigns'],
    },
  );

  assert.equal(config.provider, 'anthropic');
  assert.equal(config.model, 'claude-sonnet-4-6');
  assert.equal(config.localInference, undefined);
  assert.equal(config.cliLocalProvider, undefined);
  assert.equal(config.cliProfile, undefined);
});

test('resolveRoleConfig keeps explicit Codex local transport overrides for alternate local models', () => {
  const config = resolveRoleConfig(
    {
      provider: 'codex_cli',
      model: 'qwen3.6:27b',
      localInference: true,
      cliLocalProvider: 'ollama',
    },
    {
      modelOverride: 'qwen3.6:27b-alt',
      localInferenceOverride: true,
      cliLocalProviderOverride: 'lmstudio',
      cliProfileOverride: 'lmstudio-local',
      workingDirectory: '/tmp/work',
      additionalDirectories: ['/tmp/campaigns'],
    },
  );

  assert.equal(config.provider, 'codex_cli');
  assert.equal(config.model, 'qwen3.6:27b-alt');
  assert.equal(config.localInference, true);
  assert.equal(config.cliLocalProvider, 'lmstudio');
  assert.equal(config.cliProfile, 'lmstudio-local');
});
