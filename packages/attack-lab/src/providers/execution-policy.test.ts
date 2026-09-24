import test from 'node:test';
import assert from 'node:assert/strict';
import { createAdapter } from './adapter-factory.js';
import {
  HOST_EXECUTION_ENV_VAR,
  isHostExecutingProvider,
  resolveHostExecutionPolicy,
} from './execution-policy.js';
import { UnavailableAdapter, isUnavailableAdapter } from './unavailable-adapter.js';
import type { ModelConfig } from './contracts.js';

const HOST_PROVIDERS: Array<ModelConfig['provider']> = [
  'claude_code',
  'codex_cli',
  'pi_cli',
  'bounded_local',
];

function config(provider: ModelConfig['provider']): ModelConfig {
  return {
    provider,
    model: 'test-model',
    maxTokens: 256,
  } as ModelConfig;
}

test('host execution is disabled by default', () => {
  const policy = resolveHostExecutionPolicy({ env: {} });
  assert.equal(policy.allowed, false);
  assert.equal(policy.source, 'default');
});

test('host execution requires an explicit opt-in value', () => {
  for (const value of ['1', 'true', 'YES', 'on']) {
    const policy = resolveHostExecutionPolicy({ env: { [HOST_EXECUTION_ENV_VAR]: value } });
    assert.equal(policy.allowed, true, value);
    assert.equal(policy.source, 'env');
  }
  for (const value of ['0', 'false', '', 'nope']) {
    const policy = resolveHostExecutionPolicy({ env: { [HOST_EXECUTION_ENV_VAR]: value } });
    assert.equal(policy.allowed, false, value);
  }
});

test('an explicit decision overrides the environment', () => {
  assert.equal(
    resolveHostExecutionPolicy({ explicit: false, env: { [HOST_EXECUTION_ENV_VAR]: '1' } }).allowed,
    false,
  );
  assert.equal(resolveHostExecutionPolicy({ explicit: true, env: {} }).source, 'explicit');
});

test('the four host-executing providers are classified as such', () => {
  for (const provider of HOST_PROVIDERS) {
    assert.equal(isHostExecutingProvider(provider), true, provider);
  }
  for (const provider of ['anthropic', 'openai', 'gemini'] as const) {
    assert.equal(isHostExecutingProvider(provider), false, provider);
  }
});

test('createAdapter refuses every host-executing provider by default', () => {
  const policy = resolveHostExecutionPolicy({ env: {} });
  for (const provider of HOST_PROVIDERS) {
    const adapter = createAdapter(config(provider), { hostExecution: policy });
    assert.equal(isUnavailableAdapter(adapter), true, `${provider} must be refused`);
    assert.ok(adapter instanceof UnavailableAdapter);
    assert.match(adapter.reason, /disabled by default/);
    assert.match(adapter.reason, /--allow-host-execution/);
  }
});

test('createAdapter builds host-executing providers once opted in', () => {
  const policy = resolveHostExecutionPolicy({ explicit: true });
  for (const provider of HOST_PROVIDERS) {
    const adapter = createAdapter(config(provider), { hostExecution: policy });
    assert.equal(isUnavailableAdapter(adapter), false, `${provider} should be constructed`);
    assert.equal(adapter.provider, provider);
  }
});
