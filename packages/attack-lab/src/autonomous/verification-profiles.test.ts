import test from 'node:test';
import assert from 'node:assert/strict';
import {
  listVerificationProfiles,
  listLocalModelDescriptors,
  getVerificationProfile,
  resolveVerificationProfile,
  computeVerificationProfileFingerprint,
  VERIFICATION_PROFILES,
  LOCAL_MODEL_CATALOG,
} from './verification-profiles.js';

// ---------------------------------------------------------------------------
// Listing functions
// ---------------------------------------------------------------------------

test('listVerificationProfiles returns all built-in profiles', () => {
  const profiles = listVerificationProfiles();
  assert.equal(profiles.length, VERIFICATION_PROFILES.length);
  assert.ok(profiles.length >= 5);
  const ids = profiles.map((p) => p.id);
  assert.ok(ids.includes('qwen_default'));
  assert.ok(ids.includes('qwen_source_r1_critic'));
  assert.ok(ids.includes('r1_source_qwen_runtime'));
});

test('listVerificationProfiles returns a copy', () => {
  const a = listVerificationProfiles();
  const b = listVerificationProfiles();
  assert.notEqual(a, b);
});

test('listLocalModelDescriptors returns all catalog entries', () => {
  const models = listLocalModelDescriptors();
  assert.equal(models.length, LOCAL_MODEL_CATALOG.length);
  assert.ok(models.length >= 4);
  const ids = models.map((m) => m.id);
  assert.ok(ids.includes('qwen27_local'));
  assert.ok(ids.includes('r1_14b_local'));
  assert.ok(ids.includes('qwen14_local'));
  assert.ok(ids.includes('gemma12_local'));
});

// ---------------------------------------------------------------------------
// getVerificationProfile
// ---------------------------------------------------------------------------

test('getVerificationProfile returns correct profile', () => {
  const profile = getVerificationProfile('qwen_default');
  assert.ok(profile);
  assert.equal(profile.id, 'qwen_default');
  assert.equal(profile.source.model, 'qwen3.6-27b');
});

test('getVerificationProfile returns null for unknown id', () => {
  const profile = getVerificationProfile('nonexistent_profile');
  assert.equal(profile, null);
});

test('getVerificationProfile returns profile with sourceCritic', () => {
  const profile = getVerificationProfile('qwen_source_r1_critic');
  assert.ok(profile);
  assert.ok(profile.sourceCritic);
  assert.equal(profile.sourceCritic.model, 'deepseek-r1:14b');
});

// ---------------------------------------------------------------------------
// resolveVerificationProfile
// ---------------------------------------------------------------------------

test('resolveVerificationProfile with profile only applies defaults', () => {
  const profile = getVerificationProfile('qwen_default')!;
  const resolved = resolveVerificationProfile(profile, {});

  assert.equal(resolved.id, 'qwen_default');
  assert.equal(resolved.source.model, 'qwen3.6-27b');
  assert.equal(resolved.runtime.model, 'qwen3.6-27b');
  // sourceCritic defaults to source
  assert.equal(resolved.sourceCritic.model, 'qwen3.6-27b');
  // runtimeSetup defaults to runtime
  assert.equal(resolved.runtimeSetup.model, 'qwen3.6-27b');
  // runtimeProbe defaults to runtime
  assert.equal(resolved.runtimeProbe.model, 'qwen3.6-27b');
});

test('resolveVerificationProfile with profile that has sourceCritic', () => {
  const profile = getVerificationProfile('qwen_source_r1_critic')!;
  const resolved = resolveVerificationProfile(profile, {});

  assert.equal(resolved.source.model, 'qwen3.6-27b');
  assert.equal(resolved.sourceCritic.model, 'deepseek-r1:14b');
  assert.equal(resolved.sourceCritic.baseUrl, 'http://127.0.0.1:11434/v1');
});

test('resolveVerificationProfile CLI overrides win over profile', () => {
  const profile = getVerificationProfile('qwen_default')!;
  const resolved = resolveVerificationProfile(profile, {
    sourceModel: 'custom-model',
    sourceBaseUrl: 'http://127.0.0.1:9999/v1',
  });

  assert.equal(resolved.source.model, 'custom-model');
  assert.equal(resolved.source.baseUrl, 'http://127.0.0.1:9999/v1');
  // Runtime should still be from profile
  assert.equal(resolved.runtime.model, 'qwen3.6-27b');
});

test('resolveVerificationProfile sourceCritic override on profile with no critic', () => {
  const profile = getVerificationProfile('qwen_default')!;
  const resolved = resolveVerificationProfile(profile, {
    sourceCriticModel: 'deepseek-r1:14b',
    sourceCriticBaseUrl: 'http://127.0.0.1:11434/v1',
  });

  assert.equal(resolved.source.model, 'qwen3.6-27b');
  assert.equal(resolved.sourceCritic.model, 'deepseek-r1:14b');
  assert.equal(resolved.sourceCritic.baseUrl, 'http://127.0.0.1:11434/v1');
});

test('resolveVerificationProfile runtimeSetup/runtimeProbe overrides', () => {
  const profile = getVerificationProfile('qwen_default')!;
  const resolved = resolveVerificationProfile(profile, {
    runtimeSetupModel: 'setup-model',
    runtimeProbeModel: 'probe-model',
  });

  assert.equal(resolved.runtimeSetup.model, 'setup-model');
  assert.equal(resolved.runtimeProbe.model, 'probe-model');
  assert.equal(resolved.runtime.model, 'qwen3.6-27b');
});

test('resolveVerificationProfile with no profile uses defaults', () => {
  const resolved = resolveVerificationProfile(null, {
    sourceModel: 'test-model',
  });

  assert.equal(resolved.id, null);
  assert.equal(resolved.source.model, 'test-model');
  assert.equal(resolved.source.provider, 'bounded_local');
  assert.equal(resolved.runtime.model, 'qwen3.6-27b');
});

test('resolveVerificationProfile sourceCritic inherits from resolved source', () => {
  const resolved = resolveVerificationProfile(null, {
    sourceModel: 'custom-source',
    sourceBaseUrl: 'http://127.0.0.1:9999/v1',
  });

  assert.equal(resolved.sourceCritic.model, 'custom-source');
  assert.equal(resolved.sourceCritic.baseUrl, 'http://127.0.0.1:9999/v1');
});

test('resolveVerificationProfile runtimeSetup/Probe inherit from resolved runtime', () => {
  const resolved = resolveVerificationProfile(null, {
    runtimeModel: 'custom-runtime',
    runtimeBaseUrl: 'http://127.0.0.1:7777/v1',
  });

  assert.equal(resolved.runtimeSetup.model, 'custom-runtime');
  assert.equal(resolved.runtimeSetup.baseUrl, 'http://127.0.0.1:7777/v1');
  assert.equal(resolved.runtimeProbe.model, 'custom-runtime');
  assert.equal(resolved.runtimeProbe.baseUrl, 'http://127.0.0.1:7777/v1');
});

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

test('computeVerificationProfileFingerprint is deterministic', () => {
  const profile = getVerificationProfile('qwen_default')!;
  const resolved = resolveVerificationProfile(profile, {});
  const fp1 = computeVerificationProfileFingerprint(resolved);
  const fp2 = computeVerificationProfileFingerprint(resolved);
  assert.equal(fp1, fp2);
  assert.equal(fp1.length, 16);
});

test('computeVerificationProfileFingerprint changes when model changes', () => {
  const profile = getVerificationProfile('qwen_default')!;
  const resolved1 = resolveVerificationProfile(profile, {});
  const resolved2 = resolveVerificationProfile(profile, { sourceModel: 'different-model' });
  assert.notEqual(
    computeVerificationProfileFingerprint(resolved1),
    computeVerificationProfileFingerprint(resolved2),
  );
});

test('computeVerificationProfileFingerprint changes when critic changes', () => {
  const resolved1 = resolveVerificationProfile(getVerificationProfile('qwen_default')!, {});
  const resolved2 = resolveVerificationProfile(getVerificationProfile('qwen_source_r1_critic')!, {});
  assert.notEqual(
    computeVerificationProfileFingerprint(resolved1),
    computeVerificationProfileFingerprint(resolved2),
  );
});
