import test from 'node:test';
import assert from 'node:assert/strict';
import { MAX_ARGV_PROMPT_BYTES, argvLimitError, promptExceedsArgvLimit } from './argv-limits.js';

test('promptExceedsArgvLimit allows normal prompts and rejects oversized ones', () => {
  assert.equal(promptExceedsArgvLimit('a'.repeat(1000)), false);
  assert.equal(promptExceedsArgvLimit('a'.repeat(MAX_ARGV_PROMPT_BYTES)), false);
  assert.equal(promptExceedsArgvLimit('a'.repeat(MAX_ARGV_PROMPT_BYTES + 1)), true);
});

test('promptExceedsArgvLimit measures bytes, not characters', () => {
  // Multi-byte characters must not slip past the limit.
  const multibyte = 'é'.repeat(MAX_ARGV_PROMPT_BYTES / 2 + 1);
  assert.equal(promptExceedsArgvLimit(multibyte), true);
});

test('argvLimitError names the provider, the size and the remedy', () => {
  const error = argvLimitError('SomeAdapter', 'a'.repeat(MAX_ARGV_PROMPT_BYTES + 1), 'Use brief mode.');
  assert.match(error.message, /SomeAdapter/);
  assert.match(error.message, /E2BIG/);
  assert.match(error.message, /Use brief mode\./);
});
