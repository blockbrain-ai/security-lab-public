import test from 'node:test';
import assert from 'node:assert/strict';
import { escapesTargetHost, resolveRequestUrl } from './url-policy.js';

const BASE = 'http://127.0.0.1:3000';

test('relative paths resolve against the target', () => {
  assert.equal(resolveRequestUrl('/health', BASE), 'http://127.0.0.1:3000/health');
  assert.equal(resolveRequestUrl('api/records/1', BASE), 'http://127.0.0.1:3000/api/records/1');
  assert.equal(resolveRequestUrl('?probe=1', BASE), 'http://127.0.0.1:3000/?probe=1');
});

test('an absolute URL on the target host is allowed', () => {
  assert.equal(resolveRequestUrl('http://127.0.0.1:3000/admin', BASE), 'http://127.0.0.1:3000/admin');
});

test('an absolute URL on another host is refused', () => {
  // The classic case: a model-supplied "path" pointing at cloud metadata.
  assert.throws(
    () => resolveRequestUrl('http://169.254.169.254/latest/meta-data/', BASE),
    /different host/,
  );
  assert.throws(() => resolveRequestUrl('https://evil.example.com/steal', BASE), /different host/);
  // Same hostname, different port is still a different host.
  assert.throws(() => resolveRequestUrl('http://127.0.0.1:9999/admin', BASE), /different host/);
});

test('non-web schemes are refused', () => {
  for (const candidate of ['file:///etc/passwd', 'data:text/html,<h1>x', 'ftp://host/x', 'gopher://host/1']) {
    assert.throws(() => resolveRequestUrl(candidate, BASE), /unsupported scheme|different host/, candidate);
  }
});

test('cross-origin is permitted only when the caller declares it', () => {
  assert.equal(
    resolveRequestUrl('https://evil.example.com/csrf', BASE, { allowCrossOrigin: true }),
    'https://evil.example.com/csrf',
  );
  // Declaring cross-origin does not open up non-web schemes.
  assert.throws(() => resolveRequestUrl('file:///etc/passwd', BASE, { allowCrossOrigin: true }), /unsupported scheme/);
});

test('the browser lane may swap http for ws on the same host', () => {
  assert.equal(resolveRequestUrl('/socket', 'ws://127.0.0.1:3000'), 'ws://127.0.0.1:3000/socket');
  assert.throws(() => resolveRequestUrl('ws://127.0.0.1:4000/socket', 'ws://127.0.0.1:3000'), /different host/);
});

test('empty and malformed inputs fail with a labelled message', () => {
  assert.throws(() => resolveRequestUrl('', BASE, { label: 'probe path' }), /probe path is empty/);
  assert.throws(() => resolveRequestUrl('/x', 'not-a-url', { label: 'probe path' }), /probe path cannot be resolved/);
});

test('escapesTargetHost reports the policy decision', () => {
  assert.equal(escapesTargetHost('/health', BASE), false);
  assert.equal(escapesTargetHost('http://169.254.169.254/', BASE), true);
});
