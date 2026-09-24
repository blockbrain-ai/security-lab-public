import test from 'node:test';
import assert from 'node:assert/strict';
import {
  redactBody,
  redactHeaders,
  redactSecretString,
  secretDigest,
} from '../shared/redaction.js';

test('redactHeaders replaces credential header values but keeps the names', () => {
  const redacted = redactHeaders({
    Authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij',
    Cookie: 'session=super-secret-session-value',
    'Content-Type': 'application/json',
    'X-Api-Key': 'sk-ant-abcdefghijklmnop',
  });

  assert.equal(redacted['Authorization'], `[redacted:${secretDigest('Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij')}]`);
  assert.match(String(redacted['Cookie']), /^\[redacted:[0-9a-f]{8}\]$/);
  assert.match(String(redacted['X-Api-Key']), /^\[redacted:[0-9a-f]{8}\]$/);
  assert.equal(redacted['Content-Type'], 'application/json', 'non-secret headers are preserved');
  assert.ok(!JSON.stringify(redacted).includes('super-secret-session-value'));
});

test('redactSecretString removes secret-shaped substrings from free text', () => {
  const text = [
    'token=sk-ant-abcdefghijklmnop',
    'Authorization: Bearer abcdefghijklmnop',
    '"password": "hunter2hunter2"',
    'AIzaSyA4Dh_abcdefghijklmnopqrstuvwx',
    'left alone: ordinary text',
  ].join('\n');

  const redacted = redactSecretString(text);
  assert.ok(!redacted.includes('sk-ant-abcdefghijklmnop'));
  assert.ok(!redacted.includes('hunter2hunter2'));
  assert.ok(!redacted.includes('AIzaSyA4Dh_abcdefghijklmnopqrstuvwx'));
  assert.ok(redacted.includes('ordinary text'));
});

test('redactBody reports truncation and redaction separately', () => {
  const short = redactBody('nothing secret here', 1000);
  assert.equal(short.truncated, false);
  assert.equal(short.redacted, false);

  const withSecret = redactBody('key=sk-ant-abcdefghijklmnop', 1000);
  assert.equal(withSecret.redacted, true);
  assert.ok(!withSecret.body.includes('sk-ant-abcdefghijklmnop'));

  const long = redactBody('x'.repeat(5000), 1000);
  assert.equal(long.truncated, true);
  assert.ok(Buffer.byteLength(long.body, 'utf8') <= 1000);
});

test('redactBody slices multi-byte content within the byte budget', () => {
  const result = redactBody('é'.repeat(1000), 101);
  assert.equal(result.truncated, true);
  assert.ok(Buffer.byteLength(result.body, 'utf8') <= 101);
});
