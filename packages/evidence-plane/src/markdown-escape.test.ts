import test from 'node:test';
import assert from 'node:assert/strict';
import {
  escapeMarkdownBlock,
  escapeMarkdownLine,
  renderCodeSpan,
} from './markdown-escape.js';

test('escapeMarkdownBlock neutralises block-level constructs on every line', () => {
  const escaped = escapeMarkdownBlock('first line\n## Injected Section\n- forged bullet\n1. forged item');

  assert.equal(
    escaped,
    'first line\n\\## Injected Section\n\\- forged bullet\n1\\. forged item',
  );
  assert.doesNotMatch(escaped, /^## Injected Section$/m);
  assert.doesNotMatch(escaped, /^- forged bullet$/m);
});

test('escapeMarkdownBlock escapes raw HTML, pipes, backticks and brackets', () => {
  const escaped = escapeMarkdownBlock('<img src=x onerror=alert(1)> | `tick` | [link](http://evil.test)');

  assert.equal(
    escaped,
    '&lt;img src=x onerror=alert(1)&gt; \\| \\`tick\\` \\| \\[link\\](http://evil.test)',
  );
  assert.doesNotMatch(escaped, /<img/);
});

test('escapeMarkdownBlock doubles backslashes so escaping cannot be neutralised', () => {
  // A lone backslash before a pipe would otherwise re-enable the table break.
  assert.equal(escapeMarkdownBlock('a\\|b'), 'a\\\\\\|b');
});

test('escapeMarkdownLine collapses line breaks so table cells and headings stay on one line', () => {
  const escaped = escapeMarkdownLine('value\n## Injected Section');

  assert.equal(escaped, 'value ## Injected Section');
  assert.doesNotMatch(escaped, /\n/);
});

test('escapeMarkdownLine escapes a structural marker at the start of the value', () => {
  assert.equal(escapeMarkdownLine('# heading'), '\\# heading');
  assert.equal(escapeMarkdownLine('---'), '\\---');
  assert.equal(escapeMarkdownLine('~~~'), '\\~~~');
  assert.equal(escapeMarkdownLine('2) item'), '2\\) item');
  assert.equal(escapeMarkdownLine('> quote'), '&gt; quote');
});

test('escapeMarkdownLine leaves ordinary prose untouched', () => {
  assert.equal(
    escapeMarkdownLine('Auth becomes opt-in when BOS_JWT_SECRET is unset.'),
    'Auth becomes opt-in when BOS_JWT_SECRET is unset.',
  );
});

test('renderCodeSpan grows the fence around embedded backticks', () => {
  assert.equal(renderCodeSpan('src/api/routes/approvals.ts:42-58'), '`src/api/routes/approvals.ts:42-58`');
  assert.equal(renderCodeSpan('src/a`b.ts:1'), '``src/a`b.ts:1``');
  assert.equal(renderCodeSpan('a``b'), '```a``b```');
});

test('renderCodeSpan pads content that starts or ends with a backtick or space', () => {
  assert.equal(renderCodeSpan('`tick'), '`` `tick ``');
  assert.equal(renderCodeSpan(' tick '), '`  tick  `');
  assert.equal(renderCodeSpan(''), '``');
});

test('renderCodeSpan escapes pipes so a GFM table cell cannot be split', () => {
  assert.equal(renderCodeSpan('a|b'), '`a\\|b`');
});
