import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseSourceRef,
  formatSourceRef,
  toWorkspaceRelative,
  migrateStringRef,
  normalizeEvidenceRefs,
  type SourceLocationRef,
  type EvidenceRef,
} from './source-location-ref.js';

// ---------------------------------------------------------------------------
// parseSourceRef
// ---------------------------------------------------------------------------

test('parseSourceRef parses path:startLine-endLine format', () => {
  const ref = parseSourceRef('src/api/routes/approvals.ts:42-58');
  assert.deepEqual(ref, { path: 'src/api/routes/approvals.ts', startLine: 42, endLine: 58 });
});

test('parseSourceRef parses path:line single-line format', () => {
  const ref = parseSourceRef('src/foo.ts:10');
  assert.deepEqual(ref, { path: 'src/foo.ts', startLine: 10, endLine: undefined });
});

test('parseSourceRef returns undefined for invalid input', () => {
  assert.equal(parseSourceRef('no-colon-no-line'), undefined);
  assert.equal(parseSourceRef(''), undefined);
  assert.equal(parseSourceRef('file.ts:0'), undefined); // line 0 invalid (1-based)
  assert.equal(parseSourceRef('file.ts:abc'), undefined);
});

test('parseSourceRef rejects endLine < startLine', () => {
  assert.equal(parseSourceRef('file.ts:10-5'), undefined);
});

// ---------------------------------------------------------------------------
// formatSourceRef
// ---------------------------------------------------------------------------

test('formatSourceRef formats range refs', () => {
  const ref: SourceLocationRef = { path: 'src/api/handler.ts', startLine: 42, endLine: 58 };
  assert.equal(formatSourceRef(ref), 'src/api/handler.ts:42-58');
});

test('formatSourceRef formats single-line refs', () => {
  const ref: SourceLocationRef = { path: 'src/foo.ts', startLine: 10 };
  assert.equal(formatSourceRef(ref), 'src/foo.ts:10');
});

test('formatSourceRef omits endLine when equal to startLine', () => {
  const ref: SourceLocationRef = { path: 'src/foo.ts', startLine: 10, endLine: 10 };
  assert.equal(formatSourceRef(ref), 'src/foo.ts:10');
});

// ---------------------------------------------------------------------------
// toWorkspaceRelative
// ---------------------------------------------------------------------------

test('toWorkspaceRelative strips workspace root prefix', () => {
  const result = toWorkspaceRelative('/home/user/project/src/foo.ts', '/home/user/project');
  assert.equal(result, 'src/foo.ts');
});

test('toWorkspaceRelative handles trailing slash on root', () => {
  const result = toWorkspaceRelative('/home/user/project/src/foo.ts', '/home/user/project/');
  assert.equal(result, 'src/foo.ts');
});

test('toWorkspaceRelative returns relative paths unchanged', () => {
  const result = toWorkspaceRelative('src/foo.ts', '/home/user/project');
  assert.equal(result, 'src/foo.ts');
});

test('toWorkspaceRelative strips leading slash for paths outside workspace', () => {
  const result = toWorkspaceRelative('/other/path/foo.ts', '/home/user/project');
  assert.equal(result, 'other/path/foo.ts');
});

// ---------------------------------------------------------------------------
// migrateStringRef
// ---------------------------------------------------------------------------

test('migrateStringRef wraps ws-* as signal', () => {
  const ref = migrateStringRef('ws-3-28');
  assert.deepEqual(ref, { kind: 'signal', id: 'ws-3-28' });
});

test('migrateStringRef wraps ph-* as hypothesis', () => {
  const ref = migrateStringRef('ph-5-12');
  assert.deepEqual(ref, { kind: 'hypothesis', id: 'ph-5-12' });
});

test('migrateStringRef wraps finding-* as finding', () => {
  const ref = migrateStringRef('finding-1');
  assert.deepEqual(ref, { kind: 'finding', id: 'finding-1' });
});

test('migrateStringRef wraps exp-* as probe', () => {
  const ref = migrateStringRef('exp-test-abc');
  assert.deepEqual(ref, { kind: 'probe', id: 'exp-test-abc' });
});

test('migrateStringRef defaults to signal for unrecognized formats', () => {
  const ref = migrateStringRef('unknown-ref-42');
  assert.deepEqual(ref, { kind: 'signal', id: 'unknown-ref-42' });
});

// ---------------------------------------------------------------------------
// normalizeEvidenceRefs
// ---------------------------------------------------------------------------

test('normalizeEvidenceRefs converts mixed string/object arrays', () => {
  const input: Array<string | EvidenceRef> = [
    'ws-1-2',
    'src/handler.ts:10-20',
    { kind: 'probe', id: 'probe-99' },
  ];
  const result = normalizeEvidenceRefs(input);
  assert.equal(result.length, 3);
  assert.deepEqual(result[0], { kind: 'signal', id: 'ws-1-2' });
  assert.deepEqual(result[1], {
    kind: 'source',
    location: { path: 'src/handler.ts', startLine: 10, endLine: 20 },
  });
  assert.deepEqual(result[2], { kind: 'probe', id: 'probe-99' });
});

test('normalizeEvidenceRefs passes through EvidenceRef objects unchanged', () => {
  const ref: EvidenceRef = { kind: 'finding', id: 'finding-1' };
  const result = normalizeEvidenceRefs([ref]);
  assert.deepEqual(result[0], ref);
});

// ---------------------------------------------------------------------------
// Schema version (v3)
// ---------------------------------------------------------------------------

test('EVIDENCE_SCHEMA_VERSION is 3', async () => {
  const { EVIDENCE_SCHEMA_VERSION } = await import('./contracts.js');
  assert.equal(EVIDENCE_SCHEMA_VERSION, 3);
});
