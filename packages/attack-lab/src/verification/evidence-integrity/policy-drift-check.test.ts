import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { PolicyDriftCheck, snapshotPolicy } from './policy-drift-check.js';

describe('PolicyDriftCheck', () => {
  const check = new PolicyDriftCheck();

  it('returns null when snapshots are identical', () => {
    const a = snapshotPolicy('1.0', { rule: 'a' }, { rubric: 'r' });
    const b = snapshotPolicy('1.0', { rule: 'a' }, { rubric: 'r' });
    assert.equal(check.compare(a, b), null);
  });

  it('flags rubric change as high severity', () => {
    const a = snapshotPolicy('1.0', { rule: 'a' }, { rubric: 'r' });
    const b = snapshotPolicy('1.0', { rule: 'a' }, { rubric: 'r2' });
    const drift = check.compare(a, b);
    assert.equal(drift?.severity, 'high');
    assert.ok(drift?.changedFields.includes('rubricHash'));
  });

  it('flags policy hash change as medium severity', () => {
    const a = snapshotPolicy('1.0', { rule: 'a' }, { rubric: 'r' });
    const b = snapshotPolicy('1.0', { rule: 'b' }, { rubric: 'r' });
    const drift = check.compare(a, b);
    assert.equal(drift?.severity, 'medium');
  });
});
