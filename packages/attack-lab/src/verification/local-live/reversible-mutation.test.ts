import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { MutationJournal, buildRollback } from './reversible-mutation.js';

describe('MutationJournal', () => {
  it('records pending mutations', () => {
    const journal = new MutationJournal();
    journal.record('seed canary record', { method: 'DELETE', path: '/api/test/seeds/123' });
    assert.equal(journal.getPendingRollbacks().length, 1);
  });

  it('rolls back via injected fetch', async () => {
    const journal = new MutationJournal();
    journal.record('seed canary record', { method: 'DELETE', path: '/api/test/seeds/123' });
    const fakeFetch = (async () =>
      ({ ok: true, status: 204 }) as unknown as Response) as unknown as typeof fetch;
    const result = await journal.rollbackAll('http://localhost', fakeFetch);
    assert.equal(result.succeeded, 1);
    assert.equal(result.failed, 0);
    assert.equal(journal.getPendingRollbacks().length, 0);
  });

  it('records failure when rollback returns non-2xx', async () => {
    const journal = new MutationJournal();
    journal.record('seed canary record', { method: 'DELETE', path: '/api/test/seeds/x' });
    const fakeFetch = (async () =>
      ({ ok: false, status: 500 }) as unknown as Response) as unknown as typeof fetch;
    const result = await journal.rollbackAll('http://localhost', fakeFetch);
    assert.equal(result.succeeded, 0);
    assert.equal(result.failed, 1);
  });
});

describe('buildRollback', () => {
  it('substitutes {created_id} in path', () => {
    const cmd = buildRollback(
      { strategy: 'api_cleanup', commands: [{ method: 'DELETE', path: '/api/seeds/{created_id}' }] },
      'abc',
    );
    assert.equal(cmd?.path, '/api/seeds/abc');
  });

  it('returns null when no commands provided', () => {
    assert.equal(buildRollback({ strategy: 'manual' }, 'x'), null);
  });
});
