import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { ReportReplayer } from './report-replayer.js';

describe('ReportReplayer', () => {
  const replayer = new ReportReplayer();

  it('matches when replay produces identical findings', async () => {
    const result = await replayer.replay({
      reportId: 'r1',
      originalReport: { findings: [{ id: 'f1', verdict: 'confirmed' }] },
      rawEvidence: [],
      replayer: async () => ({ findings: [{ id: 'f1', verdict: 'confirmed' }] }),
    });
    assert.equal(result.matches, true);
    assert.equal(result.deltas.length, 0);
  });

  it('detects field divergence between original and replay', async () => {
    const result = await replayer.replay({
      reportId: 'r1',
      originalReport: { findings: [{ id: 'f1', verdict: 'confirmed' }] },
      rawEvidence: [],
      replayer: async () => ({ findings: [{ id: 'f1', verdict: 'refuted' }] }),
    });
    assert.equal(result.matches, false);
    assert.ok(result.deltas.some((d) => d.field === 'verdict'));
  });

  it('detects missing finding in replay', async () => {
    const result = await replayer.replay({
      reportId: 'r1',
      originalReport: { findings: [{ id: 'f1', verdict: 'confirmed' }] },
      rawEvidence: [],
      replayer: async () => ({ findings: [] }),
    });
    assert.ok(result.deltas.some((d) => d.field === 'existence'));
  });
});
