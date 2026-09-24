import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runEvidenceProbe } from './evidence-probe.js';

test('runEvidenceProbe detects manifest tampering and baseline drift', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-evidence-probe-'));

  try {
    const evidenceFile = join(root, 'notes.txt');
    await writeFile(evidenceFile, 'original', 'utf8');
    const originalHash = createHash('sha256').update('original').digest('hex');

    const manifestPath = join(root, 'manifest.json');
    await writeFile(
      manifestPath,
      JSON.stringify({
        files: {
          'notes.txt': originalHash,
          'missing.txt': originalHash,
        },
      }),
      'utf8',
    );

    await writeFile(evidenceFile, 'tampered', 'utf8');

    const manifest = await runEvidenceProbe(
      { kind: 'evidence_check', action: 'manifest_verify', filePath: 'manifest.json', timeoutMs: 1000 },
      root,
    );
    assert.equal(manifest.exitCode, 1);
    assert.match(manifest.stdout ?? '', /TAMPERED:/i);
    assert.match(manifest.stdout ?? '', /MISSING:/i);

    const baseline = await runEvidenceProbe(
      {
        kind: 'evidence_check',
        action: 'baseline_drift',
        filePath: 'notes.txt',
        expectedHashes: { 'notes.txt': originalHash },
        timeoutMs: 1000,
      },
      root,
    );
    assert.equal(baseline.exitCode, 1);
    assert.match(baseline.stdout ?? '', /DRIFT:/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('runEvidenceProbe flags writable truth-label files', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-evidence-label-'));

  try {
    await writeFile(join(root, 'labels.json'), '{"truth":"mutable"}', 'utf8');

    const result = await runEvidenceProbe(
      { kind: 'evidence_check', action: 'label_writability', filePath: 'labels.json', timeoutMs: 1000 },
      root,
    );

    assert.equal(result.exitCode, 1);
    assert.match(result.stdout ?? '', /WRITABLE:/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
