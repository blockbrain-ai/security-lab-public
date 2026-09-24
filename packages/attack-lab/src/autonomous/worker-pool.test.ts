import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { executeProbeBatch } from './worker-pool.js';

test('executeProbeBatch returns probe results in stable input order', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-worker-pool-'));

  try {
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(join(root, 'src', 'a.ts'), 'export const a = 1;\n', 'utf8');
    await writeFile(join(root, 'src', 'b.ts'), 'export const b = 2;\n', 'utf8');

    const target = {
      id: 'fixture',
      name: 'fixture',
      kind: 'code' as const,
      environment: 'sandbox' as const,
      repoRoot: root,
      hints: {},
      supportedProbeKinds: ['code_read'],
    };

    const results = await executeProbeBatch(
      [
        {
          index: 1,
          target,
          probe: {
            fingerprint: 'p2',
            kind: 'code_read',
            parameters: { action: 'read_file', filePath: 'src/b.ts', timeoutMs: 1000 },
          },
        },
        {
          index: 0,
          target,
          probe: {
            fingerprint: 'p1',
            kind: 'code_read',
            parameters: { action: 'read_file', filePath: 'src/a.ts', timeoutMs: 1000 },
          },
        },
      ],
      {
        maxConcurrency: 2,
        maxPerTarget: 2,
        maxPerKind: 2,
        maxCostUsd: 10,
      },
    );

    assert.deepEqual(results.map((entry) => entry.index), [0, 1]);
    assert.match(results[0]?.observation.stdout ?? '', /export const a/);
    assert.match(results[1]?.observation.stdout ?? '', /export const b/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
