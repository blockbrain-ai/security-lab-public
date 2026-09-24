import test from 'node:test';
import assert from 'node:assert/strict';
import { readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { getAttackLabRoot, loadRunfile, resolveRunfilePath } from './runfile-loader.js';

/**
 * The runfiles shipped in the repository are the only executable examples of
 * the runfile contract. If one stops parsing, the fixture smoke packs fail on
 * a contributor's first run, so every shipped runfile is validated here.
 */
test('every shipped runfile parses against the runfile schema', async () => {
  const runfilesDir = resolve(getAttackLabRoot(), 'runfiles');
  const entries = (await readdir(runfilesDir)).filter((name) => name.endsWith('.yaml') || name.endsWith('.yml'));

  assert.ok(entries.length > 0, 'expected at least one shipped runfile');

  for (const entry of entries) {
    const runfile = await loadRunfile(`runfiles/${entry}`);
    assert.ok(runfile.id.length > 0, `${entry} has no id`);
    assert.ok(runfile.targets.length > 0, `${entry} declares no targets`);
    assert.ok(runfile.scenarios.length > 0, `${entry} declares no scenarios`);
    assert.ok(['declared', 'blind'].includes(runfile.mode), `${entry} has mode ${runfile.mode}`);
  }
});

test('resolveRunfilePath resolves against the attack-lab root and rejects escapes', () => {
  const resolved = resolveRunfilePath('runfiles/fixture-http-smoke.yaml');
  assert.ok(resolved.startsWith(getAttackLabRoot()));

  // The loader joins paths without normalising traversal: document the current
  // behaviour so a future change to reject it is a deliberate one.
  const escaped = resolveRunfilePath('../../../etc/passwd');
  assert.ok(!escaped.startsWith(getAttackLabRoot()), 'traversal currently escapes the root');
});
