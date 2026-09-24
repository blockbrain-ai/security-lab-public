import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadTargetOverlay } from './target-overlay.js';
import type { InvestigationTarget, OverlayInline } from './target-profile.js';

function makeTarget(overlay?: string | OverlayInline, profilePath?: string): InvestigationTarget {
  return {
    id: 'test-target',
    name: 'Test Target',
    kind: 'code',
    environment: 'sandbox',
    hints: {},
    supportedProbeKinds: ['code_read'],
    overlay,
    profilePath,
  };
}

test('loadTargetOverlay returns empty string when no overlay is declared', async () => {
  const result = await loadTargetOverlay(makeTarget());
  assert.equal(result, '');
});

test('loadTargetOverlay renders inline overlay', async () => {
  const overlay: OverlayInline = {
    stackHints: { runtime: 'node', framework: 'Express' },
    highValuePatterns: ['eval(', '$queryRaw'],
    trustBoundaries: [
      { from: 'external', to: 'api', mechanism: 'middleware', notes: 'check gaps' },
    ],
    vulnerabilityFamilies: [
      { family: 'sqli', description: 'SQL injection via raw queries', priority: 'critical' },
    ],
  };

  const result = await loadTargetOverlay(makeTarget(overlay));
  assert.ok(result.includes('Test Target'));
  assert.ok(result.includes('runtime: node'));
  assert.ok(result.includes('framework: Express'));
  assert.ok(result.includes('eval('));
  assert.ok(result.includes('$queryRaw'));
  assert.ok(result.includes('external'));
  assert.ok(result.includes('middleware'));
  assert.ok(result.includes('sqli'));
  assert.ok(result.includes('SQL injection'));
});

test('loadTargetOverlay loads overlay from a YAML file path', async () => {
  // Self-contained fixture: the overlay is resolved relative to the profile path.
  const root = await mkdtemp(join(tmpdir(), 'target-overlay-'));
  try {
    const profilePath = join(root, 'profile.yaml');
    await writeFile(profilePath, 'id: fixture\n', 'utf8');
    await writeFile(
      join(root, 'overlay.yaml'),
      [
        'vulnerabilityFamilies:',
        '  - family: tenant_isolation',
        '    description: Cross-tenant access through a shared identifier.',
        '    priority: high',
        '  - family: prompt_injection',
        '    description: Untrusted text reaching a model prompt.',
        '    priority: medium',
        'trustBoundaries:',
        '  - from: external_untrusted',
        '    to: public_api',
        '    mechanism: session validation',
        'highValuePatterns:',
        '  - "$queryRaw"',
        '',
      ].join('\n'),
      'utf8',
    );

    const result = await loadTargetOverlay(makeTarget('./overlay.yaml', profilePath));
    assert.ok(result.length > 0);
    assert.ok(result.includes('Priority Vulnerability Families'));
    assert.ok(result.includes('tenant_isolation'));
    assert.ok(result.includes('prompt_injection'));
    assert.ok(result.includes('Trust Boundaries to Probe'));
    assert.ok(result.includes('High-Value Code Patterns'));
    assert.ok(result.includes('$queryRaw'));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('loadTargetOverlay renders partial overlays without all fields', async () => {
  const overlay: OverlayInline = {
    highValuePatterns: ['dangerous_pattern'],
  };

  const result = await loadTargetOverlay(makeTarget(overlay));
  assert.ok(result.includes('dangerous_pattern'));
  assert.ok(!result.includes('Trust Boundaries'));
  assert.ok(!result.includes('Vulnerability Families'));
});
