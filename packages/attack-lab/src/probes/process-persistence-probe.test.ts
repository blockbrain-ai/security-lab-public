import test from 'node:test';
import assert from 'node:assert/strict';
import { runPersistenceProbe } from './persistence-probe.js';
import { runProcessProbe } from './process-probe.js';

test('runProcessProbe finds credential-like environment variables and reads process metadata safely', async () => {
  process.env['SECURITY_LAB_TEST_API_KEY'] = 'secret-value';

  try {
    const credentials = await runProcessProbe({
      kind: 'process_check',
      action: 'credential_search',
      searchPatterns: ['SECURITY_LAB_TEST_API_KEY'],
      timeoutMs: 1000,
    });
    assert.equal(credentials.exitCode, 1);
    assert.match(credentials.stdout ?? '', /credential_found: SECURITY_LAB_TEST_API_KEY/i);

    const proc = await runProcessProbe({
      kind: 'process_check',
      action: 'proc_self_read',
      timeoutMs: 1000,
    });
    assert.equal(proc.exitCode, 0);
    assert.match(proc.stdout ?? '', /\/proc\/self\/(status|cmdline|maps|cgroup):/i);
  } finally {
    delete process.env['SECURITY_LAB_TEST_API_KEY'];
  }
});

test('runPersistenceProbe inspects background processes and startup footholds', async () => {
  const background = await runPersistenceProbe({
    kind: 'persistence_check',
    action: 'background_process_check',
    timeoutMs: 2000,
  });
  assert.equal(background.exitCode, 0);
  assert.ok((background.stdout ?? '').length > 0 || (background.stderr ?? '').length > 0);

  const startup = await runPersistenceProbe({
    kind: 'persistence_check',
    action: 'startup_check',
    timeoutMs: 2000,
  });
  assert.equal(startup.exitCode, 0);
  assert.match(startup.stdout ?? '', /(LaunchAgents|LaunchDaemons|not accessible)/i);
});
