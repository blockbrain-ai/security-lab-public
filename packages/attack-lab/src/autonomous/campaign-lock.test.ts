import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat, writeFile, mkdir, utimes } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { spawn, type ChildProcess } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { hostname } from 'node:os';
import { fileURLToPath } from 'node:url';
import { CampaignLock, WriterLockContentionError } from './campaign-lock.js';

test('CampaignLock acquires and releases a lock file', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-lock-'));
  try {
    await mkdir(join(root, 'test-campaign'), { recursive: true });
    const lock = new CampaignLock({
      campaignDir: join(root, 'test-campaign'),
      campaignId: 'test-campaign',
    });

    await lock.acquire();
    assert.ok(lock.isAcquired());

    // Lock file exists
    const lockContents = JSON.parse(await readFile(lock.getLockPath(), 'utf8'));
    assert.equal(lockContents.pid, process.pid);
    assert.equal(lockContents.hostname, hostname());
    assert.equal(lockContents.campaignId, 'test-campaign');

    await lock.release();
    assert.ok(!lock.isAcquired());

    // Lock file removed
    await assert.rejects(() => stat(lock.getLockPath()), { code: 'ENOENT' });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('CampaignLock rejects concurrent acquire with WriterLockContentionError', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-lock-'));
  try {
    await mkdir(join(root, 'test-campaign'), { recursive: true });
    const lock1 = new CampaignLock({
      campaignDir: join(root, 'test-campaign'),
      campaignId: 'test-campaign',
    });
    const lock2 = new CampaignLock({
      campaignDir: join(root, 'test-campaign'),
      campaignId: 'test-campaign',
    });

    await lock1.acquire();
    assert.ok(lock1.isAcquired());

    await assert.rejects(
      () => lock2.acquire(),
      (error: unknown) => error instanceof WriterLockContentionError,
    );
    assert.ok(!lock2.isAcquired());

    await lock1.release();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('CampaignLock reports contention out-of-band, never into the evidence stream', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-lock-'));
  try {
    const campaignDir = join(root, 'test-campaign');
    await mkdir(campaignDir, { recursive: true });
    const events: Array<{ stage: string; payload: Record<string, unknown> }> = [];
    const lock1 = new CampaignLock({
      campaignDir,
      campaignId: 'test-campaign',
    });
    const lock2 = new CampaignLock({
      campaignDir,
      campaignId: 'test-campaign',
      emitEvent: async (stage, payload) => { events.push({ stage, payload }); },
    });

    await lock1.acquire();

    await assert.rejects(() => lock2.acquire(), WriterLockContentionError);

    // The losing writer must not touch the protected stream: appending to
    // events.jsonl here would fork the winner's hash chain.
    assert.equal(events.length, 0);

    const diagnostics = (await readFile(lock2.getDiagnosticsPath(), 'utf8'))
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as { event: string; campaignId: string; currentPid: number });
    assert.equal(diagnostics.length, 1);
    assert.equal(diagnostics[0]!.event, 'writer_lock_contention');
    assert.equal(diagnostics[0]!.campaignId, 'test-campaign');
    assert.equal(diagnostics[0]!.currentPid, process.pid);

    await lock1.release();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('CampaignLock.releaseSync removes the lock file (regression: require() in ESM)', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-lock-'));
  try {
    const campaignDir = join(root, 'test-campaign');
    await mkdir(campaignDir, { recursive: true });
    const lock = new CampaignLock({ campaignDir, campaignId: 'test-campaign' });

    await lock.acquire();
    assert.ok(existsSync(lock.getLockPath()));

    const released = lock.releaseSync();
    assert.equal(released, true);
    assert.equal(existsSync(lock.getLockPath()), false);

    // A second writer can take the lock immediately afterwards.
    const second = new CampaignLock({ campaignDir, campaignId: 'test-campaign' });
    await second.acquire();
    assert.ok(second.isAcquired());
    await second.release();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('CampaignLock treats a live same-host holder as fresh regardless of age', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-lock-'));
  try {
    const campaignDir = join(root, 'test-campaign');
    await mkdir(campaignDir, { recursive: true });

    // Live local PID, long past the stale window.
    const lockPayload = {
      pid: process.pid,
      hostname: hostname(),
      acquiredAt: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString(),
      campaignId: 'test-campaign',
    };
    await writeFile(join(campaignDir, '.writer.lock'), JSON.stringify(lockPayload), 'utf8');

    const lock = new CampaignLock({
      campaignDir,
      campaignId: 'test-campaign',
      staleLockMs: 1000,
    });

    assert.equal(lock.isStale({ ...lockPayload, campaignId: 'test-campaign' }), false);
    await assert.rejects(() => lock.acquire(), WriterLockContentionError);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('CampaignLock does not steal a fresh unreadable lock, but reclaims an old one', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-lock-'));
  try {
    const campaignDir = join(root, 'test-campaign');
    await mkdir(campaignDir, { recursive: true });
    const lockPath = join(campaignDir, '.writer.lock');

    // Fresh empty lock file (as observed inside the create window).
    await writeFile(lockPath, '', 'utf8');
    const first = new CampaignLock({ campaignDir, campaignId: 'test-campaign' });
    await assert.rejects(() => first.acquire(), WriterLockContentionError);

    // An old unreadable lock is reclaimed.
    const old = new Date(Date.now() - 5 * 60 * 1000);
    await utimes(lockPath, old, old);
    const second = new CampaignLock({ campaignDir, campaignId: 'test-campaign' });
    await second.acquire();
    assert.ok(second.isAcquired());
    await second.release();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('CampaignLock treats an invalid lock payload as contention, not garbage', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-lock-'));
  try {
    const campaignDir = join(root, 'test-campaign');
    await mkdir(campaignDir, { recursive: true });
    await writeFile(join(campaignDir, '.writer.lock'), '{}', 'utf8');

    const lock = new CampaignLock({ campaignDir, campaignId: 'test-campaign' });
    // NaN age must not make the lock reclaimable forever-blocking OR stolen.
    await assert.rejects(() => lock.acquire(), WriterLockContentionError);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('SIGTERM drains via the shutdown hook, releases the lock and exits 143', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-lock-'));
  try {
    const campaignDir = join(root, 'test-campaign');
    await mkdir(campaignDir, { recursive: true });
    const modulePath = fileURLToPath(new URL('./campaign-lock.ts', import.meta.url));
    const scriptPath = join(root, 'signal-child.ts');
    await writeFile(
      scriptPath,
      [
        `import { CampaignLock } from ${JSON.stringify(modulePath)};`,
        'async function main() {',
        '  const dir = process.argv[2];',
        '  const lock = new CampaignLock({',
        "    campaignDir: dir, campaignId: 'sig-test',",
        "    onSignal: async () => { process.stdout.write('DRAINING\\n'); },",
        '  });',
        '  await lock.acquire();',
        "  process.stdout.write('READY\\n');",
        '  setInterval(() => {}, 1000);',
        '}',
        'main().catch((error) => { process.stderr.write(String(error) + "\\n"); process.exit(1); });',
      ].join('\n'),
      'utf8',
    );

    const child = spawn(process.execPath, ['--import', 'tsx', scriptPath, campaignDir], {
      cwd: process.cwd(),
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const output: string[] = [];
    const errors: string[] = [];
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => { output.push(chunk); });
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk: string) => { errors.push(chunk); });

    try {
      await waitFor(() => output.join('').includes('READY'), 20_000);
    } catch {
      throw new Error(`child never became ready. stdout=${output.join('')} stderr=${errors.join('')}`);
    }
    assert.ok(existsSync(join(campaignDir, '.writer.lock')), 'child should hold the lock');

    child.kill('SIGTERM');
    const exitCode = await waitForExit(child, 20_000);

    assert.equal(exitCode, 143, 'SIGTERM must terminate the process with 143');
    assert.ok(output.join('').includes('DRAINING'), 'shutdown hook should run before exit');
    assert.equal(existsSync(join(campaignDir, '.writer.lock')), false, 'lock must be released on shutdown');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('CampaignLock reclaims a stale lock (PID dead)', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-lock-'));
  try {
    const campaignDir = join(root, 'test-campaign');
    await mkdir(campaignDir, { recursive: true });

    // Create a lock with a dead PID
    const staleLock = {
      pid: 999999999,
      hostname: hostname(),
      acquiredAt: new Date(Date.now() - 60_000).toISOString(),
      campaignId: 'test-campaign',
    };
    await writeFile(join(campaignDir, '.writer.lock'), JSON.stringify(staleLock), 'utf8');

    const events: Array<{ stage: string; payload: Record<string, unknown> }> = [];
    const lock = new CampaignLock({
      campaignDir,
      campaignId: 'test-campaign',
      staleLockMs: 30 * 60 * 1000,
      emitEvent: async (stage, payload) => { events.push({ stage, payload }); },
    });

    await lock.acquire();
    assert.ok(lock.isAcquired());

    // Should have emitted a reclaim event
    assert.equal(events.length, 1);
    assert.equal(events[0]!.stage, 'writer_lock_reclaimed');

    await lock.release();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('CampaignLock reclaims a lock older than staleLockMs', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-lock-'));
  try {
    const campaignDir = join(root, 'test-campaign');
    await mkdir(campaignDir, { recursive: true });

    // Create a lock with current PID but very old timestamp
    const staleLock = {
      pid: process.pid,
      hostname: 'other-host',
      acquiredAt: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
      campaignId: 'test-campaign',
    };
    await writeFile(join(campaignDir, '.writer.lock'), JSON.stringify(staleLock), 'utf8');

    const lock = new CampaignLock({
      campaignDir,
      campaignId: 'test-campaign',
      staleLockMs: 1000, // 1 second stale threshold
    });

    await lock.acquire();
    assert.ok(lock.isAcquired());
    await lock.release();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('CampaignLock release is idempotent', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-lock-'));
  try {
    await mkdir(join(root, 'test-campaign'), { recursive: true });
    const lock = new CampaignLock({
      campaignDir: join(root, 'test-campaign'),
      campaignId: 'test-campaign',
    });

    await lock.acquire();
    await lock.release();
    // Second release should not throw
    await lock.release();
    assert.ok(!lock.isAcquired());
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

async function waitFor(predicate: () => boolean, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`condition not met within ${timeoutMs}ms`);
}

function waitForExit(child: ChildProcess, timeoutMs: number): Promise<number | null> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`child did not exit within ${timeoutMs}ms`));
    }, timeoutMs);
    child.once('exit', (code) => {
      clearTimeout(timer);
      resolve(code);
    });
  });
}
