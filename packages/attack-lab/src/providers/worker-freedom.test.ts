import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chmod, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { ClaudeCodeAdapter } from './claude-code-adapter.js';
import { CodexCliAdapter } from './codex-cli-adapter.js';

/**
 * Worker freedom acceptance tests — prove that the loosened worker contract
 * actually delivers freedom. A worker inside a bounded sandbox must be able
 * to run non-allowlisted shell commands, mutate scratch files, and return
 * structured output. This is the counterpart to `worker-contract.test.ts`
 * (which asserts the absence of prohibitions): this test proves workers can
 * actually use the freedom granted.
 *
 * We fake the CLI binaries as tiny Node.js scripts that run a real
 * non-allowlisted command (`find . -type f | wc -l`) through `execSync`,
 * mutate a real scratch file, read it back, and emit the adapter's
 * stream-json envelope with the result. If `node` is unavailable (it always
 * is when these tests run under node --test, so the guard is defensive) the
 * test skips with a visible message rather than failing.
 */

function haveNode(): boolean {
  try {
    execFileSync(process.execPath, ['-e', '1'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

const NODE_PATH = process.execPath;

test('worker (claude_code shape) can run non-allowlisted commands, mutate scratch, and return structured output', async (t) => {
  if (!haveNode()) {
    t.skip('skipped: node binary not available for fake worker');
    return;
  }

  const sandbox = await mkdtemp(resolve(tmpdir(), 'security-lab-worker-freedom-claude-'));
  for (const name of ['a.ts', 'b.ts', 'c.ts', 'd.ts']) {
    await writeFile(resolve(sandbox, name), '// scratch\n');
  }
  const scratchPath = resolve(sandbox, 'worker-scratch.json');
  const fakeScript = resolve(sandbox, 'fake-claude.mjs');
  const binaryPath = resolve(sandbox, 'claude');

  await writeFile(
    fakeScript,
    `
import { execSync } from 'node:child_process';
import { writeFileSync, readFileSync } from 'node:fs';
const out = execSync('find . -type f -name "*.ts" | wc -l', { encoding: 'utf8' }).trim();
const count = Number(out);
const scratchPath = ${JSON.stringify(scratchPath)};
writeFileSync(scratchPath, JSON.stringify({ count }));
const text = readFileSync(scratchPath, 'utf8');
const assistant = { type: 'assistant', session_id: 'sess-freedom', message: { content: [{ type: 'text', text }] } };
const result = { type: 'result', session_id: 'sess-freedom', result: 'ok', total_cost_usd: 0.01, duration_ms: 1, usage: { input_tokens: 1, output_tokens: 1 } };
process.stdout.write(JSON.stringify(assistant) + '\\n');
process.stdout.write(JSON.stringify(result) + '\\n');
`,
    'utf8',
  );
  await writeFile(
    binaryPath,
    `#!/bin/sh\nexec ${JSON.stringify(NODE_PATH)} ${JSON.stringify(fakeScript)} "$@"\n`,
    'utf8',
  );
  await chmod(binaryPath, 0o755);

  const adapter = new ClaudeCodeAdapter({
    provider: 'claude_code',
    model: 'claude-opus-4-6',
    binaryPath,
    workingDirectory: sandbox,
  });

  const response = await adapter.invoke({
    prompt: 'Count TypeScript files and return {count: n}',
  });

  const scratchContent = await readFile(scratchPath, 'utf8');
  assert.equal(scratchContent, '{"count":4}', 'worker must have actually mutated the scratch file');
  assert.equal(response.content, '{"count":4}', 'adapter must surface the worker-produced content');
  // Parse the structured payload manually — tryParseStructured requires a
  // zod schema, and this test is about the freedom not the schema plumbing.
  const parsed = JSON.parse(response.content) as { count: number };
  assert.deepEqual(parsed, { count: 4 });
});

test('worker (codex_cli shape) can run non-allowlisted commands, mutate scratch, and return structured output', async (t) => {
  if (!haveNode()) {
    t.skip('skipped: node binary not available for fake worker');
    return;
  }

  const sandbox = await mkdtemp(resolve(tmpdir(), 'security-lab-worker-freedom-codex-'));
  for (const name of ['a.ts', 'b.ts', 'c.ts']) {
    await writeFile(resolve(sandbox, name), '// scratch\n');
  }
  const scratchPath = resolve(sandbox, 'worker-scratch.json');
  const fakeScript = resolve(sandbox, 'fake-codex.mjs');
  const binaryPath = resolve(sandbox, 'codex');

  await writeFile(
    fakeScript,
    `
import { execSync } from 'node:child_process';
import { writeFileSync, readFileSync } from 'node:fs';
const out = execSync('find . -type f -name "*.ts" | wc -l', { encoding: 'utf8' }).trim();
const count = Number(out);
const scratchPath = ${JSON.stringify(scratchPath)};
writeFileSync(scratchPath, JSON.stringify({ count }));
const text = readFileSync(scratchPath, 'utf8');
const started = { type: 'thread.started', thread_id: 'thread-freedom' };
const completed = { type: 'item.completed', item: { type: 'agent_message', text } };
const turn = { type: 'turn.completed', usage: { input_tokens: 1, output_tokens: 1 } };
process.stdout.write(JSON.stringify(started) + '\\n');
process.stdout.write(JSON.stringify(completed) + '\\n');
process.stdout.write(JSON.stringify(turn) + '\\n');
`,
    'utf8',
  );
  await writeFile(
    binaryPath,
    `#!/bin/sh\nexec ${JSON.stringify(NODE_PATH)} ${JSON.stringify(fakeScript)} "$@"\n`,
    'utf8',
  );
  await chmod(binaryPath, 0o755);

  const adapter = new CodexCliAdapter({
    provider: 'codex_cli',
    model: 'gpt-5.4',
    binaryPath,
    workingDirectory: sandbox,
  });

  const response = await adapter.invoke({
    prompt: 'Count TypeScript files and return {count: n}',
  });

  const scratchContent = await readFile(scratchPath, 'utf8');
  assert.equal(scratchContent, '{"count":3}', 'worker must have actually mutated the scratch file');
  assert.equal(response.content, '{"count":3}', 'adapter must surface the worker-produced content');
  const parsed = JSON.parse(response.content) as { count: number };
  assert.deepEqual(parsed, { count: 3 });
});
