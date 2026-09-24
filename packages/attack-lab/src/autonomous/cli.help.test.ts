import test from 'node:test';
import assert from 'node:assert/strict';
import { execSync } from 'node:child_process';
import { resolve } from 'node:path';

const CLI = resolve(import.meta.dirname, 'cli.ts');

test('investigate CLI help advertises dynamic portfolio discovery and local transport overrides', () => {
  const output = execSync(`node --import tsx ${CLI} --help`, {
    encoding: 'utf8',
    timeout: 15000,
  });

  assert.match(output, /--portfolio <id>\s+Portfolio profile \(see --list-portfolios\)/);
  assert.match(output, /--planner-base-url <url>/);
  assert.match(output, /--planner-max-tokens <n>/);
  assert.match(output, /--planner-local-inference/);
  assert.match(output, /--planner-cli-local-provider <p>/);
  assert.match(output, /--planner-cli-profile <id>/);
  assert.match(output, /--judge-base-url <url>/);
  assert.match(output, /--judge-max-tokens <n>/);
  assert.match(output, /--judge-local-inference/);
  assert.match(output, /--judge-cli-local-provider <p>/);
  assert.match(output, /--judge-cli-profile <id>/);
});
