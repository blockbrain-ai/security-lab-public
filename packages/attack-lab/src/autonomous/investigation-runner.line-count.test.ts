/**
 * Section 5.2 — enforce the coordinator-only line budget for
 * `investigation-runner.ts`. The runner may only contain the thin
 * coordinator: config surface, pipeline assembly, stage iteration, lock
 * acquisition / release, error handling, and result aggregation. All
 * other logic must live in `investigation-runner-internals.ts` or the
 * named stage modules under `./stages/`.
 *
 * The hard budget is 500 non-blank non-comment lines. Raising it
 * requires a governance amendment to SL6 and the Stage Contract doc.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const RUNNER_PATH = resolve(HERE, 'investigation-runner.ts');
const LINE_BUDGET = 500;

function countSignificantLines(source: string): number {
  const lines = source.split('\n');
  let count = 0;
  let inBlockComment = false;
  for (const raw of lines) {
    const line = raw.trim();
    if (line.length === 0) continue;
    if (inBlockComment) {
      if (line.includes('*/')) inBlockComment = false;
      continue;
    }
    if (line.startsWith('/*')) {
      if (!line.includes('*/')) inBlockComment = true;
      continue;
    }
    if (line.startsWith('//')) continue;
    if (line.startsWith('*')) continue;
    count += 1;
  }
  return count;
}

test('investigation-runner.ts stays within the 500-line coordinator budget', () => {
  const source = readFileSync(RUNNER_PATH, 'utf8');
  const significant = countSignificantLines(source);
  assert.ok(
    significant <= LINE_BUDGET,
    `investigation-runner.ts has ${significant} non-blank non-comment lines, budget is ${LINE_BUDGET}. `
    + 'Move logic into investigation-runner-internals.ts or a stage module.',
  );
});
