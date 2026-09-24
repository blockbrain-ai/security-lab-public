#!/usr/bin/env node
/**
 * verify-from-campaign — resume a finished static campaign into the
 * full integrated verification path instead of using the older
 * lightweight salvage flow.
 *
 * Usage:
 *   node scripts/verify-from-campaign.mjs <campaignId> [--target <yaml>] [additional investigate args...]
 */

import { readFile, readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = resolve(__dirname, '..');
const targetsDir = resolve(repoRoot, 'packages/attack-lab/targets');

const rawArgs = process.argv.slice(2);
const campaignId = rawArgs[0];

if (!campaignId) {
  console.error('Usage: node scripts/verify-from-campaign.mjs <campaignId> [--target <yaml>] [additional investigate args...]');
  process.exit(1);
}

const forwardedArgs = rawArgs.slice(1);
// Campaigns live in the attack-lab workspace, not the repo root (see CLAUDE.md).
const campaignDir = resolve(repoRoot, 'packages/attack-lab/data/campaigns', campaignId);
const statePath = resolve(campaignDir, 'state.json');

if (!existsSync(statePath)) {
  console.error(`Campaign state not found: ${statePath}`);
  process.exit(1);
}

const state = JSON.parse(await readFile(statePath, 'utf8'));
const inferredTarget = getArg(forwardedArgs, '--target') ?? state.targetProfilePath ?? await inferTargetProfile(state.targetId);
const cleanedForwardedArgs = resolvePathFlags(
  sanitizeForwardedArgs(forwardedArgs, ['--target', '--resume', '--resume-at']),
  ['--live-target', '--hosted-target', '--baseline-path', '--quarantine-dir'],
);

if (!inferredTarget) {
  console.error(
    `Could not infer a target profile for campaign ${campaignId}. ` +
      'Pass --target <yaml> explicitly.',
  );
  process.exit(1);
}

const investigateArgs = [
  'run',
  'investigate',
  '--',
  '--target',
  inferredTarget,
  '--campaign-dir',
  resolve(repoRoot, 'packages/attack-lab/data/campaigns'),
  '--resume',
  campaignId,
  '--resume-at',
  'verification',
  ...ensureVerificationDefaults(cleanedForwardedArgs),
];

console.log(`[verify-from-campaign] campaign=${campaignId}`);
console.log(`[verify-from-campaign] target=${inferredTarget}`);
console.log(`[verify-from-campaign] forwarding: ${investigateArgs.slice(3).join(' ')}`);

const child = spawn('npm', investigateArgs, {
  cwd: repoRoot,
  stdio: 'inherit',
  env: process.env,
});

child.on('exit', (code, signal) => {
  if (signal) {
    console.error(`[verify-from-campaign] investigate terminated by signal ${signal}`);
    process.exit(1);
  }
  process.exit(code ?? 1);
});

function getArg(args, flag) {
  const index = args.indexOf(flag);
  return index >= 0 && index + 1 < args.length ? args[index + 1] : null;
}

function ensureVerificationDefaults(args) {
  const output = [...args];

  if (!output.includes('--strict-verification')) {
    output.push('--strict-verification');
  }

  if (!output.includes('--verify-via')) {
    output.push('--verify-via', getArg(output, '--live-target') ? 'test-synthesis,local-live' : 'test-synthesis');
  }

  if (!output.includes('--confirm-live') && getArg(output, '--live-target')) {
    output.push('--confirm-live');
  }

  if (!output.includes('--preset') && !output.includes('--portfolio')) {
    output.push('--preset', 'serious-local');
  }

  return output;
}

function sanitizeForwardedArgs(args, flagsWithValues) {
  const blocked = new Set(flagsWithValues);
  const cleaned = [];
  for (let index = 0; index < args.length; index += 1) {
    const value = args[index];
    if (blocked.has(value)) {
      index += 1;
      continue;
    }
    cleaned.push(value);
  }
  return cleaned;
}

function resolvePathFlags(args, flags) {
  const pathFlags = new Set(flags);
  const resolved = [];
  for (let index = 0; index < args.length; index += 1) {
    const value = args[index];
    if (pathFlags.has(value) && index + 1 < args.length) {
      resolved.push(value, resolve(repoRoot, args[index + 1]));
      index += 1;
      continue;
    }
    resolved.push(value);
  }
  return resolved;
}

async function inferTargetProfile(targetId) {
  if (!targetId || !existsSync(targetsDir)) {
    return null;
  }

  const entries = await readdir(targetsDir, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith('.yaml')) {
      continue;
    }
    const candidatePath = join(targetsDir, entry.name);
    const content = await readFile(candidatePath, 'utf8');
    if (new RegExp(`^id:\\s*${escapeRegExp(targetId)}\\s*$`, 'm').test(content)) {
      return candidatePath;
    }
  }

  return null;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
