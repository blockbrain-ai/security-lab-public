import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';
import { SecurityLabRunfileSchema, type SecurityLabRunfile } from '../types/runfile.js';

const ATTACK_LAB_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

export function getAttackLabRoot(): string {
  return ATTACK_LAB_ROOT;
}

export async function loadRunfile(runfilePath: string): Promise<SecurityLabRunfile> {
  const path = resolveRunfilePath(runfilePath);
  const raw = await readFile(path, 'utf8');
  const parsed = YAML.parse(raw);
  return SecurityLabRunfileSchema.parse(parsed);
}

export function resolveRunfilePath(runfilePath: string): string {
  return resolve(ATTACK_LAB_ROOT, runfilePath);
}

