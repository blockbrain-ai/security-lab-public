import { readFile, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { getAttackLabRoot } from '../loaders/runfile-loader.js';

export interface LoadedEnvFile {
  path: string;
  keys: string[];
}

export interface LoadedEnvironment {
  rootDir: string;
  filesLoaded: LoadedEnvFile[];
  applied: Record<string, string>;
}

export async function loadSecurityLabEnvironment(options?: {
  envFile?: string;
  rootDir?: string;
}): Promise<LoadedEnvironment> {
  const rootDir = options?.rootDir ?? resolve(getAttackLabRoot(), '..', '..');
  const filesLoaded: LoadedEnvFile[] = [];
  const applied: Record<string, string> = {};

  const env = { ...process.env } as Record<string, string | undefined>;
  const candidateFiles = [
    resolve(rootDir, '.env.local'),
    resolve(rootDir, '.env.security-lab.local'),
    process.env['SECURITY_LAB_ENV_FILE'],
    options?.envFile,
  ].filter((value): value is string => Boolean(value));

  for (const filePath of candidateFiles) {
    const resolved = resolve(filePath);
    if (!await exists(resolved)) {
      continue;
    }
    const parsed = await parseEnvFile(resolved);
    filesLoaded.push({ path: resolved, keys: Object.keys(parsed) });
    for (const [key, value] of Object.entries(parsed)) {
      env[key] = value;
      applied[key] = value;
    }
  }

  normalizeAliases(env, applied);

  for (const [key, value] of Object.entries(env)) {
    if (value !== undefined) {
      process.env[key] = value;
    }
  }

  return {
    rootDir,
    filesLoaded,
    applied,
  };
}

async function parseEnvFile(filePath: string): Promise<Record<string, string>> {
  const content = await readFile(filePath, 'utf8');
  const entries: Record<string, string> = {};

  for (const rawLine of content.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) {
      continue;
    }

    const match = line.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (!match) {
      continue;
    }

    const key = match[1]!;
    let value = match[2] ?? '';
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    value = value.replace(/\\n/g, '\n');
    entries[key] = value;
  }

  return entries;
}

function normalizeAliases(env: Record<string, string | undefined>, applied: Record<string, string>): void {
  const gemini = env['GEMINI_API_KEY'];
  const google = env['GOOGLE_AI_API_KEY'];

  if (gemini && !google) {
    env['GOOGLE_AI_API_KEY'] = gemini;
    applied['GOOGLE_AI_API_KEY'] = gemini;
  }
  if (google && !gemini) {
    env['GEMINI_API_KEY'] = google;
    applied['GEMINI_API_KEY'] = google;
  }
}

async function exists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}
