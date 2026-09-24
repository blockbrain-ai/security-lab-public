/**
 * Code probe — reads source files, lists directories, and searches for
 * patterns in a target codebase. This is how the investigator "sees" code.
 */

import { readFile, readdir, stat } from 'node:fs/promises';
import { resolve, relative, join, isAbsolute } from 'node:path';
import type { ProbeObservation } from '../../../evidence-plane/src/contracts.js';

// ---------------------------------------------------------------------------
// Generated / build artifact directories to exclude
// ---------------------------------------------------------------------------

const EXCLUDED_DIRS = new Set([
  'node_modules', '.git', 'dist', '.next', 'out', 'build',
  'coverage', '.nyc_output', 'playwright-report', '.playwright',
  '.turbo', '.cache', '.parcel-cache', '__pycache__',
  '.pytest_cache', '.tsbuildinfo', 'storybook-static',
  '.docusaurus', '.vercel', '.output',
]);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CodeProbeConfig {
  kind: 'code_read';
  action: 'read_file' | 'list_dir' | 'search_pattern';
  /** File path relative to target root. */
  filePath?: string;
  /** Glob or regex pattern for search_pattern action. */
  pattern?: string;
  /** Max directory depth for list_dir. */
  maxDepth?: number;
  /** Max file size in bytes to read (prevents reading huge files). */
  maxFileSizeBytes?: number;
  timeoutMs: number;
}

export interface CodeTargetConfig {
  kind: 'code';
  id: string;
  environment: string;
  /** Absolute path to the target repository root. */
  repoRoot: string;
  /** Optional scoped include paths relative to repoRoot. */
  includePaths?: string[];
  /** Optional excluded paths relative to repoRoot. */
  excludePaths?: string[];
}

// ---------------------------------------------------------------------------
// Security checks
// ---------------------------------------------------------------------------

const BLOCKED_PATTERNS = [
  /\.env$/,
  /\.env\..+$/,
  /credentials/i,
  /secrets?\.(?:json|ya?ml|toml|ini|cfg)/i,
  /\.key$/,
  /\.pem$/,
  /\.p12$/,
  /\.pfx$/,
  /id_rsa/,
  /id_ed25519/,
  /\.secret$/,
  /token\.json$/i,
];

function isBlockedPath(relativePath: string): boolean {
  return BLOCKED_PATTERNS.some((p) => p.test(relativePath));
}

function hasPathTraversal(relativePath: string): boolean {
  const normalized = resolve('/', relativePath);
  return normalized !== resolve('/', relativePath.replace(/\.\./g, ''));
}

function isWithinRoot(absolutePath: string, root: string): boolean {
  const normalizedRoot = resolve(root);
  const normalizedPath = resolve(absolutePath);
  const rel = relative(normalizedRoot, normalizedPath);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

// ---------------------------------------------------------------------------
// Probe execution
// ---------------------------------------------------------------------------

export async function runCodeProbe(
  probe: CodeProbeConfig,
  target: CodeTargetConfig,
): Promise<ProbeObservation> {
  const start = Date.now();
  const maxSize = probe.maxFileSizeBytes ?? 512_000; // 500KB default

  try {
    switch (probe.action) {
      case 'read_file':
        return await readFileProbe(probe, target, maxSize, start);
      case 'list_dir':
        return await listDirProbe(probe, target, start);
      case 'search_pattern':
        return await searchPatternProbe(probe, target, start);
      default:
        return {
          kind: 'code_read',
          stderr: `Unknown code action: ${probe.action}`,
          durationMs: Date.now() - start,
        };
    }
  } catch (error: unknown) {
    return {
      kind: 'code_read',
      stderr: error instanceof Error ? error.message : String(error),
      durationMs: Date.now() - start,
    };
  }
}

async function readFileProbe(
  probe: CodeProbeConfig,
  target: CodeTargetConfig,
  maxSize: number,
  start: number,
): Promise<ProbeObservation> {
  if (!probe.filePath) {
    return { kind: 'code_read', stderr: 'filePath is required for read_file', durationMs: Date.now() - start };
  }

  if (hasPathTraversal(probe.filePath)) {
    return { kind: 'code_read', stderr: 'blocked: path traversal detected', exitCode: 1, durationMs: Date.now() - start };
  }

  if (isBlockedPath(probe.filePath)) {
    return { kind: 'code_read', stderr: 'blocked: sensitive file pattern', exitCode: 1, durationMs: Date.now() - start };
  }

  const absPath = resolve(target.repoRoot, probe.filePath);
  if (!isWithinRoot(absPath, target.repoRoot)) {
    return { kind: 'code_read', stderr: 'blocked: path outside target root', exitCode: 1, durationMs: Date.now() - start };
  }
  if (!isWithinScope(absPath, target)) {
    return { kind: 'code_read', stderr: 'blocked: path outside scoped include paths', exitCode: 1, durationMs: Date.now() - start };
  }

  const fileStat = await stat(absPath);
  if (fileStat.size > maxSize) {
    return {
      kind: 'code_read',
      stderr: `blocked: file size ${fileStat.size} exceeds limit ${maxSize}`,
      exitCode: 1,
      durationMs: Date.now() - start,
    };
  }

  const content = await readFile(absPath, 'utf8');
  return {
    kind: 'code_read',
    stdout: content,
    exitCode: 0,
    durationMs: Date.now() - start,
  };
}

async function listDirProbe(
  probe: CodeProbeConfig,
  target: CodeTargetConfig,
  start: number,
): Promise<ProbeObservation> {
  const dirPath = probe.filePath;

  if (dirPath && hasPathTraversal(dirPath)) {
    return { kind: 'code_read', stderr: 'blocked: path traversal detected', exitCode: 1, durationMs: Date.now() - start };
  }
  const maxDepth = probe.maxDepth ?? 3;
  const entries: string[] = [];
  for (const absPath of resolveScopedStartPaths(target, dirPath)) {
    if (!isWithinRoot(absPath, target.repoRoot)) {
      return { kind: 'code_read', stderr: 'blocked: path outside target root', exitCode: 1, durationMs: Date.now() - start };
    }
    if (!isWithinScope(absPath, target)) {
      return { kind: 'code_read', stderr: 'blocked: path outside scoped include paths', exitCode: 1, durationMs: Date.now() - start };
    }
    await walkDir(absPath, target.repoRoot, 0, maxDepth, entries, target);
  }

  return {
    kind: 'code_read',
    stdout: entries.join('\n'),
    exitCode: 0,
    durationMs: Date.now() - start,
  };
}

async function walkDir(
  dirPath: string,
  root: string,
  depth: number,
  maxDepth: number,
  out: string[],
  target: CodeTargetConfig,
): Promise<void> {
  if (depth > maxDepth) return;

  const entries = await readdir(dirPath, { withFileTypes: true });
  for (const entry of entries) {
    if (EXCLUDED_DIRS.has(entry.name)) continue;

    const fullPath = join(dirPath, entry.name);
    const relPath = relative(root, fullPath);
    if (!isWithinScope(fullPath, target)) continue;

    if (entry.isDirectory()) {
      out.push(`${relPath}/`);
      await walkDir(fullPath, root, depth + 1, maxDepth, out, target);
    } else {
      out.push(relPath);
    }
  }
}

async function searchPatternProbe(
  probe: CodeProbeConfig,
  target: CodeTargetConfig,
  start: number,
): Promise<ProbeObservation> {
  if (!probe.pattern) {
    return { kind: 'code_read', stderr: 'pattern is required for search_pattern', durationMs: Date.now() - start };
  }

  const regex = new RegExp(probe.pattern, 'gm');
  const matches: string[] = [];
  const maxResults = 100;
  const searchPaths = resolveScopedStartPaths(target, probe.filePath);

  for (const searchDir of searchPaths) {
    if (!isWithinRoot(searchDir, target.repoRoot)) {
      return { kind: 'code_read', stderr: 'blocked: path outside target root', exitCode: 1, durationMs: Date.now() - start };
    }
    if (!isWithinScope(searchDir, target)) {
      return { kind: 'code_read', stderr: 'blocked: path outside scoped include paths', exitCode: 1, durationMs: Date.now() - start };
    }
    await searchInDir(searchDir, target.repoRoot, regex, matches, maxResults, 0, 5, target);
  }

  return {
    kind: 'code_read',
    stdout: matches.join('\n'),
    exitCode: 0,
    durationMs: Date.now() - start,
  };
}

async function searchInDir(
  dirPath: string,
  root: string,
  regex: RegExp,
  matches: string[],
  maxResults: number,
  depth: number,
  maxDepth: number,
  target: CodeTargetConfig,
): Promise<void> {
  if (depth > maxDepth || matches.length >= maxResults) return;

  let entries;
  try {
    entries = await readdir(dirPath, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (matches.length >= maxResults) break;
    if (EXCLUDED_DIRS.has(entry.name)) continue;

    const fullPath = join(dirPath, entry.name);
    const relPath = relative(root, fullPath);
    if (!isWithinScope(fullPath, target)) continue;

    if (entry.isDirectory()) {
      await searchInDir(fullPath, root, regex, matches, maxResults, depth + 1, maxDepth, target);
    } else if (/\.(ts|js|tsx|jsx|json|ya?ml|md|sh|sql)$/.test(entry.name)) {
      if (isBlockedPath(relPath)) continue;

      try {
        const content = await readFile(fullPath, 'utf8');
        const lines = content.split('\n');
        for (let i = 0; i < lines.length && matches.length < maxResults; i++) {
          if (regex.test(lines[i]!)) {
            matches.push(`${relPath}:${i + 1}: ${lines[i]!.trim()}`);
          }
          regex.lastIndex = 0;
        }
      } catch {
        // Skip unreadable files
      }
    }
  }
}

function resolveScopedStartPaths(target: CodeTargetConfig, requestedPath?: string): string[] {
  if (requestedPath) {
    return [resolve(target.repoRoot, requestedPath)];
  }

  if (target.includePaths && target.includePaths.length > 0) {
    return target.includePaths.map((entry) => resolve(target.repoRoot, entry));
  }

  return [target.repoRoot];
}

function isWithinScope(absolutePath: string, target: CodeTargetConfig): boolean {
  if (!isWithinRoot(absolutePath, target.repoRoot)) {
    return false;
  }

  const relPath = relative(target.repoRoot, absolutePath).replace(/\\/g, '/');

  if ((target.excludePaths ?? []).some((excluded) => matchesScopedPath(relPath, excluded))) {
    return false;
  }

  if (!target.includePaths || target.includePaths.length === 0) {
    return true;
  }

  return target.includePaths.some((included) => matchesScopedPath(relPath, included));
}

function matchesScopedPath(relativePath: string, scopedPath: string): boolean {
  const normalizedPath = relativePath.replace(/\\/g, '/').replace(/^\.?\//, '');
  const normalizedScope = scopedPath.replace(/\\/g, '/').replace(/^\.?\//, '').replace(/\/+$/, '');
  return normalizedPath === normalizedScope || normalizedPath.startsWith(`${normalizedScope}/`);
}
