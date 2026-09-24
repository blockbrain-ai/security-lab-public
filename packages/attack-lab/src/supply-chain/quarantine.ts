/**
 * Quarantine — inspects changed packages in isolation before trust.
 * Performs static analysis of tarball contents without executing
 * untrusted code in the main environment.
 */

import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import type { QuarantineResult, QuarantineCheck } from './contracts.js';

// ---------------------------------------------------------------------------
// Risk patterns
// ---------------------------------------------------------------------------

const RISKY_CODE_PATTERNS = [
  { pattern: /eval\s*\(/g, name: 'eval', severity: 'high' as const },
  { pattern: /new\s+Function\s*\(/g, name: 'Function constructor', severity: 'high' as const },
  { pattern: /child_process/g, name: 'child_process', severity: 'critical' as const },
  { pattern: /require\s*\(\s*['"]child_process['"]\s*\)/g, name: 'child_process require', severity: 'critical' as const },
  { pattern: /\bexec\s*\(/g, name: 'exec', severity: 'high' as const },
  { pattern: /\bexecSync\s*\(/g, name: 'execSync', severity: 'high' as const },
  { pattern: /\bspawn\s*\(/g, name: 'spawn', severity: 'medium' as const },
  { pattern: /\bfetch\s*\(/g, name: 'fetch (network)', severity: 'medium' as const },
  { pattern: /https?:\/\/[^\s'"]+/g, name: 'hardcoded URL', severity: 'low' as const },
  { pattern: /Buffer\.from\s*\([^)]*,\s*['"]base64['"]/g, name: 'base64 decode', severity: 'medium' as const },
  { pattern: /atob\s*\(/g, name: 'atob decode', severity: 'medium' as const },
  { pattern: /process\.env/g, name: 'env access', severity: 'medium' as const },
  { pattern: /fs\.(write|unlink|rm|rename|chmod)/g, name: 'filesystem mutation', severity: 'high' as const },
  { pattern: /\.so\b|\.dylib\b|\.dll\b|\.node\b/g, name: 'native binary reference', severity: 'high' as const },
];

const INSTALL_SCRIPT_NAMES = ['preinstall', 'install', 'postinstall', 'preuninstall', 'prepare'];

// ---------------------------------------------------------------------------
// Quarantine inspection
// ---------------------------------------------------------------------------

/**
 * Inspect a locally-installed package (in node_modules) for risk indicators.
 * Does NOT execute any code — pure static analysis.
 */
export async function inspectInstalledPackage(
  packageDir: string,
  packageName: string,
  version: string,
): Promise<QuarantineResult> {
  const checks: QuarantineCheck[] = [];

  // Check 1: Install scripts
  try {
    const pkgJsonContent = await readFile(join(packageDir, 'package.json'), 'utf8');
    const pkgJson = JSON.parse(pkgJsonContent);
    const scripts = pkgJson.scripts ?? {};

    for (const scriptName of INSTALL_SCRIPT_NAMES) {
      if (scripts[scriptName]) {
        const script = scripts[scriptName] as string;
        const hasNetworkAccess = /curl|wget|fetch|http|npm\s+exec|npx/i.test(script);
        checks.push({
          name: `install_script_${scriptName}`,
          passed: !hasNetworkAccess,
          severity: hasNetworkAccess ? 'critical' : 'high',
          details: hasNetworkAccess
            ? `${scriptName} script has network access: "${script}"`
            : `${scriptName} script present: "${script}"`,
        });
      }
    }
  } catch {
    checks.push({
      name: 'package_json_read',
      passed: false,
      severity: 'high',
      details: 'Could not read package.json',
    });
  }

  // Check 2: Scan source files for risky patterns
  const sourceFindings = await scanSourceFiles(packageDir);
  for (const finding of sourceFindings) {
    checks.push(finding);
  }

  // Check 3: Look for native binaries
  const nativeBinaries = await findNativeBinaries(packageDir);
  if (nativeBinaries.length > 0) {
    checks.push({
      name: 'native_binaries',
      passed: false,
      severity: 'high',
      details: `Found native binaries: ${nativeBinaries.join(', ')}`,
    });
  }

  // Compute verdict
  const criticalFails = checks.filter((c) => !c.passed && c.severity === 'critical');
  const highFails = checks.filter((c) => !c.passed && c.severity === 'high');

  let verdict: QuarantineResult['verdict'];
  let reason: string;

  if (criticalFails.length > 0) {
    verdict = 'rejected';
    reason = `Critical risk: ${criticalFails.map((c) => c.name).join(', ')}`;
  } else if (highFails.length > 0) {
    verdict = 'needs_review';
    reason = `High risk requiring review: ${highFails.map((c) => c.name).join(', ')}`;
  } else {
    verdict = 'approved';
    reason = 'No critical or high-severity risks detected';
  }

  return {
    packageName,
    version,
    verdict,
    checks,
    reason,
    inspectedAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Source file scanning
// ---------------------------------------------------------------------------

async function scanSourceFiles(dir: string, depth: number = 0): Promise<QuarantineCheck[]> {
  const findings: QuarantineCheck[] = [];
  if (depth > 3) return findings;

  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return findings;
  }

  for (const entry of entries) {
    if (entry.name === 'node_modules' || entry.name === '.git') continue;
    const fullPath = join(dir, entry.name);

    if (entry.isDirectory()) {
      findings.push(...await scanSourceFiles(fullPath, depth + 1));
    } else if (/\.(js|mjs|cjs|ts|sh|py)$/.test(entry.name)) {
      try {
        const content = await readFile(fullPath, 'utf8');
        for (const { pattern, name, severity } of RISKY_CODE_PATTERNS) {
          pattern.lastIndex = 0;
          const matches = content.match(pattern);
          if (matches && matches.length > 0) {
            findings.push({
              name: `risky_pattern_${name}`,
              passed: false,
              severity,
              details: `${entry.name}: ${matches.length} occurrence(s) of ${name}`,
            });
          }
        }
      } catch {
        // Skip unreadable files
      }
    }
  }

  return findings;
}

async function findNativeBinaries(dir: string, depth: number = 0): Promise<string[]> {
  const binaries: string[] = [];
  if (depth > 3) return binaries;

  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return binaries;
  }

  for (const entry of entries) {
    if (entry.name === 'node_modules') continue;
    const fullPath = join(dir, entry.name);

    if (entry.isDirectory()) {
      binaries.push(...await findNativeBinaries(fullPath, depth + 1));
    } else if (/\.(node|so|dylib|dll)$/.test(entry.name)) {
      binaries.push(entry.name);
    }
  }

  return binaries;
}
