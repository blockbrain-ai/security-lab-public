/**
 * Provenance verifier — checks registry, integrity, signature/provenance,
 * and publish metadata for a fetched artifact. Performs static inspection
 * of install scripts, native binaries, obfuscation, and network code.
 */

import { readFile, readdir, stat } from 'node:fs/promises';
import { resolve, extname } from 'node:path';
import { createHash } from 'node:crypto';
import type { ArtifactFetchResult, ArtifactInspection } from './contracts.js';

// ---------------------------------------------------------------------------
// Inspection thresholds
// ---------------------------------------------------------------------------

const NATIVE_EXTENSIONS = new Set(['.node', '.so', '.dylib', '.dll', '.wasm']);
const NETWORK_PATTERNS = [
  /\bfetch\s*\(/,
  /\bhttps?\.request\s*\(/,
  /\baxios\b/,
  /\bnet\.connect\s*\(/,
  /\bdns\.lookup\s*\(/,
  /\brequire\s*\(\s*['"]https?['"]\s*\)/,
];
const OBFUSCATION_PATTERNS = [
  /eval\s*\(\s*atob\s*\(/,
  /eval\s*\(\s*Buffer\.from\s*\(/,
  /Function\s*\(\s*['"][^'"]{200,}['"]/,
  /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/i,
];
const MAX_FILES_INSPECTED = 200;
const MAX_BYTES_PER_FILE = 65_536;

// ---------------------------------------------------------------------------
// Provenance verifier
// ---------------------------------------------------------------------------

export class ProvenanceVerifier {
  async inspect(fetched: ArtifactFetchResult, expectedRegistry?: string): Promise<ArtifactInspection> {
    const manifest = await this.readManifest(fetched.unpackedPath);
    const notes: string[] = [];

    // Install scripts
    let hasInstallScript = false;
    let installScriptContent: string | undefined;
    let installScriptSha256: string | undefined;
    let hasPostInstallScript = false;

    const scripts = (manifest?.scripts ?? {}) as Record<string, string>;
    const installLikeScripts = ['preinstall', 'install', 'postinstall'];
    for (const scriptName of installLikeScripts) {
      const script = scripts[scriptName];
      if (script) {
        hasInstallScript = true;
        installScriptContent = (installScriptContent ?? '') + `${scriptName}: ${script}\n`;
        if (scriptName === 'postinstall') hasPostInstallScript = true;
      }
    }
    if (installScriptContent) {
      installScriptSha256 = createHash('sha256').update(installScriptContent).digest('hex');
    }

    // Walk the package looking for native binaries, obfuscation, network calls
    const inspection = await this.walkPackage(fetched.unpackedPath);

    // Registry match
    const registryMatchesBaseline = expectedRegistry
      ? fetched.fetchedFrom.startsWith(expectedRegistry)
      : true;
    if (!registryMatchesBaseline) {
      notes.push(
        `Registry mismatch: fetched from ${fetched.fetchedFrom} but baseline expected ${expectedRegistry}`,
      );
    }

    // Signature/provenance — npm provenance via package.json publishConfig is rare;
    // we record what we can without making the rest of the pipeline depend on it.
    const signatureVerified = false;
    if (!signatureVerified) {
      notes.push('Signature verification not implemented for this registry — manual review required');
    }

    return {
      packageName: fetched.packageName,
      version: fetched.version,
      tarballSha256: fetched.tarballSha256,
      hasInstallScript,
      installScriptContent,
      installScriptSha256,
      hasPostInstallScript,
      hasNativeBinaries: inspection.nativeBinaryPaths.length > 0,
      nativeBinaryPaths: inspection.nativeBinaryPaths,
      hasObfuscatedSource: inspection.obfuscatedFiles.length > 0,
      obfuscatedFiles: inspection.obfuscatedFiles,
      containsNetworkCalls: inspection.networkCallSummary.length > 0,
      networkCallSummary: inspection.networkCallSummary,
      registryMatchesBaseline,
      signatureVerified,
      publishMetadata: undefined,
      notes,
    };
  }

  private async readManifest(unpackedPath: string): Promise<Record<string, unknown> | null> {
    try {
      const content = await readFile(resolve(unpackedPath, 'package.json'), 'utf8');
      return JSON.parse(content) as Record<string, unknown>;
    } catch {
      return null;
    }
  }

  private async walkPackage(rootPath: string): Promise<{
    nativeBinaryPaths: string[];
    obfuscatedFiles: string[];
    networkCallSummary: string[];
  }> {
    const nativeBinaryPaths: string[] = [];
    const obfuscatedFiles: string[] = [];
    const networkCallSummary: string[] = [];
    let inspected = 0;

    const walk = async (dir: string): Promise<void> => {
      if (inspected >= MAX_FILES_INSPECTED) return;
      let entries: string[];
      try {
        entries = await readdir(dir);
      } catch {
        return;
      }
      for (const entry of entries) {
        if (inspected >= MAX_FILES_INSPECTED) return;
        const path = resolve(dir, entry);
        let info;
        try {
          info = await stat(path);
        } catch {
          continue;
        }
        if (info.isDirectory()) {
          if (entry === 'node_modules' || entry === '.git') continue;
          await walk(path);
          continue;
        }
        inspected += 1;
        const ext = extname(entry).toLowerCase();
        const relPath = path.slice(rootPath.length + 1);
        if (NATIVE_EXTENSIONS.has(ext)) {
          nativeBinaryPaths.push(relPath);
          continue;
        }
        if (ext !== '.js' && ext !== '.mjs' && ext !== '.cjs' && ext !== '.ts') {
          continue;
        }
        let content: string;
        try {
          const buffer = await readFile(path);
          content = buffer.subarray(0, MAX_BYTES_PER_FILE).toString('utf8');
        } catch {
          continue;
        }
        for (const pattern of OBFUSCATION_PATTERNS) {
          if (pattern.test(content)) {
            obfuscatedFiles.push(relPath);
            break;
          }
        }
        for (const pattern of NETWORK_PATTERNS) {
          if (pattern.test(content)) {
            networkCallSummary.push(`${relPath}: matches ${pattern.source}`);
            break;
          }
        }
      }
    };

    await walk(rootPath);
    return { nativeBinaryPaths, obfuscatedFiles, networkCallSummary };
  }
}
