import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { EvidenceStore, type ChainCheckpoint } from '../store.js';
import { renderConsoleSummary } from '../report.js';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const verify = args.includes('--verify');
  const runDirArg = args.find((arg) => !arg.startsWith('-'));

  if (!runDirArg) {
    throw new Error('Usage: npm run evidence:report -- <run-dir> [--verify]');
  }

  const runDir = resolve(REPO_ROOT, runDirArg);

  if (verify) {
    // Integrity diagnostics are reported on stdout/stderr only — a verifying
    // run never appends to (or repairs) the evidence stream it is checking.
    process.exitCode = await verifyRunDirectory(runDir);
    return;
  }

  const summary = await EvidenceStore.readSummary(runDir);

  for (const line of renderConsoleSummary(summary)) {
    console.log(line);
  }
}

/**
 * Verify the event hash chain of a run directory and return the process exit
 * code: 0 for a valid chain, 1 for an invalid one.
 */
async function verifyRunDirectory(runDir: string): Promise<number> {
  const store = EvidenceStore.forRunDir(runDir);
  const checkpoint = await loadCheckpoint(runDir);
  const result = await store.verifyChain({ repairTornTail: false, checkpoint });

  for (const recovery of result.recoveries) {
    console.error(
      `[evidence-plane] ${recovery.path}: ${recovery.kind} — dropped ${recovery.droppedBytes} byte(s)`,
    );
  }

  if (result.valid) {
    const head = result.headHash === '' ? '(empty)' : result.headHash;
    console.log(`Chain valid: ${result.eventCount} event(s), head ${head}`);
    return 0;
  }

  console.error(`Chain invalid: ${result.errors.length} error(s) in ${join(runDir, 'events.jsonl')}`);
  for (const error of result.errors) {
    console.error(`  - ${error}`);
  }
  return 1;
}

/**
 * Read the manifest-recorded chain position when present. Manifests written
 * before `eventCount`/`headHash` existed carry no checkpoint — that is not an
 * error, it just means truncation cannot be detected from the manifest.
 */
async function loadCheckpoint(runDir: string): Promise<ChainCheckpoint | undefined> {
  try {
    const manifest = await EvidenceStore.readManifest(runDir);
    if (manifest.eventCount == null && manifest.headHash == null) {
      return undefined;
    }
    return { eventCount: manifest.eventCount, headHash: manifest.headHash };
  } catch (error) {
    if (isNotFound(error)) {
      console.error(`[evidence-plane] no manifest.json in ${runDir}; verifying events.jsonl without a checkpoint`);
      return undefined;
    }
    throw error;
  }
}

function isNotFound(error: unknown): boolean {
  return error instanceof Error && 'code' in error && (error as NodeJS.ErrnoException).code === 'ENOENT';
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
