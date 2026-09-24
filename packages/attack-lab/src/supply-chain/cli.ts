/**
 * CLI for the supply-chain sentinel.
 *
 * Usage:
 *   npm run sentinel -- --target targets/example-http.yaml
 *   npm run sentinel:status -- --target targets/example-http.yaml
 *   npm run sentinel:approve -- --target targets/example-http.yaml --package lodash@1.0.0
 */

import { resolve } from 'node:path';
import { loadInvestigationTarget } from '../autonomous/target-profile.js';
import { runSentinel, approveAndUpdateBaseline, summarizeSentinelResult } from './sentinel.js';

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h')) {
    console.log(`Usage:
  npm run sentinel -- --target <path-or-yaml>  Run sentinel scan
  npm run sentinel:status -- --target <path-or-yaml>  Show current drift status
  npm run sentinel:approve -- --target <path-or-yaml> --package <pkg[@version]>  Approve a package
`);
    return;
  }

  const targetIdx = args.indexOf('--target');
  const targetArg = targetIdx >= 0 && targetIdx + 1 < args.length ? args[targetIdx + 1]! : '.';
  const targetId = getArg(args, '--target-id');
  const statusOnly = args.includes('--status');
  const approveMode = args.includes('--approve');
  const approvePackage = getArg(args, '--package') ?? getArg(args, '--approve');
  const repoRoot = await resolveTargetRepoRoot(targetArg, targetId);

  if (approveMode || approvePackage) {
    if (!approvePackage) {
      throw new Error('Approving dependency drift requires --package <name[@version]>.');
    }
    const baselinePath = resolve(repoRoot, '.security-lab-baseline.json');
    await approveAndUpdateBaseline(repoRoot, baselinePath, [approvePackage]);
    console.log(`Approved: ${approvePackage}`);
    console.log(`Baseline updated at ${baselinePath}`);
    return;
  }

  console.log('Supply-Chain Sentinel');
  console.log('=====================');
  console.log(`Target: ${repoRoot}`);
  console.log('');

  const result = await runSentinel(repoRoot);
  console.log(summarizeSentinelResult(result));

  if (result.shouldBlockBuild) {
    console.log('\n⚠ BUILD WOULD BE BLOCKED due to unresolved dependency drift.');
    process.exitCode = 1;
  }

  if (statusOnly) {
    return;
  }
}

function getArg(args: string[], flag: string): string | null {
  const index = args.indexOf(flag);
  return index >= 0 && index + 1 < args.length ? args[index + 1]! : null;
}

async function resolveTargetRepoRoot(targetArg: string, targetId?: string | null): Promise<string> {
  const target = await loadInvestigationTarget(targetArg, targetId ?? undefined);
  if (target.repoRoot) {
    return target.repoRoot;
  }
  if (target.cwd) {
    return target.cwd;
  }
  return resolve(targetArg);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
