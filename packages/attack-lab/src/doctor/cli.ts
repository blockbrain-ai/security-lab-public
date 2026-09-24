import { loadSecurityLabEnvironment } from '../bootstrap/env-loader.js';
import { runDoctor } from './runner.js';

function getArg(args: string[], flag: string): string | undefined {
  const index = args.indexOf(flag);
  return index >= 0 ? args[index + 1] : undefined;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const envFile = getArg(args, '--env-file');
  await loadSecurityLabEnvironment({ envFile });

  const result = await runDoctor({
    targetRef: getArg(args, '--target'),
    targetId: getArg(args, '--target-id'),
    liveTargetRef: getArg(args, '--live-target'),
    liveTargetId: getArg(args, '--live-target-id'),
    hostedTargetRef: getArg(args, '--hosted-target'),
    preset: (getArg(args, '--preset') as 'serious-local' | 'serious-end-to-end' | 'smoke' | 'diagnostic' | undefined),
    linuxRuntime: (getArg(args, '--linux-runtime') as 'container' | 'fail' | 'skip' | undefined) ?? 'container',
  });

  console.log('Security Lab Doctor');
  console.log('===================');
  for (const check of result.checks) {
    console.log(`[${check.status.toUpperCase()}] ${check.id}: ${check.message}`);
    if (check.details) {
      console.log(`  ${check.details}`);
    }
  }

  if (!result.ok) {
    process.exitCode = 1;
  }
}

void main().catch((error) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exit(1);
});
