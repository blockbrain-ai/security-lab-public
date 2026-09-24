import { loadRunfile } from '../loaders/runfile-loader.js';
import { SecurityLabRunner } from '../runs/security-lab-runner.js';

interface CliOptions {
  runfilePath: string;
}

function parseArgs(argv: string[]): CliOptions {
  const args = argv.slice(2);

  if (args.includes('--help') || args.includes('-h')) {
    printHelp();
    process.exit(0);
  }

  return {
    runfilePath: args[0] ?? 'runfiles/fixture-http-smoke.yaml',
  };
}

function printHelp(): void {
  console.log('Usage: npm run lab:run -- [runfile]');
  console.log('');
  console.log('Examples:');
  console.log('  npm run lab:run -- runfiles/fixture-http-smoke.yaml');
  console.log('  npm run lab:run -- runfiles/fixture-chain-canary.yaml');
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv);
  const runfile = await loadRunfile(options.runfilePath);
  const runner = new SecurityLabRunner();
  const { summary, runDir } = await runner.run(runfile);

  console.log(`Run ID: ${summary.runId}`);
  console.log(`Run dir: ${runDir}`);
  console.log(`Mode: ${summary.mode}`);
  console.log(`Passed: ${summary.passed}/${summary.scenarioCount}`);

  if (summary.failed > 0) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});

