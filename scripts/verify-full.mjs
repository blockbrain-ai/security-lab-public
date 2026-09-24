import { spawnSync } from 'node:child_process';

const cwd = new URL('..', import.meta.url);

function run(args) {
  const result = spawnSync('npm', args, {
    cwd,
    stdio: 'inherit',
    shell: false,
  });

  if (result.status !== 0) {
    throw new Error(`Command failed: npm ${args.join(' ')}`);
  }
}

run(['run', 'build']);
run(['test']);
run(['run', 'fixture:smoke']);
run(['run', 'verify:campaign-soak']);
run(['run', '--silent', 'check-coverage']);

console.log('\nFull verification passed.');
