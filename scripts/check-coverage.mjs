import { execSync } from 'node:child_process';

const output = execSync('npm run test:coverage', {
  cwd: new URL('..', import.meta.url),
  encoding: 'utf8',
  stdio: ['inherit', 'pipe', 'inherit'],
});

process.stdout.write(output);

const matches = [...output.matchAll(/all files\s+\|\s+(\d+\.\d+)/g)].map((match) => Number(match[1]));

if (matches.length < 3) {
  throw new Error(`Expected at least 3 coverage summaries, found ${matches.length}`);
}

const [attackLabLine, evidencePlaneLine, securityRuntimeLine] = matches;

const thresholds = [
  { label: 'attack-lab', actual: attackLabLine, required: 90 },
  { label: 'evidence-plane', actual: evidencePlaneLine, required: 95 },
  { label: 'security-runtime', actual: securityRuntimeLine, required: 95 },
];

const failures = thresholds.filter((entry) => entry.actual < entry.required);
if (failures.length > 0) {
  const formatted = failures.map((entry) => `${entry.label} ${entry.actual.toFixed(2)}% < ${entry.required}%`).join(', ');
  throw new Error(`Coverage gate failed: ${formatted}`);
}

console.log('\nCoverage gates passed.');
