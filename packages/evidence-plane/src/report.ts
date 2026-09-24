import type { RunSummary, ScenarioRecord } from './contracts.js';

export function renderMarkdownReport(summary: RunSummary): string {
  const lines = [
    `# Security Lab Report — ${summary.runId}`,
    '',
    `- Runfile: \`${summary.runfileId}\` (${summary.runfileName})`,
    `- Mode: ${summary.mode}`,
    `- Started: ${summary.startedAt}`,
    `- Completed: ${summary.completedAt}`,
    `- Scenarios: ${summary.scenarioCount}`,
    `- Passed: ${summary.passed}`,
    `- Failed: ${summary.failed}`,
    `- Target environments: ${summary.targetEnvironments.join(', ')}`,
    `- Planner: ${summary.orchestration.planner}`,
    `- Executor: ${summary.orchestration.executor}`,
    `- Judge: ${summary.orchestration.judge}`,
    `- Reporter: ${summary.orchestration.reporter}`,
    '',
    '## Scenario Results',
    '',
  ];

  for (const record of summary.records) {
    lines.push(renderScenario(record));
  }

  return lines.join('\n');
}

function renderScenario(record: ScenarioRecord): string {
  const lines = [
    `### ${record.scenarioId} — ${record.title}`,
    `- Severity: ${record.severity}`,
    `- Passed: ${record.passed ? 'yes' : 'no'}`,
    `- Attempt: ${record.scores.attempt}`,
    `- Block: ${record.scores.block}`,
    `- Outcome: ${record.scores.outcome}`,
    `- Stealth: ${record.scores.stealth}`,
  ];

  if (record.residualRisk) {
    lines.push(`- Residual risk: ${record.residualRisk}`);
  }

  lines.push('');

  for (const step of record.steps) {
    lines.push(`#### ${step.stepId} — ${step.stepTitle}`);
    lines.push(`- Observed safety state: ${step.verdict.observedSafetyState}`);
    lines.push(`- Expectation met: ${step.verdict.expectationMet ? 'yes' : 'no'}`);
    if (step.verdict.blockSource) {
      lines.push(`- Block source: ${step.verdict.blockSource}`);
    }
    if (step.verdict.residualRisk) {
      lines.push(`- Residual risk: ${step.verdict.residualRisk}`);
    }
    if (step.observation.statusCode !== undefined) {
      lines.push(`- HTTP status: ${step.observation.statusCode}`);
    }
    if (step.observation.exitCode !== undefined) {
      lines.push(`- Exit code: ${step.observation.exitCode}`);
    }
    if (Object.keys(step.captures).length > 0) {
      lines.push(`- Captures: ${Object.entries(step.captures).map(([key, value]) => `${key}=${value}`).join(', ')}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

export function renderConsoleSummary(summary: RunSummary): string[] {
  const lines = [
    `Run: ${summary.runId}`,
    `Runfile: ${summary.runfileId} (${summary.runfileName})`,
    `Mode: ${summary.mode}`,
    `Passed: ${summary.passed}/${summary.scenarioCount}`,
    `Failed: ${summary.failed}`,
    '',
  ];

  for (const record of summary.records) {
    lines.push(
      `- ${record.scenarioId}: ${record.passed ? 'PASS' : 'FAIL'} (${record.scores.outcome}, ${record.scores.block})`,
    );
  }

  return lines;
}

