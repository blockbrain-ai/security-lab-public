/**
 * Role scorecard — formats portfolio benchmark results for
 * human review and evidence capture.
 */

import type { BenchmarkResult, RoleScorecard } from './portfolio-bench.js';

export function renderBenchmarkReport(result: BenchmarkResult): string {
  const lines = [
    '# Portfolio Benchmark Report',
    '',
    `Run: ${result.runAt}`,
    `Fixtures: ${result.config.fixtureIds.join(', ')}`,
    '',
    '## Recommended Portfolio',
    '',
    `Planner: ${result.recommendedPortfolio.planner.provider}/${result.recommendedPortfolio.planner.model}`,
    `Judge: ${result.recommendedPortfolio.judge.provider}/${result.recommendedPortfolio.judge.model}`,
  ];

  if (result.recommendedPortfolio.synthesizer) {
    lines.push(`Synthesizer: ${result.recommendedPortfolio.synthesizer.provider}/${result.recommendedPortfolio.synthesizer.model}`);
  }
  if (result.recommendedPortfolio.counterPlanner) {
    lines.push(`Counter-planner: ${result.recommendedPortfolio.counterPlanner.provider}/${result.recommendedPortfolio.counterPlanner.model}`);
  }

  lines.push('');
  lines.push(`Backed by data: ${result.recommendedPortfolio.backedByData}`);
  lines.push(`Reasoning: ${result.recommendedPortfolio.reasoning}`);
  lines.push('');

  lines.push('## Role Scorecards');
  lines.push('');

  const byRole = new Map<string, RoleScorecard[]>();
  for (const sc of result.roleScorecards) {
    const list = byRole.get(sc.role) ?? [];
    list.push(sc);
    byRole.set(sc.role, list);
  }

  for (const [role, scorecards] of byRole) {
    lines.push(`### ${role}`);
    lines.push('');
    lines.push('| Provider/Model | Recall | Precision | Chain Rate | Dormant Contrib | Cost/Signal | Cost/Chain |');
    lines.push('|---|---|---|---|---|---|---|');

    for (const sc of scorecards) {
      const m = sc.metrics;
      lines.push(
        `| ${sc.provider}/${sc.model} | ${m.signalRecall.toFixed(2)} | ${m.precision.toFixed(2)} | ${m.chainConfirmationRate.toFixed(2)} | ${m.dormantReactivationContribution.toFixed(2)} | $${m.costPerUsefulSignal.toFixed(3)} | $${m.costPerConfirmedChain.toFixed(3)} |`,
      );
    }
    lines.push('');
  }

  return lines.join('\n');
}
