/**
 * Regression promoter — converts confirmed chain findings into
 * replayable YAML regression packs. These become permanent fixtures
 * that prevent regression on known vulnerabilities.
 */

import { writeFile, mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { ChainFinding, ChainHypothesis } from './contracts.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RegressionPack {
  id: string;
  name: string;
  description: string;
  severity: string;
  source: {
    campaignId: string;
    hypothesisId: string;
    confirmedAt: string;
  };
  steps: RegressionStep[];
  involvedDormantReactivation: boolean;
}

export interface RegressionStep {
  id: string;
  title: string;
  description: string;
}

// ---------------------------------------------------------------------------
// Promotion
// ---------------------------------------------------------------------------

export function buildRegressionPack(
  campaignId: string,
  hypothesis: ChainHypothesis,
  finding: ChainFinding,
): RegressionPack {
  return {
    id: `regression-${hypothesis.id}`,
    name: `Regression: ${finding.description.split('\n')[0]?.slice(0, 80)}`,
    description: finding.description,
    severity: finding.severity,
    source: {
      campaignId,
      hypothesisId: hypothesis.id,
      confirmedAt: finding.confirmedAt,
    },
    steps: finding.reproductionSteps.map((step, i) => ({
      id: `step-${i + 1}`,
      title: `Step ${i + 1}`,
      description: step,
    })),
    involvedDormantReactivation: finding.involvedDormantReactivation,
  };
}

export async function saveRegressionPack(
  pack: RegressionPack,
  outputDir: string,
): Promise<string> {
  await mkdir(outputDir, { recursive: true });
  const filePath = resolve(outputDir, `${pack.id}.json`);
  await writeFile(filePath, JSON.stringify(pack, null, 2), 'utf8');
  return filePath;
}

export function formatRegressionSummary(packs: RegressionPack[]): string {
  if (packs.length === 0) return 'No regression packs generated.';

  const lines = [
    `# Regression Packs (${packs.length})`,
    '',
    ...packs.map((p) => {
      const dormant = p.involvedDormantReactivation ? ' [dormant reactivation]' : '';
      return `- **[${p.severity}]** ${p.name}${dormant}\n  ${p.steps.length} steps | Source: ${p.source.campaignId}`;
    }),
  ];

  return lines.join('\n');
}
