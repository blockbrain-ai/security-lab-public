import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { EvidenceStore } from '../packages/evidence-plane/src/store.js';
import type { InvestigationReportData } from '../packages/evidence-plane/src/investigation-report.js';
import {
  toCampaignAssessmentArtifact,
  type CampaignAssessment,
} from '../packages/attack-lab/src/orchestration/campaign-assessment.js';

function getArg(args: string[], flag: string): string | null {
  const index = args.indexOf(flag);
  if (index === -1) return null;
  return args[index + 1] ?? null;
}

async function readJson<T>(path: string): Promise<T | null> {
  try {
    return JSON.parse(await readFile(path, 'utf8')) as T;
  } catch {
    return null;
  }
}

function repairSummary(
  summary: InvestigationReportData,
  assessment: CampaignAssessment | null,
): InvestigationReportData {
  const effectiveAssessment = assessment ?? summary.executiveAssessment ?? summary.campaignAssessment ?? null;
  const verificationLanes = summary.verificationLanes;

  const repaired: InvestigationReportData = {
    ...summary,
    verificationLanes,
    localLive: summary.localLive ?? verificationLanes?.localLive ?? null,
    testSynthesis: summary.testSynthesis ?? verificationLanes?.testSynthesis ?? null,
    hosted: summary.hosted ?? verificationLanes?.hosted ?? undefined,
    supplyChain: summary.supplyChain ?? verificationLanes?.supplyChain ?? undefined,
  };

  if (effectiveAssessment) {
    repaired.executiveAssessment = effectiveAssessment;
    repaired.campaignAssessment = summary.campaignAssessment ?? effectiveAssessment;
    repaired.executiveVerdict = summary.executiveVerdict ?? effectiveAssessment.overallVerdict;
    repaired.assessmentParseStatus = summary.assessmentParseStatus ?? effectiveAssessment.parseStatus;
    repaired.assessmentVerdict = summary.assessmentVerdict ?? effectiveAssessment.overallVerdict ?? null;
    repaired.assessmentConfidence = summary.assessmentConfidence ?? effectiveAssessment.confidence ?? null;
    repaired.assessmentSummary = summary.assessmentSummary ?? effectiveAssessment.summary ?? null;
  }

  if (repaired.executionStatus == null && verificationLanes?.executionStatus) {
    repaired.executionStatus = verificationLanes.executionStatus;
  }
  if (repaired.requiredCoverageSatisfied == null && verificationLanes?.requiredCoverageSatisfied != null) {
    repaired.requiredCoverageSatisfied = verificationLanes.requiredCoverageSatisfied;
  }
  if (repaired.meaningfulAttempts == null && verificationLanes?.meaningfulAttempts != null) {
    repaired.meaningfulAttempts = verificationLanes.meaningfulAttempts;
  }
  if (!repaired.laneCosts && verificationLanes?.laneCosts) {
    repaired.laneCosts = verificationLanes.laneCosts;
  }

  return repaired;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const campaignId = args[0];
  if (!campaignId || campaignId.startsWith('-')) {
    throw new Error('Usage: npm run repair:campaign-artifacts -- <campaign-id> [--campaign-dir <path>]');
  }

  const campaignDir = resolve(getArg(args, '--campaign-dir') ?? 'data/campaigns');
  const evidenceStore = new EvidenceStore(campaignId, resolve(campaignDir, 'runs'));
  await evidenceStore.prepare();

  const summary = await readJson<InvestigationReportData>(evidenceStore.paths.summaryPath);
  if (!summary) {
    throw new Error(`Missing summary.json for campaign ${campaignId} at ${evidenceStore.paths.summaryPath}`);
  }

  const assessment = await readJson<CampaignAssessment>(
    resolve(evidenceStore.paths.runDir, 'campaign-assessment.json'),
  );
  const repairedSummary = repairSummary(summary, assessment);

  if (assessment) {
    await evidenceStore.writeJsonArtifact('campaign-assessment.json', toCampaignAssessmentArtifact(assessment));
  }
  await evidenceStore.writeInvestigationSummary(repairedSummary);

  console.log(`Repaired campaign artifacts for ${campaignId}`);
  console.log(`Run dir: ${evidenceStore.paths.runDir}`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
