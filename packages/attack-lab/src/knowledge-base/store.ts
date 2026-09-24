/**
 * Knowledge base store — persists target-scoped knowledge under a
 * versioned local store. Only human-approved or evidence-backed
 * artifacts can be promoted into reusable knowledge.
 */

import { readFile, writeFile, rename, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { KnowledgeBase, PriorFinding, RefutedChain, RegressionPackRef, DependencyDecision, TargetFingerprint } from './contracts.js';

const KNOWLEDGE_BASE_VERSION = '1.0.0';

// ---------------------------------------------------------------------------
// Persistence (atomic tmp+mv)
// ---------------------------------------------------------------------------

export async function loadKnowledgeBase(filePath: string): Promise<KnowledgeBase | null> {
  try {
    const content = await readFile(filePath, 'utf8');
    return JSON.parse(content);
  } catch {
    return null;
  }
}

export async function saveKnowledgeBase(kb: KnowledgeBase, filePath: string): Promise<void> {
  await mkdir(dirname(filePath), { recursive: true });
  const tmp = `${filePath}.tmp`;
  kb.updatedAt = new Date().toISOString();
  await writeFile(tmp, JSON.stringify(kb, null, 2), 'utf8');
  await rename(tmp, filePath);
}

export function createEmptyKnowledgeBase(targetFamily: string): KnowledgeBase {
  return {
    version: KNOWLEDGE_BASE_VERSION,
    updatedAt: new Date().toISOString(),
    targetFamily,
    findings: [],
    refutedChains: [],
    regressionPacks: [],
    dependencyDecisions: [],
    fingerprints: [],
  };
}

// ---------------------------------------------------------------------------
// Retrieval
// ---------------------------------------------------------------------------

export function getRelevantFindings(
  kb: KnowledgeBase,
  targetFingerprint: string,
  targetFamily: string,
): PriorFinding[] {
  return kb.findings.filter(
    (f) => f.targetFamily === targetFamily || f.targetFingerprint === targetFingerprint,
  );
}

export function getRefutedChains(
  kb: KnowledgeBase,
  targetFingerprint: string,
  targetFamily: string,
): RefutedChain[] {
  return kb.refutedChains.filter(
    (r) => r.targetFamily === targetFamily || r.targetFingerprint === targetFingerprint,
  );
}

export function getRegressionPacks(
  kb: KnowledgeBase,
  targetFingerprint: string,
): RegressionPackRef[] {
  return kb.regressionPacks.filter((r) => r.targetFingerprint === targetFingerprint);
}

export function getDependencyDecisions(
  kb: KnowledgeBase,
  targetFingerprint: string,
): DependencyDecision[] {
  return kb.dependencyDecisions.filter((d) => d.targetFingerprint === targetFingerprint);
}

// ---------------------------------------------------------------------------
// Promotion (add records to the knowledge base)
// ---------------------------------------------------------------------------

export function addFinding(kb: KnowledgeBase, finding: PriorFinding): void {
  // Deduplicate by description + target fingerprint
  const exists = kb.findings.some(
    (f) => f.description === finding.description && f.targetFingerprint === finding.targetFingerprint,
  );
  if (!exists) kb.findings.push(finding);
}

export function addRefutedChain(kb: KnowledgeBase, refuted: RefutedChain): void {
  const exists = kb.refutedChains.some(
    (r) => r.description === refuted.description && r.targetFingerprint === refuted.targetFingerprint,
  );
  if (!exists) kb.refutedChains.push(refuted);
}

export function addRegressionPack(kb: KnowledgeBase, pack: RegressionPackRef): void {
  if (!kb.regressionPacks.some((p) => p.id === pack.id)) {
    kb.regressionPacks.push(pack);
  }
}

export function addDependencyDecision(kb: KnowledgeBase, decision: DependencyDecision): void {
  // Update existing or add new
  const idx = kb.dependencyDecisions.findIndex(
    (d) => d.packageName === decision.packageName && d.targetFingerprint === decision.targetFingerprint,
  );
  if (idx >= 0) {
    kb.dependencyDecisions[idx] = decision;
  } else {
    kb.dependencyDecisions.push(decision);
  }
}

export function addFingerprint(kb: KnowledgeBase, fp: TargetFingerprint): void {
  kb.fingerprints.push(fp);
}

// ---------------------------------------------------------------------------
// Summarize for model context
// ---------------------------------------------------------------------------

export function summarizeKnowledgeBase(
  kb: KnowledgeBase,
  targetFingerprint: string,
  maxChars: number = 5000,
): string {
  const findings = getRelevantFindings(kb, targetFingerprint, kb.targetFamily);
  const refuted = getRefutedChains(kb, targetFingerprint, kb.targetFamily);

  const lines = [
    `## Prior Knowledge (${kb.targetFamily})`,
    `Version: ${kb.version}`,
    `Updated: ${kb.updatedAt}`,
    '',
  ];

  if (findings.length > 0) {
    lines.push(`### Prior Confirmed Findings (${findings.length})`);
    for (const f of findings.slice(0, 10)) {
      lines.push(`- [${f.severity}] ${f.description.split('\n')[0]?.slice(0, 100)}`);
    }
    lines.push('');
  }

  if (refuted.length > 0) {
    lines.push(`### Previously Refuted Chains — Do Not Retry (${refuted.length})`);
    for (const r of refuted.slice(0, 10)) {
      lines.push(`- ${r.description.split('\n')[0]?.slice(0, 100)} (refuted: ${r.refutationEvidence.slice(0, 60)})`);
    }
    lines.push('');
  }

  const result = lines.join('\n');
  return result.length > maxChars ? result.slice(0, maxChars) + '\n[...truncated]' : result;
}
