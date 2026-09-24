import { resolve } from 'node:path';
import { readFile, writeFile, appendFile } from 'node:fs/promises';
import { createAdapter } from '../providers/adapter-factory.js';
import { tryParseStructured } from '../providers/parse-structured.js';
import { executeGate } from './gate-supervisor.js';
import {
  SourceVerificationResultSchema,
  DefenseCriticResultSchema,
  validateSupportedRefs,
  type SourceVerificationResult,
  type SourceVerificationArtifact,
  type DefenseCriticResult,
} from './source-verify-schemas.js';
import {
  buildPerCandidateSourcePrompt,
  buildBugClassAuditPrompt,
  buildDefenseCriticPrompt,
  type CandidateInfo,
} from './source-verify-prompts.js';
import type { ModelConfig } from '../providers/contracts.js';
import type {
  CampaignAssessmentPacket,
  AssessmentEvidenceSignal,
  AssessmentEvidenceHypothesis,
  AssessmentEvidenceFinding,
} from '../orchestration/campaign-assessment.js';
import type { RunMonitor } from './run-monitor.js';
import { classifyBugFamily, resolveReviewPolicy } from './review-policy.js';
import {
  behaviorForLevel,
  checkNoProgressTimeout,
  gateClassToAnomalyKind,
  recordProgress,
  recordAnomaly,
  type DegradationState,
  type DegradationThresholds,
  DEFAULT_THRESHOLDS,
} from './degradation-ladder.js';
import { z } from 'zod';

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

export interface SourceVerifyOptions {
  reportPath: string;
  campaignId?: string;
  targetId: string;
  repoRoot: string;
  outputDir: string;
  provider: 'bounded_local' | 'pi_cli' | 'claude_code' | 'codex_cli';
  model: string;
  baseUrl?: string;
  dryRun: boolean;
  candidateLimit?: number;
  skipAudit?: boolean;
  piToolAllowlist?: string[];
  piMaxTokens?: number;
  monitor?: RunMonitor;
  criticProvider?: string;
  criticModel?: string;
  criticBaseUrl?: string;
  degradationState?: DegradationState;
  degradationThresholds?: DegradationThresholds;
}

export interface SourceVerifyResult {
  artifact: SourceVerificationArtifact;
  artifactPath: string;
  costUsd: number;
}

export interface DefenseCriticOverrideDecision {
  status: 'weakened' | 'needs_runtime';
  notes: string;
}

export interface DefendedFindingDecision {
  status: 'supported' | 'weakened' | 'needs_runtime';
  notes: string[];
}

const PLACEHOLDER_PATTERNS = /^(n\/?a|none|not applicable|todo|tbd|placeholder|unknown|see above|—|-|\.{1,3})$/i;

function isSubstantive(value: string | undefined | null): boolean {
  if (!value) return false;
  const trimmed = value.trim();
  return trimmed.length > 3 && !PLACEHOLDER_PATTERNS.test(trimmed);
}

export function resolveDefendedFindingStatus(
  result: SourceVerificationResult,
): DefendedFindingDecision | null {
  const isPositive = result.status === 'supported' || result.status === 'weakened';
  if (!isPositive || result.defenseMechanismsObserved.length === 0) return null;

  const hasConcreteSink = Boolean(
    result.residualSinkRef?.file && isSubstantive(result.residualSinkRef.snippet),
  );
  const hasConcreteBypass = isSubstantive(result.residualBypassPath);
  const hasConcreteProof = isSubstantive(result.proofPayload) && isSubstantive(result.postDefenseSnippet);
  const hasAssumptions = result.assumptions.length > 0;

  if (hasConcreteSink && hasConcreteBypass && hasConcreteProof && !hasAssumptions) {
    return {
      status: result.status === 'supported' ? 'supported' : 'weakened',
      notes: [],
    };
  }

  const notes = [
    '[primary-proof] defended supported/weakened finding downgraded to needs_runtime because residual-risk proof obligations were not satisfied.',
  ];
  if (!hasConcreteSink) notes.push('Missing residualSinkRef.');
  if (!hasConcreteBypass) notes.push('Missing residualBypassPath.');
  if (!hasConcreteProof) notes.push('Missing proofPayload/postDefenseSnippet.');
  if (hasAssumptions) {
    notes.push(`Assumptions: ${result.assumptions.join('; ')}`);
  }

  return {
    status: 'needs_runtime',
    notes,
  };
}

export function resolveDefenseCriticOverride(
  critic: DefenseCriticResult,
): DefenseCriticOverrideDecision | null {
  if (critic.defenseValid || !critic.overrideStatus) return null;

  const hasConcreteSink = Boolean(
    critic.sinkRef?.file && isSubstantive(critic.sinkRef.snippet),
  );
  if (!hasConcreteSink) return null;

  if (critic.overrideStatus === 'needs_runtime') {
    return {
      status: 'needs_runtime',
      notes: critic.reasoning,
    };
  }

  const hasConcreteBypass = isSubstantive(critic.bypassPath);
  const hasConcreteProof = isSubstantive(critic.proofPayload) && isSubstantive(critic.postDefenseSnippet);
  const hasAssumptions = critic.assumptions.length > 0;

  if (hasConcreteBypass && hasConcreteProof && !hasAssumptions) {
    return {
      status: 'weakened',
      notes: critic.reasoning,
    };
  }

  const policyNotes = [
    '[critic-policy] downgraded override to needs_runtime because the critic did not satisfy weakened proof obligations.',
  ];
  if (!hasConcreteBypass) policyNotes.push('Missing bypassPath.');
  if (!hasConcreteProof) policyNotes.push('Missing proofPayload/postDefenseSnippet.');
  if (hasAssumptions) {
    policyNotes.push(`Assumptions: ${critic.assumptions.join('; ')}`);
  }

  return {
    status: 'needs_runtime',
    notes: `${critic.reasoning}\n\n${policyNotes.join(' ')}`,
  };
}

// ---------------------------------------------------------------------------
// Candidate extraction — cumulative accumulator with dedup
// ---------------------------------------------------------------------------

function normalizeForDedup(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9\s]/g, '').replace(/\s+/g, ' ').trim().slice(0, 160);
}

export class CandidateAccumulator {
  private candidates: CandidateInfo[] = [];
  private seenIds = new Set<string>();
  private seenNormalized = new Set<string>();

  add(candidate: CandidateInfo): boolean {
    if (this.seenIds.has(candidate.id)) return false;

    const norm = normalizeForDedup(candidate.claim);
    for (const existing of this.seenNormalized) {
      if (existing.includes(norm) || norm.includes(existing)) {
        if (norm.length > existing.length) {
          const idx = this.candidates.findIndex(c => normalizeForDedup(c.claim) === existing);
          if (idx >= 0) {
            this.seenNormalized.delete(existing);
            this.seenNormalized.add(norm);
            this.candidates[idx] = candidate;
            this.seenIds.add(candidate.id);
          }
        }
        return false;
      }
    }

    this.seenIds.add(candidate.id);
    this.seenNormalized.add(norm);
    this.candidates.push(candidate);
    return true;
  }

  getAll(): CandidateInfo[] {
    return [...this.candidates];
  }

  get size(): number {
    return this.candidates.length;
  }

  existingIds(): string[] {
    return [...this.seenIds];
  }
}

function makeSlug(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 40);
}

export function extractCandidatesFromAssessmentObject(
  assessment: Record<string, unknown>,
  source: string,
  acc: CandidateAccumulator,
): void {
  const categories = ['confirmedVulnerabilities', 'validatedRisks', 'configurationRisks', 'unconfirmedLeads'];
  for (const category of categories) {
    const items = assessment[category] as Array<Record<string, unknown>> | undefined;
    if (!items || items.length === 0) continue;
    for (const item of items) {
      const title = (item.title ?? item.description ?? '') as string;
      if (!title) continue;
      const severity = (item.severity as string | undefined) ?? undefined;
      acc.add({
        id: `${source}-${category}-${makeSlug(title)}`,
        claim: title,
        context: [
          item.description !== title ? (item.description as string) : '',
          item.evidenceRefs ? `Evidence refs: ${(item.evidenceRefs as string[]).join(', ')}` : '',
          item.requiredConditions ? `Conditions: ${(item.requiredConditions as string[]).join('; ')}` : '',
        ].filter(Boolean).join('\n'),
        source: `${source}_${category}`,
        severity,
      });
    }
  }
}

export function extractCandidatesFromEmbeddedAssessment(
  assessment: Record<string, unknown>,
  acc: CandidateAccumulator,
): void {
  const fields = ['summary', 'executiveSummary'] as const;
  for (const field of fields) {
    const value = assessment[field];
    if (typeof value !== 'string') continue;
    const trimmed = value.trim();
    if (!trimmed.startsWith('{')) continue;
    try {
      const embedded = JSON.parse(trimmed) as Record<string, unknown>;
      extractCandidatesFromAssessmentObject(embedded, `embedded_${field}`, acc);
    } catch {
      // not valid JSON
    }
  }
}

export async function extractCandidatesFromPacket(
  campaignDir: string,
  acc: CandidateAccumulator,
): Promise<void> {
  let raw: string;
  try {
    raw = await readFile(resolve(campaignDir, 'campaign-assessment.packet.json'), 'utf8');
  } catch {
    return;
  }
  let packet: CampaignAssessmentPacket;
  try {
    packet = JSON.parse(raw) as CampaignAssessmentPacket;
  } catch {
    return;
  }

  if (packet.confirmedFindings) {
    for (const f of packet.confirmedFindings as AssessmentEvidenceFinding[]) {
      acc.add({
        id: `pf-${makeSlug(f.id || f.description)}`,
        claim: f.description,
        context: f.reproductionSteps?.length ? `Reproduction: ${f.reproductionSteps.join('; ')}` : '',
        source: 'packet_finding',
        severity: f.severity,
      });
    }
  }

  if (packet.testedHypotheses) {
    for (const h of packet.testedHypotheses as AssessmentEvidenceHypothesis[]) {
      acc.add({
        id: `ph-${makeSlug(h.id || h.description)}`,
        claim: h.description,
        context: [
          h.latestVerdict ? `Latest verdict: ${h.latestVerdict}` : '',
          h.relatedAssets?.length ? `Assets: ${h.relatedAssets.join(', ')}` : '',
        ].filter(Boolean).join('\n'),
        source: 'packet_hypothesis',
        severity: h.severity,
        signalIds: h.signalIds,
        relatedAssets: h.relatedAssets,
      });
    }
  }

  if (packet.topSignals) {
    for (const s of packet.topSignals as AssessmentEvidenceSignal[]) {
      if (s.status === 'refuted') continue;
      if (s.confidence < 0.5) continue;
      acc.add({
        id: `ps-${makeSlug(s.id || s.description)}`,
        claim: s.description,
        context: s.relatedAssets?.length ? `Assets: ${s.relatedAssets.join(', ')}` : '',
        source: 'packet_signal',
        confidence: s.confidence,
        relatedAssets: s.relatedAssets,
      });
    }
  }
}

export async function extractCandidatesFromEvents(
  campaignDir: string,
  acc: CandidateAccumulator,
): Promise<void> {
  const eventsPath = resolve(campaignDir, 'events.jsonl');
  let raw: string;
  try {
    raw = await readFile(eventsPath, 'utf8');
  } catch {
    return;
  }
  for (const line of raw.split('\n')) {
    if (!line.trim()) continue;
    try {
      const event = JSON.parse(line) as Record<string, unknown>;
      if (event.stage !== 'planner_hypothesis_grounded') continue;
      const payload = event.payload as Record<string, unknown> | undefined;
      if (!payload) continue;
      const description = (payload.description ?? '') as string;
      if (!description) continue;
      const signalIds = (payload.groundedSignalIds ?? []) as string[];
      const iteration = (payload.iteration ?? event.iteration ?? '') as string | number;
      acc.add({
        id: `ev-${makeSlug(`${iteration}-${description}`)}`,
        claim: description,
        context: signalIds.length ? `Grounded signals: ${signalIds.join(', ')}` : '',
        source: 'event_grounded',
        signalIds,
      });
    } catch {
      // skip malformed lines
    }
  }
}

export function extractCandidatesFromReport(reportContent: string): CandidateInfo[] {
  const acc = new CandidateAccumulator();
  extractCandidatesFromReportInto(reportContent, acc);
  return acc.getAll();
}

export function extractCandidatesFromReportInto(
  reportContent: string,
  acc: CandidateAccumulator,
): void {
  // Strategy 1: Extract from "Evidence Leads" section
  const evidenceLeadsMatch = reportContent.match(
    /## Evidence Leads[^\n]*\n([\s\S]*?)(?=\n---|\n## )/,
  );
  if (evidenceLeadsMatch) {
    const leadPattern = /- \*\*\[([^\]]+)\]\*\* \([^)]*conf=([0-9.]+)[^)]*\)\s*(.+?)(?:\s*\|\s*assets=(.+))?$/gm;
    let match;
    while ((match = leadPattern.exec(evidenceLeadsMatch[1])) !== null) {
      const [, id, confStr, description, assets] = match;
      acc.add({
        id: id!,
        claim: description!.trim(),
        context: assets ? `Referenced files: ${assets.trim()}` : '',
        source: 'report_lead',
        confidence: confStr ? parseFloat(confStr) : undefined,
      });
    }
  }

  // Strategy 2: Extract from assessment JSON embedded in report
  const assessmentMatch = reportContent.match(
    /## Executive Assessment[\s\S]*?(?:Summary:|Assessment:)\s*(\{[\s\S]*?\n\})/,
  );
  if (assessmentMatch) {
    try {
      const assessment = JSON.parse(assessmentMatch[1]) as Record<string, unknown>;
      extractCandidatesFromAssessmentObject(assessment, 'report_assessment', acc);
    } catch {
      // JSON parse failure
    }
  }
}

export async function extractCandidatesFromCampaign(
  campaignDir: string,
  reportContent: string,
): Promise<CandidateInfo[]> {
  const acc = new CandidateAccumulator();

  // 1. campaign-assessment.json normal arrays
  try {
    const assessmentPath = resolve(campaignDir, 'campaign-assessment.json');
    const raw = await readFile(assessmentPath, 'utf8');
    const assessment = JSON.parse(raw) as Record<string, unknown>;
    extractCandidatesFromAssessmentObject(assessment, 'assessment', acc);

    // 2. Embedded assessment JSON in summary/executiveSummary
    extractCandidatesFromEmbeddedAssessment(assessment, acc);
  } catch {
    // assessment not available
  }

  // 3. campaign-assessment.packet.json
  await extractCandidatesFromPacket(campaignDir, acc);

  // 4. events.jsonl
  await extractCandidatesFromEvents(campaignDir, acc);

  // 5. Report markdown — always (not just as fallback)
  extractCandidatesFromReportInto(reportContent, acc);

  return acc.getAll();
}

// ---------------------------------------------------------------------------
// Source verification runner
// ---------------------------------------------------------------------------

export async function runSourceVerification(
  options: SourceVerifyOptions,
): Promise<SourceVerifyResult> {
  const reportContent = await readFile(options.reportPath, 'utf8');

  // Extract candidates
  const campaignDir = options.campaignId
    ? resolve('data', 'campaigns', 'runs', options.campaignId)
    : undefined;
  const allCandidates = campaignDir
    ? await extractCandidatesFromCampaign(campaignDir, reportContent)
    : extractCandidatesFromReport(reportContent);

  const candidates = options.candidateLimit
    ? allCandidates.slice(0, options.candidateLimit)
    : allCandidates;

  console.log(`Extracted ${allCandidates.length} candidates:`);
  for (const c of allCandidates) {
    const tag = c.source ? ` [${c.source}${c.severity ? ` ${c.severity}` : ''}]` : '';
    console.log(`- ${c.id}${tag} ${c.claim.slice(0, 80)}${c.claim.length > 80 ? '...' : ''}`);
  }
  if (options.candidateLimit && allCandidates.length > candidates.length) {
    console.log(`(limited to ${candidates.length})`);
  }

  if (candidates.length === 0) {
    console.log('No candidates found. Skipping source verification.');
    const artifact: SourceVerificationArtifact = {
      campaignId: options.campaignId ?? 'unknown',
      targetId: options.targetId,
      timestamp: new Date().toISOString(),
      candidates: [],
    };
    const artifactPath = resolve(options.outputDir, 'source-verification.json');
    await writeFile(artifactPath, JSON.stringify(artifact, null, 2), 'utf8');
    return { artifact, artifactPath, costUsd: 0 };
  }

  if (options.dryRun) {
    console.log('\n=== DRY RUN — Source verification prompts ===\n');
    for (const candidate of candidates) {
      const prompt = buildPerCandidateSourcePrompt(candidate, options.repoRoot, options.targetId);
      console.log(`--- Candidate: ${candidate.id} ---`);
      console.log(`Prompt length: ${prompt.length} chars`);
      console.log(prompt.slice(0, 500) + '...\n');
    }
    if (!options.skipAudit) {
      const auditPrompt = buildBugClassAuditPrompt(
        options.repoRoot,
        options.targetId,
        candidates.map(c => c.id),
      );
      console.log('--- Bug-class audit ---');
      console.log(`Prompt length: ${auditPrompt.length} chars`);
      console.log(auditPrompt.slice(0, 500) + '...\n');
    }
    const artifact: SourceVerificationArtifact = {
      campaignId: options.campaignId ?? 'unknown',
      targetId: options.targetId,
      timestamp: new Date().toISOString(),
      candidates: [],
    };
    return { artifact, artifactPath: '', costUsd: 0 };
  }

  // Build adapter config
  const config: ModelConfig = {
    provider: options.provider,
    model: options.model,
    baseUrl: options.baseUrl,
    localInference: options.provider === 'pi_cli' || options.provider === 'bounded_local',
    piToolAllowlist: options.piToolAllowlist ?? ['read', 'grep', 'find', 'ls', 'bash'],
    piMaxTokens: options.piMaxTokens ?? 4096,
    workingDirectory: options.repoRoot,
  };
  const adapter = createAdapter(config);

  // Separate critic adapter when critic overrides are provided
  const hasCriticOverride = options.criticModel && (
    options.criticModel !== options.model ||
    options.criticBaseUrl !== options.baseUrl ||
    (options.criticProvider && options.criticProvider !== options.provider)
  );
  const criticAdapter = hasCriticOverride
    ? createAdapter({
        provider: (options.criticProvider ?? options.provider) as ModelConfig['provider'],
        model: options.criticModel!,
        baseUrl: options.criticBaseUrl ?? options.baseUrl,
        localInference: true,
        workingDirectory: options.repoRoot,
      })
    : adapter;

  const sessionLogPath = resolve(options.outputDir, 'source-verification-session.jsonl');
  let totalCost = 0;
  const results: SourceVerificationResult[] = [];

  const degradation = options.degradationState;
  const degThresholds = options.degradationThresholds ?? DEFAULT_THRESHOLDS;

  const noteDegradationProgress = (): void => {
    if (!degradation) return;
    const now = new Date().toISOString();
    const { escalated, newLevel } = checkNoProgressTimeout(
      degradation,
      degradation.lastActivityAt,
      now,
      degThresholds,
    );
    if (escalated) {
      console.log(`Degradation: escalated to level ${newLevel} due to inactivity`);
    }
    recordProgress(degradation, now);
  };

  // Per-candidate verification
  for (let i = 0; i < candidates.length; i++) {
    if (degradation) {
      const behavior = behaviorForLevel(degradation.currentLevel);
      if (behavior.halt) {
        console.log(`Degradation level ${degradation.currentLevel}: halting remaining candidates`);
        for (let j = i; j < candidates.length; j++) {
          const skipped = candidates[j]!;
          const bugFamily = classifyBugFamily(skipped.claim, skipped.id);
          const reviewPolicy = resolveReviewPolicy({
            bugFamily,
            severity: skipped.severity as 'critical' | 'high' | 'medium' | 'low' | 'info' | undefined,
            sourceStatus: 'needs_runtime',
            confidence: skipped.confidence ?? 0,
          });
          results.push({
            candidateId: skipped.id,
            claim: skipped.claim,
            status: 'needs_runtime',
            rootCause: 'Source verification halted by degradation ladder',
            sourceRefs: [],
            preconditions: [],
            defenseMechanismsObserved: [],
            assumptions: [],
            validationNotes: ['[degradation] source verification halted before this candidate could be attempted.'],
            error: 'degradation_halt',
            confidence: 0,
            bugFamily,
            reviewPolicy,
          });
        }
        break;
      }
    }

    const candidate = candidates[i]!;
    const label = `[${i + 1}/${candidates.length}] ${candidate.id}`;
    console.log(`${label}: verifying...`);
    if (options.monitor) await options.monitor.emitCandidateStart(candidate.id, 'source');

    const prompt = buildPerCandidateSourcePrompt(candidate, options.repoRoot, options.targetId);

    try {
      const response = await adapter.invoke({
        systemPrompt: 'You are a source-code verification agent. Read the repository files to verify the security finding. Return structured JSON only. Be focused — read only the files directly relevant to the claim.',
        prompt,
        requestTimeoutMs: 600_000,
        workingDirectory: options.repoRoot,
      });

      totalCost += response.usage.costUsd;

      await appendFile(sessionLogPath, JSON.stringify({
        type: 'candidate_response',
        candidateId: candidate.id,
        content: response.content,
        usage: response.usage,
        durationMs: response.durationMs,
      }) + '\n', 'utf8');

      // Gate 1: parse + classify + repair
      const directParse = tryParseStructured(response.content, SourceVerificationResultSchema);
      const gateResult = await executeGate(SourceVerificationResultSchema, {
        gateId: `source:${candidate.id}`,
        rawContent: response.content,
        originalPrompt: prompt,
        originalSystemPrompt: 'You are a source-code verification agent.',
        model: options.model,
        workingDirectory: options.repoRoot,
        sessionLogPath,
      }, {
        parsedOutput: directParse,
        sourceResult: directParse ?? undefined,
        provider: options.provider,
      });
      totalCost += gateResult.repairCostUsd;

      if (gateResult.classification) {
        console.log(`${label}: gate(${gateResult.classification.failureClass}) ${gateResult.repairSucceeded ? 'repaired' : 'failed'}`);
        if (options.monitor) await options.monitor.emitGateRepair(candidate.id, gateResult.classification.failureClass, gateResult.repairSucceeded, gateResult.repairCostUsd, 'source');
        if (degradation) {
          const anomalyKind = gateClassToAnomalyKind(gateResult.classification.failureClass);
          if (anomalyKind) {
            const { escalated, newLevel } = recordAnomaly(degradation, { at: new Date().toISOString(), kind: anomalyKind, candidateId: candidate.id }, degThresholds);
            if (escalated) console.log(`Degradation: escalated to level ${newLevel}`);
          }
        }
      }

      if (gateResult.success && gateResult.output) {
        // Cast safe: Zod .parse() applies .default([]) so output always has full type
        const parsed = gateResult.output as SourceVerificationResult;

        const defendedFindingDecision = resolveDefendedFindingStatus(parsed);
        if (defendedFindingDecision) {
          parsed.validationNotes.push(...defendedFindingDecision.notes);
          if (defendedFindingDecision.status !== parsed.status) {
            parsed.preValidationStatus = parsed.status;
            parsed.status = defendedFindingDecision.status;
            console.log(`${label}: primary-proof downgraded ${parsed.preValidationStatus} -> ${parsed.status}`);
            if (options.monitor) await options.monitor.emitValidatorDowngrade(candidate.id, parsed.preValidationStatus!, parsed.status, defendedFindingDecision.notes, 'source');
          }
        }

        const refWarning = validateSupportedRefs(parsed);
        if (refWarning) console.log(`  ⚠ ${refWarning}`);

        // Defense-bypass critic: review refutations that cite a defense
        const criticEnabled = !degradation || behaviorForLevel(degradation.currentLevel).enableSecondaryFollowups;
        if (criticEnabled && parsed.status === 'refuted' && parsed.defenseMechanismsObserved.length > 0) {
          console.log(`${label}: running defense-bypass critic...`);
          try {
            const criticPrompt = buildDefenseCriticPrompt(candidate, parsed, options.repoRoot);
            const criticResponse = await criticAdapter.invoke({
              systemPrompt: 'You are a defense-bypass critic. Review whether the cited defense actually applies to the exact sink/context. Return JSON only.',
              prompt: criticPrompt,
              requestTimeoutMs: 600_000,
              workingDirectory: options.repoRoot,
            });
            totalCost += criticResponse.usage.costUsd;
            await appendFile(sessionLogPath, JSON.stringify({
              type: 'defense_critic_response',
              candidateId: candidate.id,
              content: criticResponse.content,
              usage: criticResponse.usage,
              durationMs: criticResponse.durationMs,
            }) + '\n', 'utf8');

            // Gate 2: critic response parse
            const criticGate = await executeGate(DefenseCriticResultSchema, {
              gateId: `source-critic:${candidate.id}`,
              rawContent: criticResponse.content,
              originalPrompt: criticPrompt,
              originalSystemPrompt: 'You are a defense-bypass critic.',
              model: options.criticModel ?? options.model,
              baseUrl: options.criticBaseUrl ?? options.baseUrl,
              workingDirectory: options.repoRoot,
              sessionLogPath,
            }, { provider: (options.criticProvider ?? options.provider) as SourceVerifyOptions['provider'] });
            totalCost += criticGate.repairCostUsd;

            const criticParsed = criticGate.output
              ? DefenseCriticResultSchema.parse(criticGate.output)
              : null;
            if (criticParsed) {
              const criticDecision = resolveDefenseCriticOverride(criticParsed);
              if (criticDecision) {
                parsed.preCriticStatus = parsed.status;
                parsed.status = criticDecision.status;
                parsed.criticNotes = criticDecision.notes;
                console.log(`${label}: critic overrode refuted -> ${parsed.status}`);
              } else if (!criticParsed.defenseValid) {
                parsed.criticNotes = `${criticParsed.reasoning}\n\n[critic-policy] kept refuted because the critic did not identify a concrete sink/context mismatch.`;
                console.log(`${label}: critic found no concrete override basis, keeping refuted`);
              }
            }
          } catch (criticErr) {
            await appendFile(sessionLogPath, JSON.stringify({
              type: 'defense_critic_error',
              candidateId: candidate.id,
              error: criticErr instanceof Error ? criticErr.message : String(criticErr),
            }) + '\n', 'utf8');
            console.log(`${label}: critic failed, keeping original refutation`);
          }
        }

        const bugFamily = classifyBugFamily(parsed.claim, parsed.candidateId, parsed.rootCause);
        const reviewPolicy = resolveReviewPolicy({
          bugFamily,
          severity: candidate.severity as 'critical' | 'high' | 'medium' | 'low' | 'info' | undefined,
          sourceStatus: parsed.status,
          confidence: parsed.confidence,
        });
        parsed.bugFamily = bugFamily;
        parsed.reviewPolicy = reviewPolicy;

        results.push(parsed);
        console.log(`${label}: ${parsed.status} (confidence: ${parsed.confidence}) [${reviewPolicy.riskTier}/${reviewPolicy.reviewMode}]`);
        if (options.monitor) await options.monitor.emitCandidateEnd(candidate.id, 'source', { status: parsed.status, confidence: parsed.confidence });
      } else {
        const fallback: SourceVerificationResult = {
          candidateId: candidate.id,
          claim: candidate.claim,
          status: 'needs_runtime',
          rootCause: 'Source verification output could not be parsed',
          sourceRefs: [],
          preconditions: [],
          defenseMechanismsObserved: [],
          assumptions: [],
          validationNotes: [],
          error: gateResult.classification ? `gate_${gateResult.classification.failureClass}` : 'structured_parse_failure',
          confidence: 0,
        };
        results.push(fallback);
        console.log(`${label}: parse_failure → needs_runtime`);
        if (options.monitor) await options.monitor.emitCandidateEnd(candidate.id, 'source', { status: 'needs_runtime', error: 'parse_failure' });
      }
    } catch (err) {
      const fallback: SourceVerificationResult = {
        candidateId: candidate.id,
        claim: candidate.claim,
        status: 'needs_runtime',
        rootCause: 'Source verification failed',
        sourceRefs: [],
        preconditions: [],
        defenseMechanismsObserved: [],
        assumptions: [],
        validationNotes: [],
        error: err instanceof Error ? err.message : String(err),
        confidence: 0,
      };
      results.push(fallback);
      console.log(`${label}: error → needs_runtime (${fallback.error})`);
      if (options.monitor) await options.monitor.emitCandidateEnd(candidate.id, 'source', { status: 'needs_runtime', error: fallback.error });
    }

    noteDegradationProgress();
  }

  // Bug-class audit pass
  const auditEnabled = !degradation || behaviorForLevel(degradation.currentLevel).enableAudit;
  let auditFindings: SourceVerificationResult[] | undefined;
  if (!options.skipAudit && auditEnabled) {
    console.log('\nRunning bug-class audit pass...');

    const auditPrompt = buildBugClassAuditPrompt(
      options.repoRoot,
      options.targetId,
      candidates.map(c => c.id),
    );

    try {
      const response = await adapter.invoke({
        systemPrompt: 'You are a source-code audit agent. Search the repository for specific bug classes. Return structured JSON only. Be focused — search for the specific patterns described, do not explore broadly.',
        prompt: auditPrompt,
        requestTimeoutMs: 300_000,
        workingDirectory: options.repoRoot,
      });

      totalCost += response.usage.costUsd;

      await appendFile(sessionLogPath, JSON.stringify({
        type: 'audit_response',
        content: response.content,
        usage: response.usage,
        durationMs: response.durationMs,
      }) + '\n', 'utf8');

      const AuditArraySchema = z.array(SourceVerificationResultSchema);
      const parsed = tryParseStructured(response.content, AuditArraySchema);
      if (parsed && parsed.length > 0) {
        auditFindings = parsed.map((finding) => {
          const defendedFindingDecision = resolveDefendedFindingStatus(finding);
          if (defendedFindingDecision) {
            finding.validationNotes.push(...defendedFindingDecision.notes);
            if (defendedFindingDecision.status !== finding.status) {
              finding.preValidationStatus = finding.status;
              finding.status = defendedFindingDecision.status;
            }
          }
          const family = classifyBugFamily(finding.claim, finding.candidateId, finding.rootCause);
          finding.bugFamily = family;
          finding.reviewPolicy = resolveReviewPolicy({
            bugFamily: family,
            sourceStatus: finding.status,
            confidence: finding.confidence,
          });
          return finding;
        });
        console.log(`Audit found ${parsed.length} additional findings`);
        for (const finding of auditFindings) {
          console.log(`  audit: ${finding.candidateId} — ${finding.status} (confidence: ${finding.confidence})`);
        }
      } else {
        console.log('Audit produced no additional findings');
      }
    } catch (err) {
      console.log(`Audit failed: ${err instanceof Error ? err.message : String(err)}`);
    }

    noteDegradationProgress();
  }

  // Assemble artifact
  const artifact: SourceVerificationArtifact = {
    campaignId: options.campaignId ?? 'unknown',
    targetId: options.targetId,
    timestamp: new Date().toISOString(),
    candidates: results,
    auditFindings,
  };

  const artifactPath = resolve(options.outputDir, 'source-verification.json');
  await writeFile(artifactPath, JSON.stringify(artifact, null, 2), 'utf8');

  // Print summary
  const counts = {
    supported: results.filter(r => r.status === 'supported').length,
    weakened: results.filter(r => r.status === 'weakened').length,
    refuted: results.filter(r => r.status === 'refuted').length,
    needs_runtime: results.filter(r => r.status === 'needs_runtime').length,
  };
  console.log(`\nSource verification summary:`);
  console.log(`  ${counts.supported} supported, ${counts.weakened} weakened, ${counts.refuted} refuted, ${counts.needs_runtime} needs_runtime`);
  if (auditFindings) console.log(`  ${auditFindings.length} audit additions`);
  console.log(`  Cost: $${totalCost.toFixed(4)}`);
  console.log(`  Artifact: ${artifactPath}`);

  return { artifact, artifactPath, costUsd: totalCost };
}
