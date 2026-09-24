/**
 * Campaign assessment — final evidence-led review of an investigation run.
 *
 * This stage exists because weak-signal descriptions and refuted hypotheses are
 * useful internally, but they should not become the official security verdict
 * without a stricter, campaign-level interpretation pass.
 */

import { z } from 'zod';
import type { InvokeOptions, ModelAdapter, ModelResponse } from '../providers/contracts.js';

// ---------------------------------------------------------------------------
// Evidence packet
// ---------------------------------------------------------------------------

export interface CampaignAssessmentPacket {
  campaignId: string;
  targetId: string;
  targetLabel: string;
  targetKind: string;
  environment: string;
  mode: string;
  iterations: number;
  totalCostUsd: number;
  evidenceDigest: string;
  liveConfirmation?: {
    enabled: boolean;
    status: string;
    targetId: string | null;
    confirmedFindings: number;
  };
  confirmedFindings: AssessmentEvidenceFinding[];
  topSignals: AssessmentEvidenceSignal[];
  testedHypotheses: AssessmentEvidenceHypothesis[];
  modelActivity: AssessmentModelActivity[];
}

export interface AssessmentEvidenceFinding {
  id: string;
  severity: string;
  description: string;
  reproductionSteps: string[];
  remediationSuggestion: string;
  involvedDormantReactivation: boolean;
  confirmedAt: string;
}

export interface AssessmentEvidenceSignal {
  id: string;
  surface: string;
  confidence: number;
  status: string;
  description: string;
  relatedAssets: string[];
}

export interface AssessmentEvidenceHypothesis {
  id: string;
  severity: string;
  status: string;
  description: string;
  signalIds: string[];
  relatedAssets: string[];
  latestVerdict?: string;
  latestReasoning?: string;
  decisionSource?: string;
  involvedDormantReactivation?: boolean;
  boundaryCrossing?: {
    from: string;
    to: string;
    mechanism: string;
  };
}

export interface AssessmentModelActivity {
  role: string;
  provider: string;
  model: string;
  calls: number;
  costUsd: number;
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

export const AssessmentItemSchema = z.object({
  title: z.string(),
  severity: z.enum(['critical', 'high', 'medium', 'low']),
  description: z.string(),
  evidenceRefs: z.array(z.string()).default([]),
  requiredConditions: z.array(z.string()).default([]),
});

export const SuppressedClaimSchema = z.object({
  claim: z.string(),
  reason: z.string(),
  evidenceRefs: z.array(z.string()).default([]),
});

export const CampaignAssessmentSchema = z.object({
  overallVerdict: z.enum([
    'confirmed_vulnerabilities_present',
    'validated_architectural_risks_only',
    'high_priority_unconfirmed_leads',
    'no_material_findings',
  ]),
  summary: z.string(),
  confidence: z.number().min(0).max(1),
  confirmedVulnerabilities: z.array(AssessmentItemSchema).default([]),
  validatedRisks: z.array(AssessmentItemSchema).default([]),
  configurationRisks: z.array(AssessmentItemSchema).default([]),
  unconfirmedLeads: z.array(AssessmentItemSchema).default([]),
  suppressedClaims: z.array(SuppressedClaimSchema).default([]),
  nextActions: z.array(z.string()).default([]),
});

export type CampaignAssessment = z.infer<typeof CampaignAssessmentSchema> & {
  source: 'deterministic' | 'review_panel' | 'synthesized';
  reviewerModels: string[];
  synthesizerModel?: string | null;
  parseStatus?: string;
  // Compatibility aliases for artifact consumers that still look for
  // older top-level names.
  verdict?: z.infer<typeof CampaignAssessmentSchema>['overallVerdict'];
  executiveSummary?: string;
};

export interface CampaignAssessmentInvocation {
  output: CampaignAssessment;
  prompt: string;
  systemPrompt: string;
  response: ModelResponse;
  parseSuccess: boolean;
  parseStatus: string;
}

export interface CampaignAssessmentReviewResult {
  label: string;
  provider: string;
  model: string;
  output: CampaignAssessment;
  invocation: CampaignAssessmentInvocation;
  confidenceScore: number;
}

export interface CampaignAssessmentPanelResult {
  reviewerResults: CampaignAssessmentReviewResult[];
  verdictSplit: Record<string, number>;
  unanimous: boolean;
  distinctVerdicts: number;
  dissenters: string[];
}

// ---------------------------------------------------------------------------
// Prompts
// ---------------------------------------------------------------------------

const REVIEW_SYSTEM_PROMPT = `You are a campaign-level security review assessor.

Your job is NOT to find new vulnerabilities. Your job is to classify the run output correctly.

You must separate:
1. Confirmed vulnerabilities
2. Validated architectural risks
3. Configuration-sensitive risks
4. High-priority unconfirmed leads
5. Claims that should be suppressed because they are contradicted, unsupported, or overstated

Rules:
- Treat the packet as the source of truth.
- Weak-signal text may itself overstate significance. Do not repeat that overstatement uncritically.
- A static code investigation is NOT enough to call a vulnerability confirmed unless the packet already contains confirmed findings or explicit live confirmation.
- If a risk only exists when auth/config is disabled or misconfigured, classify it as configuration-sensitive.
- If the evidence is suggestive but not decisive, classify it as an unconfirmed lead.
- Evidence refs must point only to IDs present in the packet.

Return strict JSON:
{
  "overallVerdict": "confirmed_vulnerabilities_present" | "validated_architectural_risks_only" | "high_priority_unconfirmed_leads" | "no_material_findings",
  "summary": "short executive summary",
  "confidence": 0.0 to 1.0,
  "confirmedVulnerabilities": [{ "title": "", "severity": "critical|high|medium|low", "description": "", "evidenceRefs": [], "requiredConditions": [] }],
  "validatedRisks": [{ "title": "", "severity": "critical|high|medium|low", "description": "", "evidenceRefs": [], "requiredConditions": [] }],
  "configurationRisks": [{ "title": "", "severity": "critical|high|medium|low", "description": "", "evidenceRefs": [], "requiredConditions": [] }],
  "unconfirmedLeads": [{ "title": "", "severity": "critical|high|medium|low", "description": "", "evidenceRefs": [], "requiredConditions": [] }],
  "suppressedClaims": [{ "claim": "", "reason": "", "evidenceRefs": [] }],
  "nextActions": ["actionable next step"]
}`;

const SYNTHESIS_SYSTEM_PROMPT = `You are the final campaign-report synthesizer.

You receive normalized reviewer assessments over the same investigation packet.

Your job is to produce the official security-lab verdict by:
- preferring conservative, evidence-led classification over excitement
- preventing unconfirmed static leads from being reported as confirmed vulnerabilities
- preserving important architectural or configuration risks
- explicitly suppressing claims that are overstated or contradicted

Use only the packet and reviewer outputs. Do not invent evidence.
Return the same JSON schema as the reviewers.`;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export async function reviewCampaignAssessment(
  adapter: ModelAdapter,
  packet: CampaignAssessmentPacket,
  options?: { invokeOptions?: Partial<InvokeOptions<CampaignAssessment>> },
): Promise<CampaignAssessmentInvocation> {
  const prompt = formatAssessmentPrompt(packet);
  const response = await adapter.invoke({
    ...(options?.invokeOptions ?? {}),
    systemPrompt: REVIEW_SYSTEM_PROMPT,
    prompt,
    maxTokens: 8192,
    temperature: 0,
  });
  const parsed = parseAssessmentResponse(response.content);
  const normalized = normalizeAssessment(parsed.output, packet, {
    source: 'review_panel',
    reviewerModels: [`${response.provider}/${response.model}`],
    parseStatus: parsed.parseStatus,
  });

  return {
    output: normalized,
    prompt,
    systemPrompt: REVIEW_SYSTEM_PROMPT,
    response,
    parseSuccess: parsed.parsed,
    parseStatus: parsed.parseStatus,
  };
}

export async function runCampaignAssessmentPanel(
  reviewers: Array<{ label: string; adapter: ModelAdapter }>,
  packet: CampaignAssessmentPacket,
  options?: { invokeOptionsByLabel?: Record<string, Partial<InvokeOptions<CampaignAssessment>>> },
): Promise<CampaignAssessmentPanelResult> {
  const reviewerResults = await Promise.all(
    reviewers.map(async (reviewer): Promise<CampaignAssessmentReviewResult> => {
      const invocation = await reviewCampaignAssessment(reviewer.adapter, packet, {
        invokeOptions: options?.invokeOptionsByLabel?.[reviewer.label],
      });
      return {
        label: reviewer.label,
        provider: reviewer.adapter.provider,
        model: reviewer.adapter.model,
        output: invocation.output,
        invocation,
        confidenceScore: scoreAssessmentConfidence(invocation.output),
      };
    }),
  );

  const verdictSplit: Record<string, number> = {};
  for (const result of reviewerResults) {
    verdictSplit[result.output.overallVerdict] = (verdictSplit[result.output.overallVerdict] ?? 0) + 1;
  }
  const distinctVerdicts = Object.keys(verdictSplit).length;
  const unanimous = distinctVerdicts === 1;
  const majorityVerdict = Object.entries(verdictSplit).sort((a, b) => b[1] - a[1])[0]?.[0];
  const dissenters = reviewerResults
    .filter((result) => result.output.overallVerdict !== majorityVerdict)
    .map((result) => result.label);

  return {
    reviewerResults,
    verdictSplit,
    unanimous,
    distinctVerdicts,
    dissenters,
  };
}

export async function synthesizeCampaignAssessment(
  adapter: ModelAdapter,
  packet: CampaignAssessmentPacket,
  panel: CampaignAssessmentPanelResult,
  options?: { invokeOptions?: Partial<InvokeOptions<CampaignAssessment>> },
): Promise<CampaignAssessmentInvocation> {
  const prompt = formatSynthesisPrompt(packet, panel);
  const response = await adapter.invoke({
    ...(options?.invokeOptions ?? {}),
    systemPrompt: SYNTHESIS_SYSTEM_PROMPT,
    prompt,
    maxTokens: 8192,
    temperature: 0,
  });
  const parsed = parseAssessmentResponse(response.content);
  const normalized = normalizeAssessment(parsed.output, packet, {
    source: 'synthesized',
    reviewerModels: panel.reviewerResults.map((result) => `${result.provider}/${result.model}`),
    synthesizerModel: `${response.provider}/${response.model}`,
    parseStatus: parsed.parseStatus,
  });

  return {
    output: normalized,
    prompt,
    systemPrompt: SYNTHESIS_SYSTEM_PROMPT,
    response,
    parseSuccess: parsed.parsed,
    parseStatus: parsed.parseStatus,
  };
}

export function buildDeterministicCampaignAssessment(
  packet: CampaignAssessmentPacket,
): CampaignAssessment {
  const confirmed = packet.confirmedFindings.map((finding) => ({
    title: firstSentence(finding.description),
    severity: normalizeSeverity(finding.severity),
    description: finding.description,
    evidenceRefs: [finding.id],
    requiredConditions: [],
  }));

  const configurationRisks = packet.topSignals
    .filter((signal) => isConditionalClaim(signal.description))
    .slice(0, 5)
    .map((signal) => ({
      title: firstSentence(signal.description),
      severity: inferLeadSeverity(signal.description, 'medium'),
      description: signal.description,
      evidenceRefs: [signal.id],
      requiredConditions: ['Requires the surrounding route/configuration to be mounted as observed.'],
    }));

  const unconfirmedLeads = packet.testedHypotheses
    .filter((hypothesis) => hypothesis.status !== 'confirmed')
    .slice(0, 8)
    .map((hypothesis) => ({
      title: firstSentence(hypothesis.description),
      severity: normalizeSeverity(hypothesis.severity),
      description: hypothesis.description,
      evidenceRefs: [hypothesis.id, ...hypothesis.signalIds].slice(0, 6),
      requiredConditions: ['Requires additional confirmation before being reported as a vulnerability.'],
    }));

  const overallVerdict = confirmed.length > 0
    ? 'confirmed_vulnerabilities_present'
    : configurationRisks.length > 0
      ? 'validated_architectural_risks_only'
      : unconfirmedLeads.length > 0
        ? 'high_priority_unconfirmed_leads'
        : 'no_material_findings';

  return {
    overallVerdict,
    summary: confirmed.length > 0
      ? 'The run produced confirmed findings.'
      : configurationRisks.length > 0
        ? 'The run produced credible architectural or configuration-sensitive risks, but no confirmed exploit.'
        : unconfirmedLeads.length > 0
          ? 'The run produced unconfirmed leads that require further validation.'
          : 'The run did not produce material findings.',
    confidence: confirmed.length > 0 ? 0.85 : unconfirmedLeads.length > 0 ? 0.65 : 0.8,
    confirmedVulnerabilities: confirmed,
    validatedRisks: [],
    configurationRisks,
    unconfirmedLeads,
    suppressedClaims: [],
    nextActions: buildDefaultNextActions(packet, overallVerdict),
    source: 'deterministic',
    reviewerModels: [],
    synthesizerModel: null,
    parseStatus: 'deterministic',
    verdict: overallVerdict,
    executiveSummary: confirmed.length > 0
      ? 'The run produced confirmed findings.'
      : configurationRisks.length > 0
        ? 'The run produced credible architectural or configuration-sensitive risks, but no confirmed exploit.'
        : unconfirmedLeads.length > 0
          ? 'The run produced unconfirmed leads that require further validation.'
          : 'The run did not produce material findings.',
  };
}

export function toCampaignAssessmentArtifact(assessment: CampaignAssessment): Record<string, unknown> {
  return {
    ...assessment,
    verdict: assessment.overallVerdict,
    executiveSummary: assessment.summary,
  };
}

// ---------------------------------------------------------------------------
// Formatting + parsing
// ---------------------------------------------------------------------------

function formatAssessmentPrompt(packet: CampaignAssessmentPacket): string {
  const lines = [
    `## Campaign`,
    `Campaign: ${packet.campaignId}`,
    `Target: ${packet.targetLabel} (${packet.targetId})`,
    `Kind: ${packet.targetKind}`,
    `Environment: ${packet.environment}`,
    `Mode: ${packet.mode}`,
    `Iterations: ${packet.iterations}`,
    `Total cost: $${packet.totalCostUsd.toFixed(4)}`,
    '',
    `## Guardrails`,
    `- Confirmed findings already in packet: ${packet.confirmedFindings.length}`,
    `- Live confirmation enabled: ${packet.liveConfirmation?.enabled ? 'yes' : 'no'}`,
    `- Live confirmation status: ${packet.liveConfirmation?.status ?? 'not_run'}`,
    `- Live confirmed findings: ${packet.liveConfirmation?.confirmedFindings ?? 0}`,
    '',
    `## Model Activity`,
    ...packet.modelActivity.map((activity) =>
      `- ${activity.role}: ${activity.provider}/${activity.model} (${activity.calls} calls, $${activity.costUsd.toFixed(4)})`),
    '',
    `## Confirmed Findings`,
    packet.confirmedFindings.length === 0
      ? 'None.'
      : packet.confirmedFindings.map((finding) =>
          `- [${finding.id}] [${finding.severity}] ${finding.description}`).join('\n'),
    '',
    `## Top Signals (Leads, not verdicts)`,
    packet.topSignals.length === 0
      ? 'None.'
      : packet.topSignals.map((signal) =>
          `- [${signal.id}] (${signal.surface}, ${signal.status}, conf=${signal.confidence.toFixed(2)}) ${signal.description} | assets=${signal.relatedAssets.join(', ') || 'none'}`).join('\n'),
    '',
    `## Tested Hypotheses`,
    packet.testedHypotheses.length === 0
      ? 'None.'
      : packet.testedHypotheses.map((hypothesis) => formatHypothesisForPrompt(hypothesis)).join('\n\n'),
    '',
    `## Evidence Digest`,
    packet.evidenceDigest,
  ];

  return lines.join('\n');
}

function formatSynthesisPrompt(
  packet: CampaignAssessmentPacket,
  panel: CampaignAssessmentPanelResult,
): string {
  const lines = [
    `## Campaign`,
    `Campaign: ${packet.campaignId}`,
    `Target: ${packet.targetLabel} (${packet.targetId})`,
    `Kind: ${packet.targetKind}`,
    `Environment: ${packet.environment}`,
    '',
    `## Reviewer Verdicts`,
    ...panel.reviewerResults.map((result) => [
      `### ${result.label} (${result.provider}/${result.model})`,
      `Overall verdict: ${result.output.overallVerdict}`,
      `Confidence: ${result.output.confidence.toFixed(2)}`,
      `Summary: ${result.output.summary}`,
      `Confirmed vulnerabilities: ${result.output.confirmedVulnerabilities.length}`,
      `Validated risks: ${result.output.validatedRisks.length}`,
      `Configuration risks: ${result.output.configurationRisks.length}`,
      `Unconfirmed leads: ${result.output.unconfirmedLeads.length}`,
      `Suppressed claims: ${result.output.suppressedClaims.length}`,
    ].join('\n')),
    '',
    `## Disagreement`,
    `Unanimous: ${panel.unanimous}`,
    `Verdict split: ${JSON.stringify(panel.verdictSplit)}`,
    `Dissenters: ${panel.dissenters.join(', ') || 'none'}`,
    '',
    `## Evidence Digest`,
    packet.evidenceDigest,
  ];

  return lines.join('\n\n');
}

function formatHypothesisForPrompt(hypothesis: AssessmentEvidenceHypothesis): string {
  const lines = [
    `- [${hypothesis.id}] [${hypothesis.severity}] [${hypothesis.status}] ${hypothesis.description}`,
    `  signals=${hypothesis.signalIds.join(', ') || 'none'}`,
  ];
  if (hypothesis.relatedAssets.length > 0) {
    lines.push(`  assets=${hypothesis.relatedAssets.join(', ')}`);
  }
  if (hypothesis.boundaryCrossing) {
    lines.push(
      `  boundary=${hypothesis.boundaryCrossing.from} -> ${hypothesis.boundaryCrossing.to} via ${hypothesis.boundaryCrossing.mechanism}`,
    );
  }
  if (hypothesis.latestVerdict) {
    lines.push(`  latestVerdict=${hypothesis.latestVerdict}`);
  }
  if (hypothesis.decisionSource) {
    lines.push(`  decisionSource=${hypothesis.decisionSource}`);
  }
  return lines.join('\n');
}

function parseAssessmentResponse(content: string): { output: z.infer<typeof CampaignAssessmentSchema>; parsed: boolean; parseStatus: string } {
  const extracted = extractJsonCandidate(content);
  if (extracted.value !== null) {
    const repaired = repairAssessmentCandidate(extracted.value, content, extracted.source);
    const parsed = CampaignAssessmentSchema.safeParse(repaired.output);
    if (parsed.success) {
      return {
        output: parsed.data,
        parsed: true,
        parseStatus: repaired.parseStatus,
      };
    }
  }

  return {
    output: {
      overallVerdict: 'high_priority_unconfirmed_leads',
      summary: content.trim() || 'Assessment response could not be parsed cleanly.',
      confidence: 0.35,
      confirmedVulnerabilities: [],
      validatedRisks: [],
      configurationRisks: [],
      unconfirmedLeads: [],
      suppressedClaims: [],
      nextActions: [],
    },
    parsed: false,
    parseStatus: 'fallback_text',
  };
}

function extractJsonCandidate(content: string): { value: unknown | null; source: string } {
  const fenced = content.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  if (fenced?.[1]) {
    try {
      return { value: JSON.parse(fenced[1]), source: 'fenced_json' };
    } catch {
      // fall through to brace extraction
    }
  }

  const brace = content.match(/(\{[\s\S]*\})/);
  if (brace?.[1]) {
    try {
      return { value: JSON.parse(brace[1]), source: 'brace_json' };
    } catch {
      return { value: null, source: 'malformed_brace_json' };
    }
  }

  return { value: null, source: 'no_json_found' };
}

function repairAssessmentCandidate(
  raw: unknown,
  fallbackSummary: string,
  source: string,
  depth = 0,
): { output: z.infer<typeof CampaignAssessmentSchema>; parseStatus: string } {
  const candidate = typeof raw === 'object' && raw !== null ? raw as Record<string, unknown> : {};
  let parseStatus = source;
  const summaryCandidate = pickString(candidate['summary']);
  let resolved = { ...candidate };

  if (summaryCandidate && depth < 3) {
    const nested = extractJsonCandidate(summaryCandidate);
    if (nested.value && looksLikeAssessmentPayload(nested.value)) {
      const nestedRepair = repairAssessmentCandidate(nested.value, summaryCandidate, `nested_summary:${nested.source}`, depth + 1);
      resolved = deepMergeAssessmentObject(resolved, nested.value as Record<string, unknown>);
      if (nestedRepair.output.summary.trim().length > 0) {
        resolved['summary'] = nestedRepair.output.summary;
      }
      parseStatus = nestedRepair.parseStatus;
    }
  }

  return {
    output: {
      overallVerdict: normalizeVerdict(
        pickString(resolved['overallVerdict'], resolved['verdict']),
      ),
      summary: pickString(resolved['summary']) ?? fallbackSummary.trim(),
      confidence: normalizeConfidence(resolved['confidence']),
      confirmedVulnerabilities: normalizeAssessmentItems(
        resolved['confirmedVulnerabilities'] ?? resolved['confirmed_vulnerabilities'],
      ),
      validatedRisks: normalizeAssessmentItems(
        resolved['validatedRisks'] ?? resolved['validated_risks'],
      ),
      configurationRisks: normalizeAssessmentItems(
        resolved['configurationRisks'] ?? resolved['configuration_risks'],
      ),
      unconfirmedLeads: normalizeAssessmentItems(
        resolved['unconfirmedLeads'] ?? resolved['unconfirmed_leads'],
      ),
      suppressedClaims: normalizeSuppressedClaims(
        resolved['suppressedClaims'] ?? resolved['suppressed_claims'],
      ),
      nextActions: normalizeStringArray(resolved['nextActions'] ?? resolved['next_actions']),
    },
    parseStatus,
  };
}

function looksLikeAssessmentPayload(value: unknown): boolean {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const candidate = value as Record<string, unknown>;
  return [
    'overallVerdict',
    'summary',
    'confirmedVulnerabilities',
    'validatedRisks',
    'configurationRisks',
    'unconfirmedLeads',
    'suppressedClaims',
    'nextActions',
  ].some((key) => key in candidate);
}

function deepMergeAssessmentObject(
  outer: Record<string, unknown>,
  inner: Record<string, unknown>,
): Record<string, unknown> {
  const result: Record<string, unknown> = { ...outer };
  for (const [key, value] of Object.entries(inner)) {
    if (value === undefined) {
      continue;
    }
    if (Array.isArray(value)) {
      result[key] = [...value];
      continue;
    }
    if (value && typeof value === 'object' && result[key] && typeof result[key] === 'object' && !Array.isArray(result[key])) {
      result[key] = deepMergeAssessmentObject(result[key] as Record<string, unknown>, value as Record<string, unknown>);
      continue;
    }
    result[key] = value;
  }
  return result;
}

function normalizeAssessmentItems(value: unknown): Array<z.infer<typeof AssessmentItemSchema>> {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.flatMap((entry) => {
    if (!entry || typeof entry !== 'object') {
      return [];
    }

    const item = entry as Record<string, unknown>;
    const description = pickString(item['description'], item['summary'], item['evidence']);
    if (!description) {
      return [];
    }

    return [{
      title: pickString(item['title'], item['id']) ?? firstSentence(description),
      severity: normalizeSeverity(pickString(item['severity']) ?? 'medium'),
      description,
      evidenceRefs: normalizeEvidenceRefs(item['evidenceRefs'] ?? item['evidence_refs'] ?? item['evidence']),
      requiredConditions: normalizeStringArray(
        item['requiredConditions'] ?? item['required_conditions'] ?? item['conditions'],
      ),
    }];
  });
}

function normalizeSuppressedClaims(value: unknown): Array<z.infer<typeof SuppressedClaimSchema>> {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.flatMap((entry) => {
    if (!entry || typeof entry !== 'object') {
      return [];
    }

    const claim = entry as Record<string, unknown>;
    const claimText = pickString(claim['claim'], claim['original_claim']);
    const reason = pickString(claim['reason'], claim['suppression_reason']);
    if (!claimText || !reason) {
      return [];
    }

    return [{
      claim: claimText,
      reason,
      evidenceRefs: normalizeEvidenceRefs(claim['evidenceRefs'] ?? claim['evidence_refs']),
    }];
  });
}

function normalizeEvidenceRefs(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.filter((entry): entry is string => typeof entry === 'string');
  }
  if (typeof value === 'string') {
    return Array.from(value.matchAll(/\b(?:ws|ph|finding)-[\w-]+\b/g)).map((match) => match[0]);
  }
  return [];
}

function normalizeStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((entry): entry is string => typeof entry === 'string' && entry.trim().length > 0);
}

function normalizeVerdict(value: string | undefined): z.infer<typeof CampaignAssessmentSchema>['overallVerdict'] {
  switch (value) {
    case 'confirmed_vulnerabilities_present':
    case 'validated_architectural_risks_only':
    case 'high_priority_unconfirmed_leads':
    case 'no_material_findings':
      return value;
    default:
      return 'high_priority_unconfirmed_leads';
  }
}

function normalizeConfidence(value: unknown): number {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return clamp(value, 0, 1);
  }
  if (typeof value === 'string') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) {
      return clamp(parsed, 0, 1);
    }
  }
  return 0.35;
}

function pickString(...values: unknown[]): string | undefined {
  for (const value of values) {
    if (typeof value === 'string' && value.trim().length > 0) {
      return value.trim();
    }
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Normalization + safeguards
// ---------------------------------------------------------------------------

function normalizeAssessment(
  output: z.infer<typeof CampaignAssessmentSchema>,
  packet: CampaignAssessmentPacket,
  meta: {
    source: CampaignAssessment['source'];
    reviewerModels: string[];
    synthesizerModel?: string;
    parseStatus: string;
  },
): CampaignAssessment {
  const knownRefs = new Set<string>([
    ...packet.confirmedFindings.map((finding) => finding.id),
    ...packet.topSignals.map((signal) => signal.id),
    ...packet.testedHypotheses.map((hypothesis) => hypothesis.id),
  ]);
  const confirmedRefs = new Set<string>(packet.confirmedFindings.map((finding) => finding.id));

  const sanitizeItems = (
    items: Array<z.infer<typeof AssessmentItemSchema>> | undefined,
  ): Array<z.infer<typeof AssessmentItemSchema>> => (items ?? []).map((item) => ({
    ...item,
    severity: normalizeSeverity(item.severity),
    evidenceRefs: item.evidenceRefs.filter((ref) => knownRefs.has(ref)),
    requiredConditions: item.requiredConditions ?? [],
  }));

  const confirmedVulnerabilities: Array<z.infer<typeof AssessmentItemSchema>> = [];
  const downgradedLeads: Array<z.infer<typeof AssessmentItemSchema>> = [];

  const campaignHasLiveConfirmation = (packet.liveConfirmation?.confirmedFindings ?? 0) > 0;

  for (const item of sanitizeItems(output.confirmedVulnerabilities)) {
    const hasConfirmedEvidence = item.evidenceRefs.some((ref) => confirmedRefs.has(ref));
    // A campaign-level flag says "something in this campaign was confirmed
    // live"; it is not evidence for *this* item. It may keep an item that cites
    // at least one known reference, but it cannot launder a claim that cites
    // nothing at all.
    const grounded = item.evidenceRefs.length > 0;
    if (hasConfirmedEvidence || (campaignHasLiveConfirmation && grounded)) {
      confirmedVulnerabilities.push(item);
      continue;
    }
    downgradedLeads.push({
      ...item,
      description: `Downgraded from confirmed claim: ${item.description}`,
      requiredConditions: [
        ...item.requiredConditions,
        'Requires confirmation beyond static or unconfirmed evidence before being reported as a vulnerability.',
      ],
    });
  }

  const validatedRisks = sanitizeItems(output.validatedRisks);
  const configurationRisks = sanitizeItems(output.configurationRisks);
  const unconfirmedLeads = [
    ...sanitizeItems(output.unconfirmedLeads),
    ...downgradedLeads,
  ];
  const suppressedClaims = output.suppressedClaims.map((claim) => ({
    ...claim,
    evidenceRefs: claim.evidenceRefs.filter((ref) => knownRefs.has(ref)),
  }));

  const overallVerdict = confirmedVulnerabilities.length > 0
    ? 'confirmed_vulnerabilities_present'
    : validatedRisks.length > 0 || configurationRisks.length > 0
      ? 'validated_architectural_risks_only'
      : unconfirmedLeads.length > 0
        ? 'high_priority_unconfirmed_leads'
        : 'no_material_findings';

  return {
    overallVerdict,
    summary: normalizeSummary(output.summary, overallVerdict, packet.targetKind),
    confidence: clamp(output.confidence, 0, 1),
    confirmedVulnerabilities,
    validatedRisks,
    configurationRisks,
    unconfirmedLeads,
    suppressedClaims,
    nextActions: output.nextActions.length > 0
      ? output.nextActions
      : buildDefaultNextActions(packet, overallVerdict),
    source: meta.source,
    reviewerModels: meta.reviewerModels,
    synthesizerModel: meta.synthesizerModel ?? null,
    parseStatus: meta.parseStatus,
    verdict: overallVerdict,
    executiveSummary: normalizeSummary(output.summary, overallVerdict, packet.targetKind),
  };
}

function normalizeSummary(summary: string, verdict: CampaignAssessment['overallVerdict'], targetKind: string): string {
  const trimmed = summary.trim();
  if (trimmed.length > 0) {
    return trimmed;
  }
  if (verdict === 'confirmed_vulnerabilities_present') {
    return 'The run produced confirmed vulnerabilities.';
  }
  if (verdict === 'validated_architectural_risks_only') {
    return targetKind === 'code'
      ? 'The run produced validated architectural or configuration-sensitive risks, but not confirmed exploit findings.'
      : 'The run produced validated architectural or configuration-sensitive risks.';
  }
  if (verdict === 'high_priority_unconfirmed_leads') {
    return 'The run produced high-priority leads that require further confirmation before being reported as vulnerabilities.';
  }
  return 'The run did not produce material security findings.';
}

function buildDefaultNextActions(
  packet: CampaignAssessmentPacket,
  verdict: CampaignAssessment['overallVerdict'],
): string[] {
  if (verdict === 'confirmed_vulnerabilities_present') {
    return ['Prioritize remediation of confirmed findings and rerun the corresponding regression packs.'];
  }
  if (verdict === 'validated_architectural_risks_only') {
    return packet.targetKind === 'code'
      ? ['Run a bounded live-confirmation pass against a controlled local or staging target for the highest-risk chains.']
      : ['Add targeted regression packs for the validated architectural risks and verify the runtime controls.'];
  }
  if (verdict === 'high_priority_unconfirmed_leads') {
    return ['Promote the strongest leads into live-confirmation scenarios before treating them as real vulnerabilities.'];
  }
  return ['Continue monitoring for new weak signals and expand the target surface or budget if deeper coverage is required.'];
}

function scoreAssessmentConfidence(assessment: CampaignAssessment): number {
  let score = clamp(assessment.confidence, 0, 1);
  if (assessment.confirmedVulnerabilities.length > 0) score += 0.1;
  if (assessment.suppressedClaims.length > 0) score += 0.05;
  if (assessment.unconfirmedLeads.length > 4) score -= 0.05;
  return clamp(score, 0, 1);
}

function normalizeSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' {
  switch (severity) {
    case 'critical':
    case 'high':
    case 'medium':
    case 'low':
      return severity;
    default:
      return 'medium';
  }
}

function inferLeadSeverity(text: string, fallback: 'critical' | 'high' | 'medium' | 'low'): 'critical' | 'high' | 'medium' | 'low' {
  const lower = text.toLowerCase();
  if (lower.includes('critical')) return 'critical';
  if (lower.includes('high')) return 'high';
  if (lower.includes('low')) return 'low';
  return fallback;
}

function isConditionalClaim(text: string): boolean {
  const lower = text.toLowerCase();
  return [
    ' if ',
    ' may ',
    ' might ',
    ' could ',
    ' appears ',
    ' suggests ',
    ' implying ',
    ' not found ',
    ' not located ',
    ' no evidence ',
    ' when ',
    ' unless ',
  ].some((marker) => lower.includes(marker));
}

function firstSentence(text: string): string {
  const sentence = text.split(/(?<=[.!?])\s+/)[0]?.trim();
  return sentence && sentence.length > 0 ? sentence : text.trim();
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}
