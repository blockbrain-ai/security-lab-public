import { z } from 'zod';

export const SourceRefSchema = z.object({
  file: z.string(),
  line: z.number().optional(),
  snippet: z.string(),
});

export const SourceVerificationResultSchema = z.object({
  candidateId: z.string(),
  claim: z.string(),
  status: z.enum(['supported', 'weakened', 'refuted', 'needs_runtime']),
  evidenceClass: z.enum(['single_site_default', 'multi_site_flow']).optional(),
  rootCause: z.string(),
  sourceRefs: z.array(SourceRefSchema).default([]),
  exploitPath: z.string().optional(),
  preconditions: z.array(z.string()),
  defenseMechanismsObserved: z.array(z.string()).default([]),
  residualSinkRef: SourceRefSchema.optional(),
  residualBypassPath: z.string().optional(),
  proofPayload: z.string().optional(),
  postDefenseSnippet: z.string().optional(),
  assumptions: z.array(z.string()).default([]),
  dedupNotes: z.string().optional(),
  runtimePlan: z.string().optional(),
  validationNotes: z.array(z.string()).default([]),
  preValidationStatus: z.enum(['supported', 'weakened', 'refuted', 'needs_runtime']).optional(),
  criticNotes: z.string().optional(),
  preCriticStatus: z.enum(['supported', 'weakened', 'refuted', 'needs_runtime']).optional(),
  error: z.string().optional(),
  confidence: z.number().min(0).max(1),
  bugFamily: z.string().optional(),
  reviewPolicy: z.object({
    riskTier: z.enum(['critical', 'intermediate', 'low']),
    reviewMode: z.enum(['always', 'borderline', 'none']),
    hardFailOnMiss: z.boolean(),
    requireRuntime: z.boolean(),
    bugFamily: z.string(),
    observational: z.boolean(),
  }).optional(),
});

export type SourceVerificationResult = z.infer<typeof SourceVerificationResultSchema>;

export const SourceVerificationArtifactSchema = z.object({
  campaignId: z.string(),
  targetId: z.string(),
  timestamp: z.string(),
  candidates: z.array(SourceVerificationResultSchema),
  auditFindings: z.array(SourceVerificationResultSchema).optional(),
});

export type SourceVerificationArtifact = z.infer<typeof SourceVerificationArtifactSchema>;

export const DefenseCriticResultSchema = z.object({
  defenseValid: z.boolean(),
  reasoning: z.string(),
  sinkRef: SourceRefSchema.optional(),
  bypassPath: z.string().optional(),
  proofPayload: z.string().optional(),
  postDefenseSnippet: z.string().optional(),
  assumptions: z.array(z.string()).default([]),
  overrideStatus: z.enum(['weakened', 'needs_runtime']).optional(),
});

export type DefenseCriticResult = z.infer<typeof DefenseCriticResultSchema>;

export function validateSupportedRefs(
  result: Pick<SourceVerificationResult, 'status' | 'evidenceClass' | 'sourceRefs' | 'candidateId'>,
): string | null {
  if (result.status !== 'supported') return null;
  const minRefs = result.evidenceClass === 'single_site_default' ? 1 : 2;
  if (result.sourceRefs.length < minRefs) {
    return `supported finding "${result.candidateId}" needs at least ${minRefs} sourceRefs (has ${result.sourceRefs.length})`;
  }
  return null;
}
