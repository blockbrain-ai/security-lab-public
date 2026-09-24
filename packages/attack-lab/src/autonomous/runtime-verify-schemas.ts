import { z } from 'zod';

export const DockerSetupResultSchema = z.object({
  success: z.boolean(),
  baseUrl: z.string().optional(),
  ports: z.array(z.string()).default([]),
  composeCwd: z.string().optional(),
  composeFiles: z.array(z.string()).default([]),
  projectName: z.string().optional(),
  log: z.string().optional(),
});

export type DockerSetupResult = z.infer<typeof DockerSetupResultSchema>;

export const HttpEvidenceSchema = z.object({
  url: z.string(),
  method: z.string(),
  statusCode: z.number(),
  snippet: z.string(),
});

export const RuntimeVerificationResultSchema = z.object({
  candidateId: z.string(),
  claim: z.string(),
  status: z.enum(['confirmed', 'partially_confirmed', 'not_reproducible', 'blocked', 'refuted']),
  rootCause: z.string(),
  reproducerCommands: z.array(z.string()).default([]),
  reproducerOutput: z.string().optional(),
  httpEvidence: z.array(HttpEvidenceSchema).default([]),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
  pvrReady: z.boolean().default(false),
  filingNotes: z.string().optional(),
  suggestedFix: z.string().optional(),
  regressionTest: z.string().optional(),
  blocker: z.string().optional(),
  confidence: z.number().min(0).max(1),
});

export type RuntimeVerificationResult = z.infer<typeof RuntimeVerificationResultSchema>;

export const ServiceInfoSchema = z.object({
  baseUrl: z.string().optional(),
  ports: z.array(z.string()).default([]),
  composeCwd: z.string().optional(),
  composeFiles: z.array(z.string()).default([]),
  projectName: z.string().optional(),
});

export type ServiceInfo = z.infer<typeof ServiceInfoSchema>;

export const ValidationNoteSchema = z.object({
  rule: z.string(),
  detail: z.string(),
});

export const ValidatedCandidateSchema = z.object({
  modelResult: RuntimeVerificationResultSchema,
  validatedResult: RuntimeVerificationResultSchema,
  wasDowngraded: z.boolean(),
  validationNotes: z.array(ValidationNoteSchema).default([]),
  reviewPolicy: z.object({
    riskTier: z.enum(['critical', 'intermediate', 'low']),
    reviewMode: z.enum(['always', 'borderline', 'none']),
    hardFailOnMiss: z.boolean(),
    requireRuntime: z.boolean(),
    bugFamily: z.string(),
    observational: z.boolean(),
  }).optional(),
});

export type ValidatedCandidate = z.infer<typeof ValidatedCandidateSchema>;

export const RuntimeVerificationArtifactSchema = z.object({
  campaignId: z.string(),
  targetId: z.string(),
  timestamp: z.string(),
  dockerSetupSuccess: z.boolean(),
  dockerSetupLog: z.string().optional(),
  serviceInfo: ServiceInfoSchema.optional(),
  candidates: z.array(ValidatedCandidateSchema),
});

export type RuntimeVerificationArtifact = z.infer<typeof RuntimeVerificationArtifactSchema>;
