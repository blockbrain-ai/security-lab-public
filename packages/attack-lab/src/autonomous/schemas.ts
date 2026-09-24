/**
 * Zod schemas for structured model output — forces planner and judge
 * to return parseable JSON that the system can act on.
 */

import { z } from 'zod';

// ---------------------------------------------------------------------------
// Planner output
// ---------------------------------------------------------------------------

export const PlannerSignalSchema = z.object({
  description: z.string(),
  surface: z.string(),
  confidence: z.number().min(0).max(1),
  relatedAssets: z.array(z.string()).default([]),
  potentialCapabilities: z.array(z.string()).default([]),
  suggestedFollowUps: z.array(z.string()).default([]),
});

export const PlannerProbeRequestSchema = z.object({
  targetKind: z.enum(['http', 'shell', 'code', 'dependency', 'prompt', 'process', 'state', 'evidence', 'persistence']),
  action: z.string(),
  rationale: z.string(),
  hypothesisId: z.string().optional(),
  parameters: z.record(z.unknown()).default({}),
});

export const PlannerChainHypothesisSchema = z.object({
  description: z.string(),
  severity: z.enum(['low', 'medium', 'high', 'critical']),
  signalIds: z.array(z.string()),
  prerequisites: z.array(z.string()).default([]),
  boundaryCrossing: z
    .object({
      from: z.string(),
      to: z.string(),
      mechanism: z.string(),
    })
    .optional(),
});

export const PlannerOutputSchema = z.object({
  /** New weak signals the planner has identified. */
  newSignals: z.array(PlannerSignalSchema).default([]),
  /** Probes the planner wants to execute. */
  probeRequests: z.array(PlannerProbeRequestSchema).default([]),
  /** New chain hypotheses the planner has synthesized. */
  newChainHypotheses: z.array(PlannerChainHypothesisSchema).default([]),
  /** Signal IDs the planner recommends marking dormant. */
  markDormant: z.array(z.string()).default([]),
  /** Signal IDs the planner recommends reactivating (with reason). */
  reactivations: z
    .array(
      z.object({
        signalId: z.string(),
        reason: z.string(),
      }),
    )
    .default([]),
  /** Overall reasoning. */
  reasoning: z.string(),
});

export type PlannerOutput = z.infer<typeof PlannerOutputSchema>;
export type PlannerProbeRequest = z.infer<typeof PlannerProbeRequestSchema>;

// ---------------------------------------------------------------------------
// Judge output
// ---------------------------------------------------------------------------

export const JudgeOutputSchema = z.object({
  /** Verdict on the hypothesis or observation. */
  verdict: z.enum(['continue', 'confirmed_finding', 'dead_end', 'merge_with_existing', 'needs_dormant_review']),
  /** If confirmed, the finding details. */
  finding: z
    .object({
      description: z.string(),
      severity: z.enum(['low', 'medium', 'high', 'critical']),
      reproductionSteps: z.array(z.string()),
      remediationSuggestion: z.string(),
      involvedDormantReactivation: z.boolean().default(false),
    })
    .optional(),
  /** Signals to promote based on evidence. */
  promoteSignals: z.array(z.string()).default([]),
  /** Signals to dismiss based on evidence. */
  dismissSignals: z.array(z.string()).default([]),
  /** Signals to reactivate from dormant status. */
  reactivateSignals: z
    .array(
      z.object({
        signalId: z.string(),
        reason: z.string(),
      }),
    )
    .default([]),
  /** New correlations discovered. */
  newCorrelations: z
    .array(
      z.object({
        signalIdA: z.string(),
        signalIdB: z.string(),
        resolved: z.boolean(),
      }),
    )
    .default([]),
  /** Whether partial chain progress was made. */
  partialProgress: z.boolean().default(false),
  /** Reasoning. */
  reasoning: z.string(),
});

export type JudgeOutput = z.infer<typeof JudgeOutputSchema>;
