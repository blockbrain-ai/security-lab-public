import { appendFile } from 'node:fs/promises';
import type { z } from 'zod';
import type { ToolTranscriptEntry } from '../providers/contracts.js';
import type { ValidationNote } from './runtime-evidence-validator.js';
import type { SourceVerificationResult } from './source-verify-schemas.js';
import {
  extractJsonString,
  parseWithGenericRepair,
  type GenericFailureKind,
  type GenericParseResult,
} from './response-repair.js';
import { BoundedLocalAdapter } from '../providers/bounded-local-adapter.js';

// ---------------------------------------------------------------------------
// Failure classification
// ---------------------------------------------------------------------------

export type GateFailureClass =
  | 'format_truncated'
  | 'format_invalid_json'
  | 'format_alias_drift'
  | 'format_no_json'
  | 'format_schema_mismatch'
  | 'context_exhaustion'
  | 'tool_loop_stall'
  | 'evidence_fabricated'
  | 'weak_source_grounding';

export type RepairPolicy =
  | 'structural_reparse'
  | 'synthesis_retry'
  | 'targeted_followup'
  | 'downgrade_only';

export interface GateClassification {
  failureClass: GateFailureClass;
  policy: RepairPolicy;
  detail: string;
}

export const POLICY_MAP: Record<GateFailureClass, RepairPolicy> = {
  format_truncated: 'structural_reparse',
  format_invalid_json: 'structural_reparse',
  format_alias_drift: 'structural_reparse',
  format_no_json: 'synthesis_retry',
  format_schema_mismatch: 'synthesis_retry',
  context_exhaustion: 'synthesis_retry',
  tool_loop_stall: 'synthesis_retry',
  evidence_fabricated: 'downgrade_only',
  weak_source_grounding: 'targeted_followup',
};

// ---------------------------------------------------------------------------
// Gate result
// ---------------------------------------------------------------------------

export interface GateResult<T> {
  success: boolean;
  output?: T;
  classification?: GateClassification;
  repairAttempted: boolean;
  repairSucceeded: boolean;
  rawContent: string;
  repairContent?: string;
  repairCostUsd: number;
  repairDurationMs?: number;
  gateId: string;
}

// ---------------------------------------------------------------------------
// Gate context
// ---------------------------------------------------------------------------

export interface GateContext {
  gateId: string;
  rawContent: string;
  originalPrompt: string;
  originalSystemPrompt: string;
  toolTranscript?: ToolTranscriptEntry[];
  model: string;
  baseUrl?: string;
  workingDirectory?: string;
  sessionLogPath: string;
}

export interface GateOptions {
  parsedOutput?: unknown;
  sourceResult?: SourceVerificationResult;
  validationNotes?: ValidationNote[];
  aliasMap?: Record<string, string>;
  provider?: string;
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

const GENERIC_TO_GATE: Record<GenericFailureKind, GateFailureClass | null> = {
  none: null,
  truncated: 'format_truncated',
  invalid_json: 'format_invalid_json',
  no_json_found: 'format_no_json',
  schema_mismatch: 'format_schema_mismatch',
};

const BUDGET_MARKERS = [
  'BUDGET_EXHAUSTED',
  'budget exhausted',
  'maximum turns reached',
  '<tool_call>',
  '<function_call>',
];

const FABRICATION_RULES = new Set([
  'reproducer_output_not_in_transcript',
  'http_evidence_snippet_not_in_transcript',
  'named_control_not_in_evidence',
]);

export function classifyFailure<T>(
  rawContent: string,
  genericResult: GenericParseResult<T>,
  options?: GateOptions,
): GateClassification | null {
  // Layer 1: structural failures
  if (!genericResult.success) {
    const gateClass = GENERIC_TO_GATE[genericResult.failureKind];
    if (gateClass) {
      // Check alias drift if an aliasMap was provided
      if (genericResult.failureKind === 'schema_mismatch' && options?.aliasMap) {
        const jsonStr = extractJsonString(rawContent);
        if (jsonStr) {
          try {
            const parsed = JSON.parse(jsonStr);
            const hasAlias = Object.keys(options.aliasMap).some((k) => k in parsed);
            if (hasAlias) {
              return {
                failureClass: 'format_alias_drift',
                policy: POLICY_MAP.format_alias_drift,
                detail: `Alias keys found: ${Object.keys(options.aliasMap).filter((k) => k in parsed).join(', ')}`,
              };
            }
          } catch {
            // not parseable
          }
        }
      }
      return {
        failureClass: gateClass,
        policy: POLICY_MAP[gateClass],
        detail: `Generic parse failure: ${genericResult.failureKind}`,
      };
    }
  }

  // Layer 2: semantic failures (only when parse succeeded)
  if (genericResult.success) {
    // evidence_fabricated
    if (options?.validationNotes) {
      const fabricationNotes = options.validationNotes.filter(
        (n) => FABRICATION_RULES.has(n.rule),
      );
      if (fabricationNotes.length > 0) {
        return {
          failureClass: 'evidence_fabricated',
          policy: POLICY_MAP.evidence_fabricated,
          detail: fabricationNotes.map((n) => `[${n.rule}] ${n.detail}`).join('; '),
        };
      }
    }

    // weak_source_grounding
    if (options?.sourceResult) {
      const sr = options.sourceResult;
      if (sr.status === 'supported' || sr.status === 'weakened') {
        const hasLineRef = sr.sourceRefs.some((ref) => ref.line !== undefined);
        const rootCauseHasFileLine = /[\w./]+:\d+/.test(sr.rootCause);
        if (sr.sourceRefs.length === 0 || (!hasLineRef && !rootCauseHasFileLine)) {
          return {
            failureClass: 'weak_source_grounding',
            policy: POLICY_MAP.weak_source_grounding,
            detail: `${sr.status} verdict with ${sr.sourceRefs.length} sourceRefs, ${hasLineRef ? 'has' : 'no'} line numbers, rootCause ${rootCauseHasFileLine ? 'has' : 'lacks'} file:line`,
          };
        }
      }
    }
  }

  return null;
}

export function classifyTranscriptFailure(
  rawContent: string,
  toolTranscript: ToolTranscriptEntry[],
): GateClassification | null {
  // tool_loop_stall: 3+ identical tool calls
  const callSigs = toolTranscript.map(
    (t) => `${t.tool}:${JSON.stringify(t.args)}`,
  );
  const sigCounts = new Map<string, number>();
  for (const sig of callSigs) {
    sigCounts.set(sig, (sigCounts.get(sig) ?? 0) + 1);
  }
  for (const [sig, count] of sigCounts) {
    if (count >= 3) {
      return {
        failureClass: 'tool_loop_stall',
        policy: POLICY_MAP.tool_loop_stall,
        detail: `Tool called ${count} times with same args: ${sig.slice(0, 100)}`,
      };
    }
  }

  // context_exhaustion: budget markers in raw content
  for (const marker of BUDGET_MARKERS) {
    if (rawContent.toLowerCase().includes(marker.toLowerCase())) {
      return {
        failureClass: 'context_exhaustion',
        policy: POLICY_MAP.context_exhaustion,
        detail: `Budget marker detected: "${marker}"`,
      };
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Repair functions
// ---------------------------------------------------------------------------

function buildSynthesisRepairPrompt(
  ctx: GateContext,
  classification: GateClassification,
  schemaExample: string,
): string {
  const evidenceTail = ctx.rawContent.slice(-6000);
  return `Your previous response could not be parsed.

## Error
${classification.detail}

## Required Output Schema
${schemaExample}

## Evidence From Your Previous Response
The last portion of your work:
${evidenceTail}

## Instructions
Produce ONLY a JSON object matching the schema above. No tool calls, no markdown outside the JSON block, no explanations.`;
}

function buildTargetedFollowupPrompt(
  classification: GateClassification,
  schemaExample: string,
  sourceResult: SourceVerificationResult,
): string {
  return `The previous source verification produced a "${sourceResult.status}" verdict but with insufficient source grounding.

## Problem
${classification.detail}

## Original Claim
${sourceResult.claim}

## Original Root Cause
${sourceResult.rootCause}

## Task
Find the exact file path and line number where this vulnerability exists. Read the relevant files.

## Required Output Schema
${schemaExample}

Populate the sourceRefs array with at least one entry containing file, line, and snippet. Return ONLY the JSON object.`;
}

async function executeSynthesisRepair<T>(
  schema: z.ZodType<T>,
  ctx: GateContext,
  classification: GateClassification,
  schemaExample: string,
): Promise<{ success: boolean; output?: T; content: string; costUsd: number; durationMs: number }> {
  const adapter = new BoundedLocalAdapter({
    provider: 'bounded_local',
    model: ctx.model,
    baseUrl: ctx.baseUrl,
    workingDirectory: ctx.workingDirectory ?? process.cwd(),
    boundedConfig: {
      maxTurns: 1,
      readBudget: 0,
      runtimeTools: false,
      synthesisMaxTokens: 4096,
      maxContextChars: 20_000,
    },
  });

  const prompt = buildSynthesisRepairPrompt(ctx, classification, schemaExample);
  const response = await adapter.invoke({
    systemPrompt: 'You are a JSON repair agent. Produce only valid JSON matching the schema. No explanations.',
    prompt,
    requestTimeoutMs: 120_000,
  });

  const parsed = parseWithGenericRepair(response.content, schema);
  return {
    success: parsed.success,
    output: parsed.output,
    content: response.content,
    costUsd: response.usage.costUsd,
    durationMs: response.durationMs ?? 0,
  };
}

async function executeTargetedFollowup<T>(
  schema: z.ZodType<T>,
  ctx: GateContext,
  classification: GateClassification,
  schemaExample: string,
  sourceResult: SourceVerificationResult,
): Promise<{ success: boolean; output?: T; content: string; costUsd: number; durationMs: number }> {
  const adapter = new BoundedLocalAdapter({
    provider: 'bounded_local',
    model: ctx.model,
    baseUrl: ctx.baseUrl,
    workingDirectory: ctx.workingDirectory ?? process.cwd(),
    boundedConfig: {
      maxTurns: 4,
      readBudget: 3,
      runtimeTools: false,
      shellBudget: 0,
      httpBudget: 0,
      synthesisMaxTokens: 4096,
      maxContextChars: 20_000,
    },
  });

  const prompt = buildTargetedFollowupPrompt(classification, schemaExample, sourceResult);
  const response = await adapter.invoke({
    systemPrompt: 'You are a source-code lookup agent. Find the exact file:line for the described vulnerability. Return structured JSON only.',
    prompt,
    requestTimeoutMs: 180_000,
    workingDirectory: ctx.workingDirectory,
  });

  const parsed = parseWithGenericRepair(response.content, schema);
  return {
    success: parsed.success,
    output: parsed.output,
    content: response.content,
    costUsd: response.usage.costUsd,
    durationMs: response.durationMs ?? 0,
  };
}

// ---------------------------------------------------------------------------
// Main gate entry point
// ---------------------------------------------------------------------------

export async function executeGate<T>(
  schema: z.ZodType<T>,
  ctx: GateContext,
  options?: GateOptions,
): Promise<GateResult<T>> {
  const genericResult = parseWithGenericRepair(ctx.rawContent, schema, options?.aliasMap);

  // Check structural + semantic failures
  let classification = classifyFailure(ctx.rawContent, genericResult, options);

  // Check transcript-level failures if parse succeeded and transcript available
  if (!classification && genericResult.success && ctx.toolTranscript?.length) {
    classification = classifyTranscriptFailure(ctx.rawContent, ctx.toolTranscript);
  }

  // No failure — return success
  if (!classification) {
    return {
      success: genericResult.success,
      output: genericResult.output,
      repairAttempted: false,
      repairSucceeded: false,
      rawContent: ctx.rawContent,
      repairCostUsd: 0,
      gateId: ctx.gateId,
    };
  }

  const policy = classification.policy;
  let result: GateResult<T>;

  // Structural reparse — already done in genericResult
  if (policy === 'structural_reparse') {
    result = {
      success: genericResult.success,
      output: genericResult.output,
      classification,
      repairAttempted: genericResult.repairAttempted,
      repairSucceeded: genericResult.repairSucceeded,
      rawContent: ctx.rawContent,
      repairContent: genericResult.repairedContent,
      repairCostUsd: 0,
      gateId: ctx.gateId,
    };
  }
  // Downgrade only — pass through existing validated output
  else if (policy === 'downgrade_only') {
    result = {
      success: true,
      output: genericResult.output,
      classification,
      repairAttempted: false,
      repairSucceeded: false,
      rawContent: ctx.rawContent,
      repairCostUsd: 0,
      gateId: ctx.gateId,
    };
  }
  // Model-based repair — only for bounded_local
  else if (policy === 'synthesis_retry' || policy === 'targeted_followup') {
    const isBoundedLocal = options?.provider === 'bounded_local';
    if (!isBoundedLocal) {
      result = {
        success: genericResult.success,
        output: genericResult.output,
        classification,
        repairAttempted: false,
        repairSucceeded: false,
        rawContent: ctx.rawContent,
        repairCostUsd: 0,
        gateId: ctx.gateId,
      };
    } else {
      const schemaExample = '(see original prompt for schema)';
      try {
        let repairResult;
        if (policy === 'targeted_followup' && options?.sourceResult) {
          repairResult = await executeTargetedFollowup(
            schema, ctx, classification, schemaExample, options.sourceResult,
          );
        } else {
          repairResult = await executeSynthesisRepair(
            schema, ctx, classification, schemaExample,
          );
        }
        result = {
          success: repairResult.success,
          output: repairResult.output,
          classification,
          repairAttempted: true,
          repairSucceeded: repairResult.success,
          rawContent: ctx.rawContent,
          repairContent: repairResult.content,
          repairCostUsd: repairResult.costUsd,
          repairDurationMs: repairResult.durationMs,
          gateId: ctx.gateId,
        };
      } catch (err) {
        result = {
          success: genericResult.success,
          output: genericResult.output,
          classification,
          repairAttempted: true,
          repairSucceeded: false,
          rawContent: ctx.rawContent,
          repairCostUsd: 0,
          gateId: ctx.gateId,
        };
      }
    }
  } else {
    result = {
      success: genericResult.success,
      output: genericResult.output,
      classification,
      repairAttempted: false,
      repairSucceeded: false,
      rawContent: ctx.rawContent,
      repairCostUsd: 0,
      gateId: ctx.gateId,
    };
  }

  // Archive
  try {
    await appendFile(ctx.sessionLogPath, JSON.stringify({
      type: 'gate_repair',
      gateId: ctx.gateId,
      at: new Date().toISOString(),
      failureClass: classification.failureClass,
      policy: classification.policy,
      detail: classification.detail,
      repairAttempted: result.repairAttempted,
      repairSucceeded: result.repairSucceeded,
      originalContentHead: ctx.rawContent.slice(0, 2000),
      repairContentHead: result.repairContent?.slice(0, 2000),
      repairCostUsd: result.repairCostUsd,
      repairDurationMs: result.repairDurationMs,
    }) + '\n', 'utf8');
  } catch {
    // archival failure should not block the pipeline
  }

  return result;
}
