/**
 * Structured-output repair — detects malformed/truncated model responses
 * and attempts bounded normalization before retrying.
 *
 * Rules:
 * - Maximum one repair attempt
 * - Maximum one retry attempt
 * - Every repair/retry is archived in evidence
 * - No invented content — only structural fixes
 *
 * Two layers:
 * - Generic JSON repair (extractJsonString, detectGenericFailureKind,
 *   repairGenericJson, parseWithGenericRepair) — schema-agnostic, used by
 *   GateSupervisor and any verify lane.
 * - Planner-specific repair (detectFailureKind, repairStructuredOutput,
 *   parseWithRepair) — adds planner alias mapping and default field injection.
 */

import type { z } from 'zod';

// ---------------------------------------------------------------------------
// Generic JSON repair layer — schema-agnostic
// ---------------------------------------------------------------------------

export type GenericFailureKind =
  | 'none'
  | 'truncated'
  | 'invalid_json'
  | 'no_json_found'
  | 'schema_mismatch';

export function extractJsonString(content: string): string | null {
  const m =
    content.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/) ??
    content.match(/(\{[\s\S]*\})/) ??
    content.match(/(\{[\s\S]+)/);  // fallback for truncated JSON (no closing brace)
  return m ? m[1]! : null;
}

export function detectGenericFailureKind(content: string): GenericFailureKind {
  const jsonStr = extractJsonString(content);
  if (!jsonStr) return 'no_json_found';

  const openBraces = (jsonStr.match(/\{/g) ?? []).length;
  const closeBraces = (jsonStr.match(/\}/g) ?? []).length;
  const openBrackets = (jsonStr.match(/\[/g) ?? []).length;
  const closeBrackets = (jsonStr.match(/\]/g) ?? []).length;

  if (openBraces > closeBraces || openBrackets > closeBrackets) return 'truncated';

  try {
    JSON.parse(jsonStr);
    return 'none';
  } catch {
    return 'invalid_json';
  }
}

export function repairGenericJson(content: string): string | null {
  const jsonStr = extractJsonString(content);
  if (!jsonStr) return null;

  let repaired = jsonStr;

  const openBraces = (repaired.match(/\{/g) ?? []).length;
  const closeBraces = (repaired.match(/\}/g) ?? []).length;
  const openBrackets = (repaired.match(/\[/g) ?? []).length;
  const closeBrackets = (repaired.match(/\]/g) ?? []).length;

  if (openBraces > closeBraces || openBrackets > closeBrackets) {
    repaired = repaired.replace(/,\s*"[^"]*$/, '');
    repaired = repaired.replace(/,\s*\{[^}]*$/, '');
    repaired = repaired.replace(/,\s*\[[^\]]*$/, '');
    repaired = repaired.replace(/,\s*$/, '');

    const curOpen = (repaired.match(/\[/g) ?? []).length;
    const curClose = (repaired.match(/\]/g) ?? []).length;
    const curOpenB = (repaired.match(/\{/g) ?? []).length;
    const curCloseB = (repaired.match(/\}/g) ?? []).length;
    for (let i = 0; i < curOpen - curClose; i++) repaired += ']';
    for (let i = 0; i < curOpenB - curCloseB; i++) repaired += '}';
  }

  try {
    JSON.parse(repaired);
    return repaired !== jsonStr ? repaired : null;
  } catch {
    return null;
  }
}

export interface GenericParseResult<T> {
  success: boolean;
  output?: T;
  failureKind: GenericFailureKind;
  repairAttempted: boolean;
  repairSucceeded: boolean;
  rawContent: string;
  repairedContent?: string;
}

export function parseWithGenericRepair<T>(
  content: string,
  schema: z.ZodType<T>,
  aliasMap?: Record<string, string>,
): GenericParseResult<T> {
  const jsonStr = extractJsonString(content);

  if (jsonStr) {
    try {
      let parsed = JSON.parse(jsonStr);
      if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) parsed = stripNullValues(parsed);
      if (aliasMap) parsed = applyAliasMap(parsed, aliasMap);
      const validated = schema.parse(parsed);
      return {
        success: true,
        output: validated,
        failureKind: 'none',
        repairAttempted: false,
        repairSucceeded: false,
        rawContent: content,
      };
    } catch {
      // Fall through
    }
  }

  const failureKind = detectGenericFailureKind(content);

  if (failureKind === 'no_json_found') {
    return { success: false, failureKind, repairAttempted: false, repairSucceeded: false, rawContent: content };
  }

  const repaired = repairGenericJson(content);
  if (repaired) {
    try {
      let parsed = JSON.parse(repaired);
      if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) parsed = stripNullValues(parsed);
      if (aliasMap) parsed = applyAliasMap(parsed, aliasMap);
      const validated = schema.parse(parsed);
      return {
        success: true,
        output: validated,
        failureKind,
        repairAttempted: true,
        repairSucceeded: true,
        rawContent: content,
        repairedContent: repaired,
      };
    } catch {
      // structural repair succeeded but schema still fails
    }
  }

  // Determine if schema_mismatch: JSON is structurally valid but Zod rejects
  const testStr = repaired ?? jsonStr;
  if (testStr) {
    try {
      JSON.parse(testStr);
      return { success: false, failureKind: 'schema_mismatch', repairAttempted: !!repaired, repairSucceeded: false, rawContent: content, repairedContent: repaired ?? undefined };
    } catch {
      // not valid JSON
    }
  }

  return { success: false, failureKind, repairAttempted: true, repairSucceeded: false, rawContent: content };
}

function stripNullValues(obj: Record<string, unknown>): Record<string, unknown> {
  for (const key of Object.keys(obj)) {
    if (obj[key] === null) {
      delete obj[key];
    }
  }
  return obj;
}

function applyAliasMap(obj: Record<string, unknown>, aliasMap: Record<string, string>): Record<string, unknown> {
  for (const [alias, canonical] of Object.entries(aliasMap)) {
    if (alias in obj && !(canonical in obj)) {
      obj[canonical] = obj[alias];
      delete obj[alias];
    }
  }
  return obj;
}

// ---------------------------------------------------------------------------
// Planner-specific repair layer
// ---------------------------------------------------------------------------

export type ParseFailureKind =
  | 'none'
  | 'truncated'
  | 'invalid_json'
  | 'alias_drift'
  | 'schema_mismatch'
  | 'no_json_found';

export interface ParseAttemptResult<T> {
  success: boolean;
  output?: T;
  failureKind: ParseFailureKind;
  repairAttempted: boolean;
  repairSucceeded: boolean;
  rawContent: string;
  repairedContent?: string;
}

const PLANNER_ALIAS_KEYS = ['weak_signals', 'signals', 'probes', 'hypotheses', 'chain_hypotheses', 'new_signals'];
const PLANNER_SCHEMA_KEYS = ['newSignals', 'probeRequests', 'reasoning'];

export function detectFailureKind(content: string): ParseFailureKind {
  const jsonStr = extractJsonString(content);
  if (!jsonStr) return 'no_json_found';

  const openBraces = (jsonStr.match(/\{/g) ?? []).length;
  const closeBraces = (jsonStr.match(/\}/g) ?? []).length;
  const openBrackets = (jsonStr.match(/\[/g) ?? []).length;
  const closeBrackets = (jsonStr.match(/\]/g) ?? []).length;

  if (openBraces > closeBraces || openBrackets > closeBrackets) return 'truncated';

  try {
    const parsed = JSON.parse(jsonStr);

    const hasAliases = PLANNER_ALIAS_KEYS.some((k) => k in parsed);
    const hasSchemaKeys = PLANNER_SCHEMA_KEYS.some((k) => k in parsed);

    if (hasAliases && !hasSchemaKeys) return 'alias_drift';

    return 'none';
  } catch {
    return 'invalid_json';
  }
}

const PLANNER_ALIAS_MAP: Record<string, string> = {
  'weak_signals': 'newSignals',
  'signals': 'newSignals',
  'new_signals': 'newSignals',
  'probes': 'probeRequests',
  'probe_requests': 'probeRequests',
  'hypotheses': 'newChainHypotheses',
  'chain_hypotheses': 'newChainHypotheses',
  'new_hypotheses': 'newChainHypotheses',
  'new_chain_hypotheses': 'newChainHypotheses',
  'mark_dormant': 'markDormant',
  'dormant': 'markDormant',
};

export function repairStructuredOutput(content: string): string | null {
  const jsonStr = extractJsonString(content);
  if (!jsonStr) return null;

  let workStr = jsonStr;

  const openBraces = (workStr.match(/\{/g) ?? []).length;
  const closeBraces = (workStr.match(/\}/g) ?? []).length;
  const openBrackets = (workStr.match(/\[/g) ?? []).length;
  const closeBrackets = (workStr.match(/\]/g) ?? []).length;

  if (openBraces > closeBraces || openBrackets > closeBrackets) {
    workStr = workStr.replace(/,\s*"[^"]*$/, '');
    workStr = workStr.replace(/,\s*\{[^}]*$/, '');
    workStr = workStr.replace(/,\s*\[[^\]]*$/, '');
    workStr = workStr.replace(/,\s*$/, '');

    const curOpen = (workStr.match(/\[/g) ?? []).length;
    const curClose = (workStr.match(/\]/g) ?? []).length;
    const curOpenB = (workStr.match(/\{/g) ?? []).length;
    const curCloseB = (workStr.match(/\}/g) ?? []).length;
    for (let i = 0; i < curOpen - curClose; i++) workStr += ']';
    for (let i = 0; i < curOpenB - curCloseB; i++) workStr += '}';
  }

  try {
    const parsed = JSON.parse(workStr);

    let changed = false;
    for (const [alias, canonical] of Object.entries(PLANNER_ALIAS_MAP)) {
      if (alias in parsed && !(canonical in parsed)) {
        parsed[canonical] = parsed[alias];
        delete parsed[alias];
        changed = true;
      }
    }

    if (!('newSignals' in parsed)) parsed.newSignals = [];
    if (!('probeRequests' in parsed)) parsed.probeRequests = [];
    if (!('newChainHypotheses' in parsed)) parsed.newChainHypotheses = [];
    if (!('markDormant' in parsed)) parsed.markDormant = [];
    if (!('reactivations' in parsed)) parsed.reactivations = [];
    if (!('reasoning' in parsed)) parsed.reasoning = '(repaired — original output was malformed)';

    if (Array.isArray(parsed.newSignals)) {
      for (const sig of parsed.newSignals) {
        if (sig.source_location && !sig.relatedAssets) {
          sig.relatedAssets = [sig.source_location];
          delete sig.source_location;
        }
        if (sig.tags && !sig.potentialCapabilities) {
          sig.potentialCapabilities = sig.tags;
          delete sig.tags;
        }
        if (!sig.relatedAssets) sig.relatedAssets = [];
        if (!sig.potentialCapabilities) sig.potentialCapabilities = [];
        if (!sig.suggestedFollowUps) sig.suggestedFollowUps = [];
      }
    }

    return changed || openBraces > closeBraces || openBrackets > closeBrackets
      ? JSON.stringify(parsed)
      : null;
  } catch {
    return null;
  }
}

export function parseWithRepair<T>(
  content: string,
  schema: z.ZodType<T>,
): ParseAttemptResult<T> {
  const failureKind = detectFailureKind(content);

  const jsonStr = extractJsonString(content);

  if (jsonStr) {
    try {
      const parsed = JSON.parse(jsonStr);
      const validated = schema.parse(parsed);
      return {
        success: true,
        output: validated,
        failureKind: 'none',
        repairAttempted: false,
        repairSucceeded: false,
        rawContent: content,
      };
    } catch {
      // Fall through to repair
    }
  }

  if (failureKind !== 'no_json_found') {
    const repaired = repairStructuredOutput(content);
    if (repaired) {
      try {
        const parsed = JSON.parse(repaired);
        const validated = schema.parse(parsed);
        return {
          success: true,
          output: validated,
          failureKind,
          repairAttempted: true,
          repairSucceeded: true,
          rawContent: content,
          repairedContent: repaired,
        };
      } catch {
        // Repair didn't produce valid schema output
      }
    }
  }

  return {
    success: false,
    failureKind,
    repairAttempted: failureKind !== 'no_json_found',
    repairSucceeded: false,
    rawContent: content,
  };
}
