import type { ToolTranscriptEntry } from '../providers/contracts.js';
import type { RuntimeVerificationResult } from './runtime-verify-schemas.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface ValidationNote {
  rule: string;
  detail: string;
}

export interface ValidatedRuntimeResult {
  /** The model's original unmodified result. */
  modelResult: RuntimeVerificationResult;
  /** The post-validation result (may differ from modelResult). */
  validatedResult: RuntimeVerificationResult;
  /** Whether the validator overrode the model's status/pvrReady. */
  wasDowngraded: boolean;
  /** Specific validation failures. */
  validationNotes: ValidationNote[];
}

// ---------------------------------------------------------------------------
// Whitespace normalization for substring matching
// ---------------------------------------------------------------------------

function normalize(s: string): string {
  return s.replace(/\s+/g, ' ').trim().toLowerCase();
}

function normalizedIncludes(haystack: string, needle: string): boolean {
  if (needle.length === 0) return false;
  return normalize(haystack).includes(normalize(needle));
}

// ---------------------------------------------------------------------------
// Rule 1: confirmed requires at least one runtime tool call
// ---------------------------------------------------------------------------

const RUNTIME_TOOLS = new Set(['http_request', 'shell_exec']);

function checkHasRuntimeToolCall(
  transcript: ToolTranscriptEntry[],
): ValidationNote | null {
  const hasRuntime = transcript.some((t) => RUNTIME_TOOLS.has(t.tool));
  if (!hasRuntime) {
    return {
      rule: 'runtime_tool_required',
      detail: 'confirmed requires at least one http_request or shell_exec call; only source reads found',
    };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Rule 2: reproducerOutput / httpEvidence snippets must appear in transcript
// ---------------------------------------------------------------------------

function checkReproducerOutputInTranscript(
  result: RuntimeVerificationResult,
  transcript: ToolTranscriptEntry[],
): ValidationNote[] {
  const notes: ValidationNote[] = [];
  const allOutputs = transcript.map((t) => t.output);

  if (result.reproducerOutput && result.reproducerOutput.length > 0) {
    const chunks = splitIntoChunks(result.reproducerOutput, 40);
    const anyMatch = chunks.some((chunk) =>
      allOutputs.some((out) => normalizedIncludes(out, chunk)),
    );
    if (!anyMatch) {
      notes.push({
        rule: 'reproducer_output_not_in_transcript',
        detail: `reproducerOutput does not match any tool transcript output (first 80 chars: "${result.reproducerOutput.slice(0, 80)}")`,
      });
    }
  }

  for (let i = 0; i < result.httpEvidence.length; i++) {
    const ev = result.httpEvidence[i]!;
    if (!ev.snippet || ev.snippet.length < 8) continue;
    const anyMatch = allOutputs.some((out) => normalizedIncludes(out, ev.snippet));
    if (!anyMatch) {
      notes.push({
        rule: 'http_evidence_snippet_not_in_transcript',
        detail: `httpEvidence[${i}].snippet not found in any tool output (snippet: "${ev.snippet.slice(0, 80)}")`,
      });
    }
  }

  return notes;
}

function splitIntoChunks(text: string, minLen: number): string[] {
  const lines = text.split('\n').filter((l) => l.trim().length >= minLen);
  if (lines.length > 0) return lines;
  if (text.length >= minLen) return [text];
  if (text.trim().length >= 8) return [text];
  return [];
}

// ---------------------------------------------------------------------------
// Rule 3: named controls must appear in source refs or transcript
// ---------------------------------------------------------------------------

const CONTROL_PATTERNS = [
  /\bx-[\w-]+/gi,                     // X- headers
  /\b(?:authorization|content-type|cookie|set-cookie|host|origin|referer)\b/gi,
  /(?<=[\s"'`])\/[a-z_/][\w/.-]{2,}/gi, // URL paths like /api/pass-through
  /\b[a-z_]{2,}(?:_key|_token|_secret|_url|_id|_param)\b/gi, // config keys
];

const IGNORE_CONTROLS = new Set([
  'content-type', 'authorization', 'host', 'cookie',
  'x-content-type-options', 'x-frame-options',
]);

export function extractNamedControls(text: string): string[] {
  const controls = new Set<string>();
  for (const re of CONTROL_PATTERNS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const val = m[0].toLowerCase();
      if (!IGNORE_CONTROLS.has(val) && val.length > 3) {
        controls.add(val);
      }
    }
  }
  return [...controls];
}

function checkNamedControlsInEvidence(
  result: RuntimeVerificationResult,
  transcript: ToolTranscriptEntry[],
): ValidationNote[] {
  const notes: ValidationNote[] = [];

  const claimControls = extractNamedControls(result.claim + ' ' + result.rootCause);
  if (claimControls.length === 0) return notes;

  const allText = transcript.map((t) => t.output).join('\n');
  const allArgs = transcript.map((t) => JSON.stringify(t.args)).join('\n');
  const combinedEvidence = (allText + '\n' + allArgs).toLowerCase();

  const missing: string[] = [];
  for (const control of claimControls) {
    if (!combinedEvidence.includes(control)) {
      missing.push(control);
    }
  }

  if (missing.length > 0) {
    notes.push({
      rule: 'named_control_not_in_evidence',
      detail: `Controls referenced in claim/rootCause but not found in any tool transcript: ${missing.join(', ')}`,
    });
  }

  return notes;
}

// ---------------------------------------------------------------------------
// Main validator
// ---------------------------------------------------------------------------

export function validateRuntimeResult(
  result: RuntimeVerificationResult,
  transcript: ToolTranscriptEntry[],
): ValidatedRuntimeResult {
  const notes: ValidationNote[] = [];

  const needsValidation = result.status === 'confirmed' || result.pvrReady;
  if (!needsValidation) {
    return {
      modelResult: structuredClone(result),
      validatedResult: result,
      wasDowngraded: false,
      validationNotes: [],
    };
  }

  const runtimeNote = checkHasRuntimeToolCall(transcript);
  if (runtimeNote) notes.push(runtimeNote);

  notes.push(...checkReproducerOutputInTranscript(result, transcript));
  notes.push(...checkNamedControlsInEvidence(result, transcript));

  const shouldDowngrade = notes.length > 0;

  if (shouldDowngrade) {
    const validated = structuredClone(result);
    if (validated.status === 'confirmed') {
      validated.status = 'partially_confirmed';
    }
    validated.pvrReady = false;
    const notesSummary = notes.map((n) => `[${n.rule}] ${n.detail}`).join('; ');
    validated.filingNotes = validated.filingNotes
      ? `${validated.filingNotes}\n\n--- VALIDATION OVERRIDE ---\n${notesSummary}`
      : `--- VALIDATION OVERRIDE ---\n${notesSummary}`;

    return {
      modelResult: structuredClone(result),
      validatedResult: validated,
      wasDowngraded: true,
      validationNotes: notes,
    };
  }

  return {
    modelResult: structuredClone(result),
    validatedResult: result,
    wasDowngraded: false,
    validationNotes: [],
  };
}
