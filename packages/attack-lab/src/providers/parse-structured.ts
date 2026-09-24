import type { z } from 'zod';

/**
 * Extract JSON from model output and validate against a Zod schema.
 *
 * Strategy: strict parse first, then a lenient coercion pass that handles
 * common local-model deviations (extra fields, nested objects where strings
 * are expected, missing optional fields). API models hit the strict path;
 * local models get a second chance before we discard the output.
 */
export function tryParseStructured<T>(
  content: string,
  schema?: z.ZodType<T, z.ZodTypeDef, unknown>,
): T | undefined {
  if (!schema) {
    return undefined;
  }

  const json = extractJson(content);
  if (json === undefined) {
    return undefined;
  }

  // Strict parse — works for well-behaved API models.
  try {
    return schema.parse(json);
  } catch {
    // fall through to lenient path
  }

  // Lenient pass — coerce common local-model deviations then retry.
  try {
    const coerced = coerceForSchema(json);
    return schema.parse(coerced);
  } catch {
    return undefined;
  }
}

/**
 * Extract the first plausible JSON object or array from model output.
 * Handles markdown fences, leading prose, and trailing commentary.
 */
function extractJson(content: string): unknown | undefined {
  // Try markdown fenced block first.
  const fenced = content.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  if (fenced) {
    try {
      return JSON.parse(fenced[1]!);
    } catch {
      // Malformed fence — fall through.
    }
  }

  // Try bare JSON object or array.
  const bare = content.match(/(\{[\s\S]*\}|\[[\s\S]*\])/);
  if (bare) {
    try {
      return JSON.parse(bare[1]!);
    } catch {
      // fall through
    }
  }

  return undefined;
}

/**
 * Recursively coerce common local-model deviations:
 *
 * 1. Arrays of objects where strings are expected — extract plausible
 *    string field (id, signalId, name, value) from each element.
 * 2. Object shapes with different field names for correlations —
 *    map {signals: [a, b], ...} → {signalIdA: a, signalIdB: b, resolved: false}.
 * 3. Strip unknown top-level fields (Zod .default() handles missing ones).
 */
function coerceForSchema(obj: unknown): unknown {
  if (obj === null || obj === undefined || typeof obj !== 'object') {
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map(coerceForSchema);
  }

  const record = obj as Record<string, unknown>;
  const result: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(record)) {
    // Strip explicit nulls — Zod .optional() accepts undefined, not null.
    if (value === null) continue;

    if (Array.isArray(value)) {
      result[key] = value.map((item) => coerceArrayElement(key, item));
    } else if (typeof value === 'object' && value !== null) {
      result[key] = coerceForSchema(value);
    } else {
      result[key] = value;
    }
  }

  return result;
}

/**
 * Coerce an individual array element based on the parent field name.
 * Handles the common case where a local model returns rich objects
 * where the schema expects plain strings.
 */
function coerceArrayElement(fieldName: string, item: unknown): unknown {
  if (typeof item === 'string') {
    return item;
  }

  if (typeof item !== 'object' || item === null) {
    return item;
  }

  const record = item as Record<string, unknown>;

  // promoteSignals / dismissSignals: schema wants string[], model gives {signalId, ...}[]
  if (fieldName === 'promoteSignals' || fieldName === 'dismissSignals') {
    const id = record['signalId'] ?? record['id'] ?? record['signal'] ?? record['name'];
    if (typeof id === 'string') return id;
  }

  // newCorrelations: schema wants {signalIdA, signalIdB, resolved},
  // model gives {signals: [a, b], reasoning: "..."}
  if (fieldName === 'newCorrelations') {
    const signals = record['signals'];
    if (Array.isArray(signals) && signals.length >= 2) {
      return {
        signalIdA: String(signals[0]),
        signalIdB: String(signals[1]),
        resolved: record['resolved'] ?? false,
      };
    }
  }

  // reactivateSignals: schema wants {signalId, reason}[],
  // model might give just string[]
  if (fieldName === 'reactivateSignals' && typeof record === 'object') {
    if (!('signalId' in record) && ('id' in record || 'signal' in record)) {
      return {
        signalId: String(record['id'] ?? record['signal']),
        reason: String(record['reason'] ?? ''),
      };
    }
  }

  return coerceForSchema(item);
}
