/**
 * Telemetry — per-invocation cost tracking, budget enforcement,
 * and accumulated metrics. Mirrors the reference architecture's telemetry pattern.
 */

import type { TokenUsage } from '../providers/contracts.js';
import type { InvestigationState } from './state.js';

// ---------------------------------------------------------------------------
// Per-invocation tracking
// ---------------------------------------------------------------------------

export interface InvocationRecord {
  kind: 'plan' | 'counter_plan' | 'judge' | 'tribunal' | 'synthesizer' | 'reporter' | 'scan' | 'probe';
  at: string;
  provider: string;
  model: string;
  usage: TokenUsage;
  durationMs: number;
}

export interface TelemetryAccumulator {
  records: InvocationRecord[];
  totalCostUsd: number;
  totalInputTokens: number;
  totalOutputTokens: number;
  totalDurationMs: number;
  invocationCount: number;
  byKind: Record<string, KindMetrics>;
}

export interface KindMetrics {
  count: number;
  costUsd: number;
  inputTokens: number;
  outputTokens: number;
  durationMs: number;
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

export function createAccumulator(): TelemetryAccumulator {
  return {
    records: [],
    totalCostUsd: 0,
    totalInputTokens: 0,
    totalOutputTokens: 0,
    totalDurationMs: 0,
    invocationCount: 0,
    byKind: {},
  };
}

export function recordInvocation(
  acc: TelemetryAccumulator,
  record: InvocationRecord,
): void {
  acc.records.push(record);
  acc.totalCostUsd += record.usage.costUsd;
  acc.totalInputTokens += record.usage.inputTokens;
  acc.totalOutputTokens += record.usage.outputTokens;
  acc.totalDurationMs += record.durationMs;
  acc.invocationCount++;

  const kind = acc.byKind[record.kind] ?? {
    count: 0, costUsd: 0, inputTokens: 0, outputTokens: 0, durationMs: 0,
  };
  kind.count++;
  kind.costUsd += record.usage.costUsd;
  kind.inputTokens += record.usage.inputTokens;
  kind.outputTokens += record.usage.outputTokens;
  kind.durationMs += record.durationMs;
  acc.byKind[record.kind] = kind;
}

export function isBudgetExceeded(
  acc: TelemetryAccumulator,
  state: InvestigationState,
): boolean {
  return acc.totalCostUsd >= state.maxCostUsd;
}

export function summarizeTelemetry(acc: TelemetryAccumulator): string {
  const lines = [
    `Total cost: $${acc.totalCostUsd.toFixed(4)}`,
    `Total tokens: ${acc.totalInputTokens} in / ${acc.totalOutputTokens} out`,
    `Total duration: ${(acc.totalDurationMs / 1000).toFixed(1)}s`,
    `Invocations: ${acc.invocationCount}`,
    '',
    'By kind:',
  ];

  for (const [kind, metrics] of Object.entries(acc.byKind)) {
    lines.push(
      `  ${kind}: ${metrics.count} calls, $${metrics.costUsd.toFixed(4)}, ${(metrics.durationMs / 1000).toFixed(1)}s`,
    );
  }

  return lines.join('\n');
}
