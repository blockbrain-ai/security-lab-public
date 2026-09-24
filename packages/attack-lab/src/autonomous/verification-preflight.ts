import { z } from 'zod';
import type { ResolvedVerificationProfile, VerificationStageModel } from './verification-profiles.js';

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

export const PreflightCheckSchema = z.object({
  stage: z.enum(['source', 'sourceCritic', 'runtimeSetup', 'runtimeProbe']),
  name: z.enum([
    'endpoint_reachable',
    'structured_json',
    'read_only_tools',
    'runtime_tools',
  ]),
  status: z.enum(['pass', 'fail', 'skip']),
  detail: z.string(),
});

export type PreflightCheck = z.infer<typeof PreflightCheckSchema>;

export const VerificationPreflightReportSchema = z.object({
  profileId: z.string().nullable(),
  checks: z.array(PreflightCheckSchema),
  passed: z.boolean(),
});

export type VerificationPreflightReport = z.infer<typeof VerificationPreflightReportSchema>;

// ---------------------------------------------------------------------------
// Individual check runners
// ---------------------------------------------------------------------------

async function checkEndpointReachable(
  stage: PreflightCheck['stage'],
  stageModel: VerificationStageModel,
): Promise<PreflightCheck> {
  const baseUrl = (stageModel.baseUrl ?? 'http://127.0.0.1:8080/v1').replace(/\/+$/, '');
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const res = await fetch(`${baseUrl}/models`, { signal: controller.signal });
    clearTimeout(timeout);
    if (res.ok) {
      return { stage, name: 'endpoint_reachable', status: 'pass', detail: `${baseUrl}/models returned ${res.status}` };
    }
    return { stage, name: 'endpoint_reachable', status: 'fail', detail: `${baseUrl}/models returned ${res.status}` };
  } catch (err) {
    return { stage, name: 'endpoint_reachable', status: 'fail', detail: err instanceof Error ? err.message : String(err) };
  }
}

async function checkStructuredJson(
  stage: PreflightCheck['stage'],
  stageModel: VerificationStageModel,
): Promise<PreflightCheck> {
  const baseUrl = (stageModel.baseUrl ?? 'http://127.0.0.1:8080/v1').replace(/\/+$/, '');
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 120_000);
    const res = await fetch(`${baseUrl}/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      body: JSON.stringify({
        model: stageModel.model,
        messages: [
          { role: 'system', content: 'Return valid JSON only. /no_think' },
          { role: 'user', content: 'Return exactly: {"ok": true}' },
        ],
        max_tokens: 1024,
        temperature: 0,
      }),
    });
    clearTimeout(timeout);

    if (!res.ok) {
      return { stage, name: 'structured_json', status: 'fail', detail: `Chat completions returned ${res.status}` };
    }

    const body = await res.json() as { choices?: Array<{ message?: { content?: string; reasoning_content?: string; reasoning?: string } }> };
    const msg = body.choices?.[0]?.message;
    const content = msg?.content ?? '';
    const reasoning = msg?.reasoning_content ?? msg?.reasoning ?? '';
    const textToCheck = content || reasoning;
    const jsonMatch = textToCheck.match(/\{[^}]*\}/);
    if (jsonMatch) {
      try {
        JSON.parse(jsonMatch[0]);
        return { stage, name: 'structured_json', status: 'pass', detail: `Model returned parseable JSON${content ? '' : ' (extracted from reasoning)'}` };
      } catch { /* fall through */ }
    }
    return { stage, name: 'structured_json', status: 'fail', detail: `Model response was not valid JSON: ${textToCheck.slice(0, 120)}` };
  } catch (err) {
    return { stage, name: 'structured_json', status: 'fail', detail: err instanceof Error ? err.message : String(err) };
  }
}

function skipReadOnlyTools(stage: PreflightCheck['stage']): PreflightCheck {
  return {
    stage,
    name: 'read_only_tools',
    status: 'skip',
    detail: 'Read-only tool verification requires a full adapter invocation; skipped in preflight',
  };
}

function skipRuntimeTools(stage: PreflightCheck['stage']): PreflightCheck {
  return {
    stage,
    name: 'runtime_tools',
    status: 'skip',
    detail: 'Runtime tool verification requires Docker; skipped in preflight',
  };
}

// ---------------------------------------------------------------------------
// Main preflight runner
// ---------------------------------------------------------------------------

export interface PreflightOptions {
  skipStructuredJson?: boolean;
}

export async function runPreflight(
  resolved: ResolvedVerificationProfile,
  opts?: PreflightOptions,
): Promise<VerificationPreflightReport> {
  const checks: PreflightCheck[] = [];

  const stages: Array<{ stage: PreflightCheck['stage']; model: VerificationStageModel; kind: 'source' | 'runtime' }> = [
    { stage: 'source', model: resolved.source, kind: 'source' },
    { stage: 'sourceCritic', model: resolved.sourceCritic, kind: 'source' },
    { stage: 'runtimeSetup', model: resolved.runtimeSetup, kind: 'runtime' },
    { stage: 'runtimeProbe', model: resolved.runtimeProbe, kind: 'runtime' },
  ];

  // Deduplicate endpoint checks for stages sharing the same baseUrl+model
  const seen = new Set<string>();

  for (const { stage, model, kind } of stages) {
    const endpointKey = `${model.baseUrl ?? 'default'}::${model.model}`;
    const needsEndpointCheck = !seen.has(endpointKey);
    if (needsEndpointCheck) seen.add(endpointKey);

    if (needsEndpointCheck) {
      checks.push(await checkEndpointReachable(stage, model));
    }

    if (kind === 'source' && !opts?.skipStructuredJson) {
      if (needsEndpointCheck) {
        checks.push(await checkStructuredJson(stage, model));
      }
    }

    if (kind === 'source' && model.provider === 'bounded_local') {
      checks.push(skipReadOnlyTools(stage));
    }

    if (kind === 'runtime' && model.provider === 'bounded_local') {
      checks.push(skipRuntimeTools(stage));
    }
  }

  const passed = checks.every((c) => c.status !== 'fail');

  return {
    profileId: resolved.id,
    checks,
    passed,
  };
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

export function formatPreflightReport(report: VerificationPreflightReport): string {
  const lines: string[] = [];
  lines.push(`Preflight Report — profile: ${report.profileId ?? '(ad-hoc)'}`);
  lines.push(`Result: ${report.passed ? 'PASS' : 'FAIL'}`);
  lines.push('');

  for (const check of report.checks) {
    const icon = check.status === 'pass' ? '+' : check.status === 'fail' ? 'X' : '-';
    lines.push(`  [${icon}] ${check.stage} / ${check.name}: ${check.detail}`);
  }

  return lines.join('\n');
}
