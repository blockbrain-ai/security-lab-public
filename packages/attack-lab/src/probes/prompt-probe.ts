/**
 * Prompt probe — tests for business-data and tool-output instruction
 * smuggling. Injects content into fields that an LLM might process
 * and checks whether the system follows injected instructions.
 */

import type { ProbeObservation } from '../../../evidence-plane/src/contracts.js';

export interface PromptProbeConfig {
  kind: 'prompt_injection';
  action: 'field_injection' | 'tool_output_smuggle' | 'system_prompt_leak';
  /** The injection payload. */
  payload: string;
  /** Target field where payload is injected (e.g. 'invoice.description'). */
  targetField: string;
  /** Expected behavior if injection succeeds. */
  successIndicator: string;
  /** HTTP endpoint to test against. */
  endpoint?: string;
  timeoutMs: number;
}

export async function runPromptProbe(
  probe: PromptProbeConfig,
  baseUrl: string,
  defaultHeaders?: Record<string, string>,
): Promise<ProbeObservation> {
  const start = Date.now();

  try {
    const url = new URL(probe.endpoint ?? '/api/v1/health', baseUrl);
    const body = JSON.stringify({
      [probe.targetField]: probe.payload,
      _probeMetadata: { action: probe.action, targetField: probe.targetField },
    });

    const response = await fetch(url.toString(), {
      method: 'POST',
      headers: {
        ...(defaultHeaders ?? {}),
        'Content-Type': 'application/json',
      },
      body,
      signal: AbortSignal.timeout(probe.timeoutMs),
    });

    const responseBody = await response.text();
    const injectionDetected = responseBody.includes(probe.successIndicator);

    return {
      kind: 'prompt_injection',
      statusCode: response.status,
      responseBody,
      stdout: injectionDetected ? `INJECTION_DETECTED: ${probe.successIndicator}` : 'no_injection_detected',
      durationMs: Date.now() - start,
    };
  } catch (error: unknown) {
    return {
      kind: 'prompt_injection',
      stderr: error instanceof Error ? error.message : String(error),
      durationMs: Date.now() - start,
    };
  }
}
