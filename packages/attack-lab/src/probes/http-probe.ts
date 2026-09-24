import type { ProbeObservation } from '../../../evidence-plane/src/contracts.js';
import type { SecurityLabProbe, SecurityLabTarget } from '../types/runfile.js';

export async function runHttpProbe(
  probe: Extract<SecurityLabProbe, { kind: 'http_request' }>,
  target: Extract<SecurityLabTarget, { kind: 'http' }>,
): Promise<ProbeObservation> {
  const startedAt = Date.now();
  const url = new URL(probe.path, target.baseUrl).toString();
  const headers = {
    ...(target.defaultHeaders ?? {}),
    ...(probe.headers ?? {}),
  };

  const response = await fetch(url, {
    method: probe.method,
    headers,
    body: probe.body,
    signal: AbortSignal.timeout(probe.timeoutMs),
  });

  return {
    kind: probe.kind,
    statusCode: response.status,
    responseBody: await response.text(),
    durationMs: Date.now() - startedAt,
  };
}

