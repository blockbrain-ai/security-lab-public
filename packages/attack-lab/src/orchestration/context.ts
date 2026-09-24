import type { ProbeObservation } from '../../../evidence-plane/src/contracts.js';
import type { SecurityLabCapture, SecurityLabProbe } from '../types/runfile.js';

export type ProbeContext = Record<string, string>;

export function renderProbe(
  probe: SecurityLabProbe,
  context: ProbeContext,
): SecurityLabProbe {
  if (probe.kind === 'http_request') {
    return {
      ...probe,
      path: interpolateTemplate(probe.path, context),
      headers: mapValues(probe.headers, context),
      body: probe.body ? interpolateTemplate(probe.body, context) : undefined,
    };
  }

  return {
    ...probe,
    command: probe.command.map((part) => interpolateTemplate(part, context)),
    cwd: probe.cwd ? interpolateTemplate(probe.cwd, context) : undefined,
    env: mapValues(probe.env, context),
  };
}

export function captureStepValues(
  captureMap: Record<string, SecurityLabCapture> | undefined,
  observation: ProbeObservation,
): Record<string, string> {
  if (!captureMap) {
    return {};
  }

  const captures: Record<string, string> = {};

  for (const [key, capture] of Object.entries(captureMap)) {
    const sourceText = getCaptureSourceText(capture.source, observation);
    const match = new RegExp(capture.pattern, 'm').exec(sourceText);
    if (match?.[1]) {
      captures[key] = match[1];
    }
  }

  return captures;
}

function getCaptureSourceText(
  source: SecurityLabCapture['source'],
  observation: ProbeObservation,
): string {
  switch (source) {
    case 'responseBody':
      return observation.responseBody ?? '';
    case 'stdout':
      return observation.stdout ?? '';
    case 'stderr':
      return observation.stderr ?? '';
  }
}

function interpolateTemplate(input: string, context: ProbeContext): string {
  return input.replace(/\$\{([A-Za-z0-9_]+)\}/g, (_, key: string) => context[key] ?? '');
}

function mapValues(
  input: Record<string, string> | undefined,
  context: ProbeContext,
): Record<string, string> | undefined {
  if (!input) {
    return undefined;
  }

  return Object.fromEntries(
    Object.entries(input).map(([key, value]) => [key, interpolateTemplate(value, context)]),
  );
}

