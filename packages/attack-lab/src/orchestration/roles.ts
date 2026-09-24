import type { OrchestrationSummary } from '../../../evidence-plane/src/contracts.js';
import type { SecurityLabOrchestration } from '../types/runfile.js';

const DEFAULT_ROLE = {
  strategy: 'scripted',
} as const;

export function resolveOrchestration(
  orchestration?: SecurityLabOrchestration,
): OrchestrationSummary {
  return {
    planner: roleLabel(orchestration?.planner ?? DEFAULT_ROLE),
    executor: roleLabel(orchestration?.executor ?? DEFAULT_ROLE),
    judge: roleLabel(orchestration?.judge ?? DEFAULT_ROLE),
    reporter: roleLabel(orchestration?.reporter ?? DEFAULT_ROLE),
  };
}

function roleLabel(role: {
  strategy: 'scripted' | 'manual' | 'provider';
  provider?: string;
  model?: string;
}): string {
  if (role.strategy === 'provider') {
    return `${role.provider ?? 'provider'}:${role.model ?? 'unspecified'}`;
  }

  return role.strategy;
}

