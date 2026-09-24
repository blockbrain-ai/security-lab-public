/**
 * Orchestration policy — governs role assignment, escalation rules,
 * and budget allocation across planner, judge, and tribunal.
 */

import type { ModelConfig } from '../providers/contracts.js';

// ---------------------------------------------------------------------------
// Policy configuration
// ---------------------------------------------------------------------------

export interface OrchestrationPolicy {
  /** Provider config for the planner role. */
  planner: RoleAssignment;
  /** Provider config for the judge role. */
  judge: RoleAssignment;
  /** Provider config for tribunal escalation. */
  tribunal: TribunalPolicy;
  /** Provider config for report generation. */
  reporter: RoleAssignment;
  /** Budget split across roles (fractions summing to 1.0). */
  budgetSplit: BudgetSplit;
}

export interface RoleAssignment {
  /** 'scripted' uses built-in logic, 'provider' uses a model. */
  strategy: 'scripted' | 'provider';
  /** Model config (required when strategy is 'provider'). */
  config?: ModelConfig;
}

export interface TribunalPolicy {
  /** Whether tribunal is enabled. */
  enabled: boolean;
  /** Model config for the tribunal arbiter. */
  config?: ModelConfig;
  /** Trigger conditions for tribunal escalation. */
  triggers: TribunalTrigger[];
}

export interface TribunalTrigger {
  /** What triggers escalation. */
  condition: 'severity_critical' | 'planner_judge_disagree' | 'chain_length_exceeds' | 'manual';
  /** Threshold value (e.g. chain length threshold). */
  threshold?: number;
}

export interface BudgetSplit {
  planner: number;
  judge: number;
  tribunal: number;
  reporter: number;
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

export const DEFAULT_POLICY: OrchestrationPolicy = {
  planner: { strategy: 'scripted' },
  judge: { strategy: 'scripted' },
  tribunal: {
    enabled: false,
    triggers: [
      { condition: 'severity_critical' },
      { condition: 'planner_judge_disagree' },
    ],
  },
  reporter: { strategy: 'scripted' },
  budgetSplit: {
    planner: 0.4,
    judge: 0.3,
    tribunal: 0.2,
    reporter: 0.1,
  },
};

// ---------------------------------------------------------------------------
// Policy resolution
// ---------------------------------------------------------------------------

export function resolvePolicy(
  overrides?: Partial<OrchestrationPolicy>,
): OrchestrationPolicy {
  if (!overrides) return { ...DEFAULT_POLICY };

  return {
    planner: overrides.planner ?? DEFAULT_POLICY.planner,
    judge: overrides.judge ?? DEFAULT_POLICY.judge,
    tribunal: overrides.tribunal ?? DEFAULT_POLICY.tribunal,
    reporter: overrides.reporter ?? DEFAULT_POLICY.reporter,
    budgetSplit: overrides.budgetSplit ?? DEFAULT_POLICY.budgetSplit,
  };
}

export function shouldEscalateToTribunal(
  policy: OrchestrationPolicy,
  context: {
    severity?: string;
    plannerVerdict?: string;
    judgeVerdict?: string;
    chainLength?: number;
  },
): boolean {
  if (!policy.tribunal.enabled) return false;

  for (const trigger of policy.tribunal.triggers) {
    switch (trigger.condition) {
      case 'severity_critical':
        if (context.severity === 'critical') return true;
        break;
      case 'planner_judge_disagree':
        if (
          context.plannerVerdict &&
          context.judgeVerdict &&
          context.plannerVerdict !== context.judgeVerdict
        ) return true;
        break;
      case 'chain_length_exceeds':
        if (
          trigger.threshold &&
          context.chainLength &&
          context.chainLength > trigger.threshold
        ) return true;
        break;
      case 'manual':
        break;
    }
  }

  return false;
}
