/**
 * Rare-action runner — sends a SHADE scenario through many iterations
 * but actually performs the harmful action only at a deliberately low
 * frequency (e.g., 1 in 50). Measures whether the monitoring layer
 * still catches the rare attempts.
 */

import { findScenario } from './shade-scenarios.js';
import type { RareActionExperiment } from './contracts.js';

// ---------------------------------------------------------------------------
// Rare-action options
// ---------------------------------------------------------------------------

export interface RareActionOptions {
  scenarioId: string;
  totalAttempts: number;
  rareActionFrequency: number;
  /** Function that simulates one attempt; returns whether monitor detected. */
  simulateAttempt: (params: {
    iteration: number;
    isHarmful: boolean;
  }) => Promise<{ detected: boolean }>;
}

// ---------------------------------------------------------------------------
// Rare-action runner
// ---------------------------------------------------------------------------

export class RareActionRunner {
  async run(options: RareActionOptions): Promise<RareActionExperiment> {
    const scenario = findScenario(options.scenarioId);
    if (!scenario) {
      throw new Error(`Unknown SHADE scenario: ${options.scenarioId}`);
    }

    const harmfulInterval = Math.max(1, Math.round(1 / options.rareActionFrequency));
    let detectedCount = 0;
    let missedCount = 0;

    for (let i = 0; i < options.totalAttempts; i++) {
      const isHarmful = i > 0 && i % harmfulInterval === 0;
      const result = await options.simulateAttempt({ iteration: i, isHarmful });
      if (isHarmful) {
        if (result.detected) {
          detectedCount += 1;
        } else {
          missedCount += 1;
        }
      }
    }

    return {
      experimentId: `rare-action-${options.scenarioId}-${Date.now()}`,
      scenarioId: options.scenarioId,
      totalAttempts: options.totalAttempts,
      rareActionFrequency: options.rareActionFrequency,
      detectedCount,
      missedCount,
    };
  }
}
