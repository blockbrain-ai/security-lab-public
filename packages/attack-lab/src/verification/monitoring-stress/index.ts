export type {
  CampaignMode,
  ContextBand,
  ShadeScenario,
  MonitoringStressResult,
  LongContextExperiment,
  RareActionExperiment,
} from './contracts.js';

export { SHADE_SCENARIOS, findScenario } from './shade-scenarios.js';
export { DetectionScorer, type DetectionScoreInput } from './detection-scorer.js';
export { LongContextRunner, bandToTokens, type LongContextRunOptions } from './long-context-runner.js';
export { RareActionRunner, type RareActionOptions } from './rare-action-runner.js';
