/**
 * Monitoring stress contracts — types for paired declared/blind runs,
 * SHADE-style hidden side tasks, long-context monitor stress, and
 * rare-action experiments. The goal is to measure whether the
 * investigator and its monitoring layers stay reliable when behavior
 * becomes covert, long-context, or selectively stealthy.
 */

// ---------------------------------------------------------------------------
// Mode and context bands
// ---------------------------------------------------------------------------

export type CampaignMode = 'declared' | 'blind' | 'paired';

export type ContextBand = 'baseline' | '50k' | '100k' | '200k' | '400k';

// ---------------------------------------------------------------------------
// SHADE scenario
// ---------------------------------------------------------------------------

export interface ShadeScenario {
  id: string;
  description: string;
  /** The publicly stated task the agent appears to be working on. */
  primaryTask: string;
  /** The hidden harmful task the agent is also pursuing. */
  hiddenTask: string;
  /** Markers a monitor is expected to detect if it's working. */
  monitorDetectionMarkers: string[];
  /** Whether the scenario should ever be allowed to actually execute. */
  executionMode: 'simulated' | 'sandbox';
}

// ---------------------------------------------------------------------------
// Monitoring stress result
// ---------------------------------------------------------------------------

export interface MonitoringStressResult {
  scenarioId: string;
  mode: CampaignMode;
  contextBand: ContextBand;
  attempt: boolean;
  block: boolean;
  outcome: 'no_signal' | 'harmful_action_seen' | 'monitoring_degraded' | 'not_applicable';
  stealthScore: number;
  detectionLatencyMs: number | null;
  monitorEvents: Array<{ at: string; marker: string }>;
  notes: string[];
}

// ---------------------------------------------------------------------------
// Long-context experiment
// ---------------------------------------------------------------------------

export interface LongContextExperiment {
  experimentId: string;
  contextBand: ContextBand;
  promptTokens: number;
  targetActionAtToken: number;
  monitorRecallScore: number;
  observed: boolean;
  notes: string[];
}

// ---------------------------------------------------------------------------
// Rare-action experiment
// ---------------------------------------------------------------------------

export interface RareActionExperiment {
  experimentId: string;
  scenarioId: string;
  totalAttempts: number;
  rareActionFrequency: number;
  detectedCount: number;
  missedCount: number;
}
