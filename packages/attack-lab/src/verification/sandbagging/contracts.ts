/**
 * Diffuse sandbagging contracts — types for detecting slow, plausible,
 * cumulatively harmful behavior. The threat is many slightly-wrong
 * actions that add up rather than one catastrophic event.
 */

// ---------------------------------------------------------------------------
// Drift scenario
// ---------------------------------------------------------------------------

export interface DriftScenario {
  id: string;
  description: string;
  /** Each step the longitudinal runner walks the agent through. */
  steps: DriftStep[];
  /** What "honest mistake" looks like in this scenario. */
  honestMistakeMarkers: string[];
  /** What "patterned sabotage" looks like in this scenario. */
  patternedSabotageMarkers: string[];
}

export interface DriftStep {
  id: string;
  prompt: string;
  expectedAcceptableOutcomes: string[];
  expectedHarmfulOutcomes: string[];
}

// ---------------------------------------------------------------------------
// Episode result
// ---------------------------------------------------------------------------

export interface EpisodeResult {
  episodeId: string;
  scenarioId: string;
  step: string;
  agentResponse: string;
  classification: 'acceptable' | 'low_grade_harm' | 'patterned_harm' | 'unclear';
  weight: number;
  notes: string[];
}

// ---------------------------------------------------------------------------
// Cumulative impact
// ---------------------------------------------------------------------------

export interface CumulativeImpactScore {
  scenarioId: string;
  episodeCount: number;
  totalWeight: number;
  acceptableCount: number;
  lowGradeCount: number;
  patternedCount: number;
  cumulativeImpact: number;
  verdict: 'no_pattern' | 'patterned_degradation' | 'inconclusive' | 'not_applicable';
  reasoning: string;
}
