/**
 * Section 6.1 — Mid-round hypothesis synthesis.
 *
 * Wraps the campaign-level chain synthesizer so it can run *within*
 * a local-live round instead of only at round boundaries. When a probe
 * produces a high-novelty runtime signal, this module asks the
 * synthesizer to propose new hypotheses immediately and returns any
 * brand-new ones so the caller can enqueue them into the current
 * round's packet queue. Novelty gating avoids rerunning synthesis on
 * every probe.
 */

import type { CampaignMemory, ChainHypothesis } from '../../autonomous/contracts.js';
import { findChainCandidatesNearSignals } from '../../autonomous/attack-graph.js';
import { synthesizeHypotheses } from '../../autonomous/chain-synthesizer.js';

export interface MidRoundSynthesisOptions {
  /**
   * Novelty threshold that triggers mid-round synthesis. Signals with
   * novelty below this value do not invoke the synthesizer. Default 0.65.
   */
  noveltyThreshold?: number;
  /**
   * Max new hypotheses that may be synthesized per call. Default 5.
   */
  maxNew?: number;
  /**
   * Maximum graph neighborhood depth explored from the trigger signals.
   * Keeps local-live mid-round synthesis focused on runtime-adjacent
   * evidence instead of recomputing chain candidates across the entire
   * campaign graph.
   */
  neighborhoodDepth?: number;
  /**
   * Hard cap on the number of graph nodes included in the focused
   * synthesis neighborhood.
   */
  nodeBudget?: number;
  /**
   * Maximum path depth within the focused subgraph.
   */
  maxDepth?: number;
}

export interface MidRoundSynthesisTrigger {
  signalId: string;
  novelty: number;
}

export interface MidRoundSynthesisResult {
  /** Whether synthesis actually ran (novelty gating could skip it). */
  invoked: boolean;
  /** Reason synthesis was skipped, if applicable. */
  skipReason?: string;
  /** New hypotheses added to memory.hypotheses by this call. */
  newHypotheses: ChainHypothesis[];
  /** IDs of the triggering runtime signals. */
  triggers: MidRoundSynthesisTrigger[];
}

/**
 * Run chain-candidate discovery + synthesis against the current memory.
 * Only runs if at least one of the supplied triggers has novelty >=
 * the configured threshold. Returns any brand-new hypotheses so the
 * caller can enqueue them into the current round's queue.
 */
export function runMidRoundSynthesis(
  memory: CampaignMemory,
  triggers: MidRoundSynthesisTrigger[],
  options: MidRoundSynthesisOptions = {},
): MidRoundSynthesisResult {
  const threshold = options.noveltyThreshold ?? 0.65;
  const maxNew = options.maxNew ?? 5;

  const highNovelty = triggers.filter((trigger) => trigger.novelty >= threshold);
  if (highNovelty.length === 0) {
    return {
      invoked: false,
      skipReason: `no trigger signal met novelty threshold ${threshold}`,
      newHypotheses: [],
      triggers,
    };
  }

  const before = new Set(memory.hypotheses.map((hypothesis) => hypothesis.id));
  const candidates = findChainCandidatesNearSignals(
    memory.graph,
    highNovelty.map((trigger) => trigger.signalId),
    {
      neighborhoodDepth: options.neighborhoodDepth ?? 3,
      nodeBudget: options.nodeBudget ?? 64,
      maxDepth: options.maxDepth ?? 4,
    },
  );
  synthesizeHypotheses(memory, candidates, maxNew);
  const newHypotheses = memory.hypotheses.filter((hypothesis) => !before.has(hypothesis.id));

  return {
    invoked: true,
    newHypotheses,
    triggers: highNovelty,
  };
}

/**
 * Extract trigger candidates from a set of runtime signals that were
 * just created for the current round. Used by the LocalLiveStage to
 * decide whether to call {@link runMidRoundSynthesis}.
 */
export function selectMidRoundTriggers(
  memory: CampaignMemory,
  runtimeSignalIds: string[],
): MidRoundSynthesisTrigger[] {
  const seen = new Set<string>();
  return runtimeSignalIds
    .filter((id) => {
      if (seen.has(id)) {
        return false;
      }
      seen.add(id);
      return true;
    })
    .map((id) => memory.signals.find((signal) => signal.id === id))
    .filter((signal): signal is NonNullable<typeof signal> => Boolean(signal))
    .map((signal) => ({ signalId: signal.id, novelty: signal.novelty }));
}
