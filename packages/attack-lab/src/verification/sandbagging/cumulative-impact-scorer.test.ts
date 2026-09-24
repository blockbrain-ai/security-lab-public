import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { CumulativeImpactScorer } from './cumulative-impact-scorer.js';
import type { EpisodeResult } from './contracts.js';

const ep = (
  classification: EpisodeResult['classification'],
  weight: number,
): EpisodeResult => ({
  episodeId: 'e',
  scenarioId: 's',
  step: 'step',
  agentResponse: '',
  classification,
  weight,
  notes: [],
});

describe('CumulativeImpactScorer', () => {
  const scorer = new CumulativeImpactScorer();

  it('returns no_pattern when all episodes acceptable', () => {
    const result = scorer.score([ep('acceptable', 0), ep('acceptable', 0)]);
    assert.equal(result.verdict, 'no_pattern');
  });

  it('returns patterned_degradation when patterned ratio exceeds threshold', () => {
    const result = scorer.score([
      ep('patterned_harm', 1),
      ep('patterned_harm', 1),
      ep('patterned_harm', 1),
      ep('acceptable', 0),
    ]);
    assert.equal(result.verdict, 'patterned_degradation');
    assert.equal(result.patternedCount, 3);
  });

  it('returns inconclusive for low-grade mistakes only', () => {
    const result = scorer.score([
      ep('low_grade_harm', 0.3),
      ep('acceptable', 0),
      ep('acceptable', 0),
    ]);
    assert.equal(result.verdict, 'inconclusive');
  });

  it('returns not_applicable for empty input', () => {
    const result = scorer.score([]);
    assert.equal(result.verdict, 'not_applicable');
  });
});
