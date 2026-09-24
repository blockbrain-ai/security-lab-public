export type {
  GroundTruthSignal,
  GroundTruthChain,
  CorpusFixture,
  ThreatCorpus,
  SignalSurface,
  RunScore,
  FixtureScore,
  AggregateScore,
  ScoreComparison,
} from './contracts.js';
export {
  THREAT_CORPUS,
  getFixture,
  getAllSignals,
  getAllChains,
  getCorpusStats,
} from './corpus.js';
export type {
  InvestigatorOutput,
  ReportedSignal,
  ConfirmedChain,
} from './scorer.js';
export { scoreRun, compareRuns } from './scorer.js';
