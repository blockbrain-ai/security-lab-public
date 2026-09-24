export type {
  PriorFinding,
  RefutedChain,
  RegressionPackRef,
  DependencyDecision,
  TargetFingerprint,
  KnowledgeBase,
} from './contracts.js';
export {
  loadKnowledgeBase,
  saveKnowledgeBase,
  createEmptyKnowledgeBase,
  getRelevantFindings,
  getRefutedChains,
  getRegressionPacks,
  getDependencyDecisions,
  addFinding,
  addRefutedChain,
  addRegressionPack,
  addDependencyDecision,
  addFingerprint,
  summarizeKnowledgeBase,
} from './store.js';
