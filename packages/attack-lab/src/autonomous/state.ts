/**
 * Investigation state machine — atomic persistence, phase tracking,
 * and resume detection. Mirrors the reference design's state pattern.
 */

import { readFile, writeFile, rename, mkdir, stat } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import type { Stage } from './contracts.js';
export type { Stage } from './contracts.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type InvestigationPhase =
  | 'scanning'
  | 'mapping'
  | 'synthesizing'
  | 'planning'
  | 'executing'
  | 'judging'
  | 'resurfacing'
  | 'verifying'
  | 'assessing'
  | 'completed'
  | 'failed';

export interface InvestigationState {
  campaignId: string;
  targetId: string;
  targetProfilePath?: string;
  phase: InvestigationPhase;
  iteration: number;
  maxIterations: number;
  maxCostUsd: number;
  mode: 'declared' | 'blind';
  startedAt: string;
  lastResumedAt?: string;
  completedAt?: string;
  failedAt?: string;
  failureReason?: string;
  /** Cost checkpoints. */
  costUsd: number;
  /** Provider session IDs for resume. */
  sessionIds: Record<string, string>;
  /** Canonical local transcript files for role persistence. */
  roleSessionRefs?: Record<string, string>;
  /** Phase that failed (for resume). */
  failurePhase?: InvestigationPhase;
  /** Consecutive dead-end count (for escape hatch). */
  consecutiveDeadEnds: number;
  /** Memory file path. */
  memoryPath: string;
  /** Last iteration observation bundle. */
  lastResultsPath?: string;
  /** Optional knowledge-base path consulted for this campaign. */
  knowledgeBasePath?: string;
  /** Portfolio identifier, if any. */
  portfolioId?: string;
  /** Current execution stage (SL6 durable stage boundaries). */
  currentStage?: Stage | null;
  /** Last stage that completed successfully. */
  lastCompletedStage?: Stage | null;
}

// ---------------------------------------------------------------------------
// State store (atomic tmp+mv)
// ---------------------------------------------------------------------------

export class StateStore {
  private readonly statePath: string;
  private readonly campaignRoot: string;

  constructor(campaignDir: string, campaignId: string) {
    this.campaignRoot = resolve(campaignDir, campaignId);
    this.statePath = resolve(this.campaignRoot, 'state.json');
  }

  async exists(): Promise<boolean> {
    try {
      await stat(this.statePath);
      return true;
    } catch {
      return false;
    }
  }

  async read(): Promise<InvestigationState> {
    const content = await readFile(this.statePath, 'utf8');
    return JSON.parse(content);
  }

  async write(state: InvestigationState): Promise<void> {
    const dir = dirname(this.statePath);
    await mkdir(dir, { recursive: true });
    const tmp = `${this.statePath}.tmp`;
    await writeFile(tmp, JSON.stringify(state, null, 2), 'utf8');
    await rename(tmp, this.statePath);
  }

  async update(fn: (state: InvestigationState) => void): Promise<InvestigationState> {
    const state = await this.read();
    fn(state);
    await this.write(state);
    return state;
  }

  async setPhase(phase: InvestigationPhase): Promise<void> {
    await this.update((s) => {
      s.phase = phase;
    });
  }

  async setFailed(reason: string, phase: InvestigationPhase): Promise<void> {
    await this.update((s) => {
      s.phase = 'failed';
      s.failedAt = new Date().toISOString();
      s.failureReason = reason;
      s.failurePhase = phase;
    });
  }

  async setCompleted(): Promise<void> {
    await this.update((s) => {
      s.phase = 'completed';
      s.completedAt = new Date().toISOString();
    });
  }

  getCampaignRoot(): string {
    return this.campaignRoot;
  }
}

// ---------------------------------------------------------------------------
// Initialization and resume detection
// ---------------------------------------------------------------------------

export function createInitialState(options: {
  campaignId: string;
  targetId: string;
  maxIterations: number;
  maxCostUsd: number;
  mode: 'declared' | 'blind';
  campaignDir: string;
}): InvestigationState {
  return {
    campaignId: options.campaignId,
    targetId: options.targetId,
    phase: 'scanning',
    iteration: 0,
    maxIterations: options.maxIterations,
    maxCostUsd: options.maxCostUsd,
    mode: options.mode,
    startedAt: new Date().toISOString(),
    costUsd: 0,
    sessionIds: {},
    roleSessionRefs: {},
    consecutiveDeadEnds: 0,
    memoryPath: resolve(options.campaignDir, options.campaignId, 'memory.json'),
    lastResultsPath: resolve(options.campaignDir, options.campaignId, 'last-results.txt'),
    currentStage: null,
    lastCompletedStage: null,
  };
}

export function canResume(state: InvestigationState): boolean {
  return state.phase !== 'completed';
}

export function shouldEscapeDeadEnds(state: InvestigationState, threshold: number = 3): boolean {
  return state.consecutiveDeadEnds >= threshold;
}

export function isBudgetExhausted(state: InvestigationState): boolean {
  return state.costUsd >= state.maxCostUsd;
}

export function isIterationLimitReached(state: InvestigationState): boolean {
  return state.iteration >= state.maxIterations;
}
