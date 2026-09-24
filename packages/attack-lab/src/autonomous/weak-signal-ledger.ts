/**
 * Weak-signal ledger — records, tracks, and manages minor anomalies
 * that are not full findings on their own but may compose into chains.
 */

import type { WeakSignal, SignalStatus, CampaignMemory } from './contracts.js';

// ---------------------------------------------------------------------------
// Signal management
// ---------------------------------------------------------------------------

export function addSignal(
  memory: CampaignMemory,
  signal: Omit<WeakSignal, 'id' | 'discoveredAt' | 'iteration' | 'status' | 'correlatedWith' | 'unresolvedCorrelations'>,
): WeakSignal {
  const id = `ws-${memory.iteration}-${memory.signals.length + 1}`;

  // Check for duplicates
  const isDuplicate = memory.signals.some(
    (s) =>
      s.description === signal.description &&
      s.surface === signal.surface &&
      s.status !== 'dismissed',
  );

  if (isDuplicate) {
    const existing = memory.signals.find(
      (s) => s.description === signal.description && s.surface === signal.surface,
    )!;
    // Boost confidence of existing signal
    existing.confidence = Math.min(1, existing.confidence + 0.1);
    return existing;
  }

  const newSignal: WeakSignal = {
    ...signal,
    id,
    discoveredAt: new Date().toISOString(),
    iteration: memory.iteration,
    status: 'active',
    correlatedWith: [],
    unresolvedCorrelations: [],
  };

  memory.signals.push(newSignal);
  return newSignal;
}

export function markDormant(memory: CampaignMemory, signalId: string): void {
  const signal = memory.signals.find((s) => s.id === signalId);
  if (signal && signal.status === 'active') {
    signal.status = 'dormant';
    signal.dormantSince = new Date().toISOString();
    if (!memory.dormantSignalIds.includes(signalId)) {
      memory.dormantSignalIds.push(signalId);
    }
  }
}

export function reactivateSignal(
  memory: CampaignMemory,
  signalId: string,
  reason: string,
): void {
  const signal = memory.signals.find((s) => s.id === signalId);
  if (signal && (signal.status === 'dormant' || signal.status === 'dismissed')) {
    signal.status = 'reopened';
    signal.reactivationReason = reason;
    signal.dormantSince = undefined;
    memory.dormantSignalIds = memory.dormantSignalIds.filter((id) => id !== signalId);
  }
}

export function promoteSignal(memory: CampaignMemory, signalId: string): void {
  const signal = memory.signals.find((s) => s.id === signalId);
  if (signal) {
    signal.status = 'promoted';
  }
}

export function dismissSignal(memory: CampaignMemory, signalId: string): void {
  const signal = memory.signals.find((s) => s.id === signalId);
  if (signal) {
    signal.status = 'dismissed';
  }
}

export function addCorrelation(
  memory: CampaignMemory,
  signalIdA: string,
  signalIdB: string,
  resolved: boolean,
): void {
  const a = memory.signals.find((s) => s.id === signalIdA);
  const b = memory.signals.find((s) => s.id === signalIdB);
  if (!a || !b) return;

  if (resolved) {
    if (!a.correlatedWith.includes(signalIdB)) a.correlatedWith.push(signalIdB);
    if (!b.correlatedWith.includes(signalIdA)) b.correlatedWith.push(signalIdA);
    a.unresolvedCorrelations = a.unresolvedCorrelations.filter((id) => id !== signalIdB);
    b.unresolvedCorrelations = b.unresolvedCorrelations.filter((id) => id !== signalIdA);
  } else {
    if (!a.unresolvedCorrelations.includes(signalIdB)) a.unresolvedCorrelations.push(signalIdB);
    if (!b.unresolvedCorrelations.includes(signalIdA)) b.unresolvedCorrelations.push(signalIdA);
  }
}

// ---------------------------------------------------------------------------
// Querying
// ---------------------------------------------------------------------------

export function getActiveSignals(memory: CampaignMemory): WeakSignal[] {
  return memory.signals.filter((s) => s.status === 'active' || s.status === 'reopened');
}

export function getDormantSignals(memory: CampaignMemory): WeakSignal[] {
  return memory.signals.filter((s) => s.status === 'dormant');
}

export function getSignalsWithUnresolvedCorrelations(memory: CampaignMemory): WeakSignal[] {
  return memory.signals.filter(
    (s) => s.unresolvedCorrelations.length > 0 && s.status !== 'dismissed',
  );
}

export function getSignalsByStatus(memory: CampaignMemory, status: SignalStatus): WeakSignal[] {
  return memory.signals.filter((s) => s.status === status);
}

export function getSignalsBySurface(memory: CampaignMemory, surface: string): WeakSignal[] {
  return memory.signals.filter((s) => s.surface === surface && s.status !== 'dismissed');
}

// ---------------------------------------------------------------------------
// Resurfacing — periodically re-examine dormant signals
// ---------------------------------------------------------------------------

const RESURFACING_INTERVAL = 5; // every N iterations

export function shouldResurface(memory: CampaignMemory): boolean {
  return (
    memory.dormantSignalIds.length > 0 &&
    memory.iteration - memory.lastResurfacingIteration >= RESURFACING_INTERVAL
  );
}

/**
 * Returns dormant signals that should be reconsidered given new context.
 * New context = signals discovered since they went dormant.
 */
export function getCandidatesForResurfacing(memory: CampaignMemory): WeakSignal[] {
  const dormant = getDormantSignals(memory);
  const active = getActiveSignals(memory);

  return dormant.filter((d) => {
    // A dormant signal is worth resurfacing if any active signal
    // shares an asset, surface, or has an unresolved correlation with it
    return active.some(
      (a) =>
        d.unresolvedCorrelations.includes(a.id) ||
        a.unresolvedCorrelations.includes(d.id) ||
        d.relatedAssets.some((asset) => a.relatedAssets.includes(asset)) ||
        d.surface === a.surface,
    );
  });
}

export function markResurfacingDone(memory: CampaignMemory): void {
  memory.lastResurfacingIteration = memory.iteration;
}
