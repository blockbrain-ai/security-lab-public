/**
 * Campaign memory — serialization, deserialization, and snapshot
 * management for long-running investigation campaigns.
 */

import { readFile, writeFile, rename, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { CampaignMemory } from './contracts.js';
import {
  serializeInventory,
  deserializeInventory,
} from '../verification/probe-intelligence/entity-inventory.js';

// ---------------------------------------------------------------------------
// Persistence (atomic tmp+mv, mirrors the reference design's write helper)
// ---------------------------------------------------------------------------

export async function saveMemory(memory: CampaignMemory, filePath: string): Promise<void> {
  const dir = dirname(filePath);
  await mkdir(dir, { recursive: true });

  const serializable = {
    ...memory,
    // Set → Array for JSON serialization
    probeFingerprints: [...memory.probeFingerprints],
    // Section 11.1 — serialize entity inventory
    entityInventory: memory.entityInventory
      ? serializeInventory(memory.entityInventory)
      : undefined,
  };

  const tmp = `${filePath}.tmp`;
  await writeFile(tmp, JSON.stringify(serializable, null, 2), 'utf8');
  await rename(tmp, filePath);
}

export async function loadMemory(filePath: string): Promise<CampaignMemory | null> {
  try {
    const content = await readFile(filePath, 'utf8');
    const raw = JSON.parse(content);

    return {
      ...raw,
      // Array → Set for runtime use
      probeFingerprints: new Set(raw.probeFingerprints ?? []),
      // Section 11.1 — deserialize entity inventory
      entityInventory: raw.entityInventory
        ? deserializeInventory(raw.entityInventory)
        : undefined,
    };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Snapshot for model context (bounded size)
// ---------------------------------------------------------------------------

export function memorySnapshot(memory: CampaignMemory, maxTokens: number = 50_000): string {
  const lines: string[] = [
    `# Campaign Memory: ${memory.campaignId}`,
    `Iteration: ${memory.iteration}`,
    `Signals: ${memory.signals.length} (${memory.signals.filter((s) => s.status === 'active').length} active, ${memory.dormantSignalIds.length} dormant)`,
    `Hypotheses: ${memory.hypotheses.length} (${memory.hypotheses.filter((h) => h.status === 'confirmed').length} confirmed)`,
    `Findings: ${memory.findings.length}`,
    `Cost: $${memory.totalCostUsd.toFixed(4)}`,
    `Probes: ${memory.totalProbes}`,
    `Duplicates suppressed: ${memory.duplicateProbesSuppressed}`,
    '',
  ];

  // Active signals
  const active = memory.signals.filter((s) => s.status === 'active' || s.status === 'reopened');
  if (active.length > 0) {
    lines.push('## Active Signals');
    for (const s of active.slice(0, 20)) {
      lines.push(`- [${s.id}] (${s.surface}, conf=${s.confidence.toFixed(2)}) ${s.description}`);
      if (s.unresolvedCorrelations.length > 0) {
        lines.push(`  unresolved correlations: ${s.unresolvedCorrelations.join(', ')}`);
      }
    }
    lines.push('');
  }

  // Dormant signals
  const dormant = memory.signals.filter((s) => s.status === 'dormant');
  if (dormant.length > 0) {
    lines.push('## Dormant Signals (may be worth resurfacing)');
    for (const s of dormant.slice(0, 10)) {
      lines.push(`- [${s.id}] (${s.surface}) ${s.description} [dormant since ${s.dormantSince}]`);
    }
    lines.push('');
  }

  // Active hypotheses
  const testing = memory.hypotheses.filter((h) => h.status === 'proposed' || h.status === 'testing');
  if (testing.length > 0) {
    lines.push('## Active Hypotheses');
    for (const h of testing.slice(0, 10)) {
      lines.push(`- [${h.id}] (${h.severity}) ${h.description}`);
      lines.push(`  signals: ${h.signalIds.join(', ')}`);
      lines.push(`  attempts: ${h.attempts.length}`);
    }
    lines.push('');
  }

  // Confirmed findings
  if (memory.findings.length > 0) {
    lines.push('## Confirmed Findings');
    for (const f of memory.findings) {
      lines.push(`- (${f.severity}) ${f.description}`);
      if (f.involvedDormantReactivation) {
        lines.push('  [involved dormant signal reactivation]');
      }
    }
    lines.push('');
  }

  // Refuted hypotheses (brief)
  const refuted = memory.hypotheses.filter((h) => h.status === 'refuted');
  if (refuted.length > 0) {
    lines.push('## Refuted Hypotheses (do not retry)');
    for (const h of refuted.slice(0, 10)) {
      lines.push(`- [${h.id}] ${h.description.split('\n')[0]}`);
    }
    lines.push('');
  }

  let result = lines.join('\n');

  // Truncate if too long (rough char-to-token ratio of 4:1)
  if (result.length > maxTokens * 4) {
    result = result.substring(0, maxTokens * 4) + '\n\n[...truncated]';
  }

  return result;
}
