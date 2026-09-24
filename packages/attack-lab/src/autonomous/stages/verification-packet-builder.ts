/**
 * Section 5.1 — VerificationPacketBuilderStage.
 *
 * Wraps the runner's `buildVerificationPackets` call in a `Stage` shape. The
 * actual packet-building logic is still owned by the runner during Section
 * 5.1 (so the behavior-equivalence test can confirm zero divergence); this
 * module provides the stage seam and a pure helper that the stage delegates
 * to via the runner host.
 *
 * The stage is named `verification_packet_build` (SL6, Section 1.1).
 */

import type { Stage, StageContext, StageResult, VerificationPacketSummary } from './contracts.js';

export class VerificationPacketBuilderStage implements Stage {
  readonly name = 'verification_packet_build' as const;

  async run(context: StageContext): Promise<StageResult> {
    const packets = context.runner.buildVerificationPacketsFriend(context.memory, context.target);
    return {
      stage: 'verification_packet_build',
      outcome: packets.length > 0 ? 'complete' : 'degraded',
      events: [],
      coverageGaps: [],
      metadata: {
        packetCount: packets.length,
        packetIds: packets.map((p) => p.id),
      },
    };
  }
}

/**
 * Pure utility: convert a verification packet list into a deduplicated
 * packet-id-keyed Map. Tests exercise this directly to confirm the
 * stage never drops packets when passed through its metadata.
 */
export function indexPacketsById(
  packets: VerificationPacketSummary[],
): Map<string, VerificationPacketSummary> {
  const byId = new Map<string, VerificationPacketSummary>();
  for (const packet of packets) {
    if (!byId.has(packet.id)) {
      byId.set(packet.id, packet);
    }
  }
  return byId;
}
