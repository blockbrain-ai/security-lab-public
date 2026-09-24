/**
 * Section 5.1 — VerificationPacketBuilderStage tests.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  VerificationPacketBuilderStage,
  indexPacketsById,
} from './verification-packet-builder.js';
import type {
  StageContext,
  StageRunnerHost,
  VerificationPacketSummary,
} from './contracts.js';
import type { CampaignMemory } from '../contracts.js';
import type { InvestigationTarget } from '../target-profile.js';

function makeStubHost(packets: VerificationPacketSummary[]): StageRunnerHost {
  return {
    buildVerificationPacketsFriend: () => packets,
    runLocalLiveLaneFriend: async () => {
      throw new Error('not used');
    },
    runTestSynthesisLaneFriend: async () => {
      throw new Error('not used');
    },
  };
}

function makeContext(host: StageRunnerHost): StageContext {
  return {
    memory: { hypotheses: [], signals: [] } as unknown as CampaignMemory,
    target: { id: 'stub' } as unknown as InvestigationTarget,
    runner: host,
  } as unknown as StageContext;
}

describe('VerificationPacketBuilderStage', () => {
  it('has the canonical stage name', () => {
    const stage = new VerificationPacketBuilderStage();
    assert.equal(stage.name, 'verification_packet_build');
  });

  it('returns a complete outcome when packets exist', async () => {
    const packets: VerificationPacketSummary[] = [
      { id: 'packet-1', hypothesisId: 'h1', signalDescriptions: [], relatedAssets: [] },
      { id: 'packet-2', hypothesisId: 'h2', signalDescriptions: [], relatedAssets: [] },
    ];
    const stage = new VerificationPacketBuilderStage();
    const result = await stage.run(makeContext(makeStubHost(packets)));
    assert.equal(result.outcome, 'complete');
    assert.equal(result.metadata.packetCount, 2);
    assert.deepEqual(result.metadata.packetIds, ['packet-1', 'packet-2']);
  });

  it('returns a degraded outcome when there are no packets', async () => {
    const stage = new VerificationPacketBuilderStage();
    const result = await stage.run(makeContext(makeStubHost([])));
    assert.equal(result.outcome, 'degraded');
    assert.equal(result.metadata.packetCount, 0);
  });

  it('delegates packet building to the runner host', async () => {
    let called = 0;
    const host: StageRunnerHost = {
      buildVerificationPacketsFriend: () => {
        called += 1;
        return [];
      },
      runLocalLiveLaneFriend: async () => {
        throw new Error('not used');
      },
      runTestSynthesisLaneFriend: async () => {
        throw new Error('not used');
      },
    };
    const stage = new VerificationPacketBuilderStage();
    await stage.run(makeContext(host));
    assert.equal(called, 1);
  });
});

describe('indexPacketsById', () => {
  it('deduplicates packets by id preserving first occurrence', () => {
    const packets: VerificationPacketSummary[] = [
      { id: 'a', hypothesisId: 'h1', signalDescriptions: ['first'], relatedAssets: [] },
      { id: 'b', hypothesisId: 'h2', signalDescriptions: [], relatedAssets: [] },
      { id: 'a', hypothesisId: 'h1-dup', signalDescriptions: ['second'], relatedAssets: [] },
    ];
    const indexed = indexPacketsById(packets);
    assert.equal(indexed.size, 2);
    assert.deepEqual(indexed.get('a')?.signalDescriptions, ['first']);
  });
});
