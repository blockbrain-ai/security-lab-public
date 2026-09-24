/**
 * Section 5.1 — Behavior equivalence test.
 *
 * This test is the last line of defence before merging the stage extraction.
 * It exercises the extracted Section 5.1 stages against a deterministic
 * fixture stub and asserts that the observable behavior — ordering of
 * friend-method calls, events forwarded to the evidence store, and the
 * mapping from lane status to stage outcome — matches a golden sequence.
 *
 * The Section 5.1 extraction is a *seam* — the real static loop and
 * local-live lane body still live inline in `investigation-runner.ts`
 * and delegate through the typed `RunnerFriend` interface. As a result,
 * the stage modules themselves are small enough that a golden-event
 * comparison over a stub driver is sufficient for merge-gating: if the
 * ordering, count, or type of events diverges from the golden sequence
 * below, the seam has leaked side effects and the extraction is no
 * longer safe.
 *
 * The golden sequence mirrors what a pre-5.1 monolith would have
 * produced when walked through the same stage boundary. It is small
 * by design; Section 5.2 will expand the fixture as the stage modules
 * grow their own bodies.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { StaticInvestigationStage } from './static-investigation.js';
import { VerificationPacketBuilderStage } from './verification-packet-builder.js';
import { LocalLiveStage } from './local-live.js';
import { TestSynthesisStage } from './test-synthesis.js';
import { FocusedClosureStage } from './focused-closure.js';
import { AssessmentReportingStage } from './assessment-reporting.js';
import type {
  ExperimentStoreHandle,
  StageContext,
  StageRunnerHost,
  VerificationPacketSummary,
} from './contracts.js';
import type { VerificationLaneSummary } from '../investigation-runner.js';

type RecordedEvent =
  | { kind: 'friend_call'; method: string }
  | { kind: 'evidence_event'; stage: string; hypothesisId?: string }
  | { kind: 'stage_result'; stage: string; outcome: string };

/**
 * Stub evidence store that records every `appendEvent` call so the test
 * can assert on the ordered event stream. Only the methods touched by
 * the Section 5.1 stage seam surface are implemented; anything else the
 * stages touch will throw and force the test author to extend this
 * stub, which is the correct failure mode for a behavior-equivalence
 * gate.
 */
function recordingEvidenceStore(log: RecordedEvent[]): {
  appendEvent: (stage: string, payload: Record<string, unknown>) => Promise<void>;
} {
  return {
    appendEvent: async (stage, payload) => {
      const hypothesisId =
        typeof payload['hypothesisId'] === 'string' ? payload['hypothesisId'] : undefined;
      log.push({ kind: 'evidence_event', stage, hypothesisId });
    },
  };
}

function recordingHost(log: RecordedEvent[]): StageRunnerHost {
  const lane = (): VerificationLaneSummary => ({
    attempted: 0,
    meaningfulAttempts: 0,
    confirmed: 0,
    refuted: 0,
    inconclusive: 0,
    blocked: 0,
    skipped: 0,
    authFailed: 0,
    notApplicable: 0,
    notAuthorized: 0,
    rateLimited: 0,
    autoStopped: 0,
    timeout: 0,
    runtimeError: 0,
    compileError: 0,
    dryRunSimulated: 0,
    coverageGapCount: 0,
    costUsd: 0,
    durationMs: 0,
    status: 'complete',
    required: false,
    coverageGaps: [],
  });
  const packets: VerificationPacketSummary[] = [
    { id: 'packet-1', hypothesisId: 'h1', signalDescriptions: [], relatedAssets: [] },
    { id: 'packet-2', hypothesisId: 'h2', signalDescriptions: [], relatedAssets: [] },
  ];
  return {
    buildVerificationPacketsFriend: () => {
      log.push({ kind: 'friend_call', method: 'buildVerificationPackets' });
      return packets;
    },
    runLocalLiveLaneFriend: async () => {
      log.push({ kind: 'friend_call', method: 'runLocalLiveLane' });
      return lane();
    },
    runTestSynthesisLaneFriend: async () => {
      log.push({ kind: 'friend_call', method: 'runTestSynthesisLane' });
      return lane();
    },
  };
}

function makeContext(host: StageRunnerHost, log: RecordedEvent[]): StageContext {
  return {
    target: {},
    memory: {},
    state: {},
    stateStore: {},
    evidenceStore: recordingEvidenceStore(log),
    campaignDir: '/tmp',
    telemetry: {},
    roleSessions: {},
    archiver: null,
    runner: host,
    adapters: { reporter: undefined, synthesizer: undefined },
  } as unknown as StageContext;
}

describe('stage pipeline behavior equivalence (Section 5.1)', () => {
  const experimentStore: ExperimentStoreHandle = { record: async () => {} };

  it('exposes the four Section 5.1 stages in canonical order', () => {
    const stages = [
      new StaticInvestigationStage(),
      new VerificationPacketBuilderStage(),
      new LocalLiveStage(experimentStore),
      new TestSynthesisStage(experimentStore),
    ];
    assert.deepEqual(
      stages.map((s) => s.name),
      ['static', 'verification_packet_build', 'local_live', 'test_synthesis'],
    );
  });

  it('exposes all six extracted stages in canonical order (Section 5.2)', () => {
    const stages = [
      new StaticInvestigationStage(),
      new VerificationPacketBuilderStage(),
      new LocalLiveStage(experimentStore),
      new TestSynthesisStage(experimentStore),
      new FocusedClosureStage(),
      new AssessmentReportingStage(),
    ];
    assert.deepEqual(
      stages.map((s) => s.name),
      [
        'static',
        'verification_packet_build',
        'local_live',
        'test_synthesis',
        'focused_closure',
        'assessment',
      ],
    );
  });

  it('FocusedClosureStage actively applies the citation rule at the 5.2 seam', async () => {
    const log: RecordedEvent[] = [];
    const context = makeContext(recordingHost(log), log);

    const focusedResult = await new FocusedClosureStage().run(context);
    assert.equal(focusedResult.stage, 'focused_closure');
    assert.equal(focusedResult.outcome, 'complete');
    // The stage emits exactly one citation-audit event per run.
    assert.equal(focusedResult.events.length, 1);
    assert.equal(focusedResult.events[0]?.name, 'focused_closure_citation_audit');
    assert.deepEqual(focusedResult.coverageGaps, []);
    // The runner-side audit event should have been forwarded through
    // the stub evidence store exactly once.
    const citationEvents = log.filter(
      (e): e is Extract<RecordedEvent, { kind: 'evidence_event' }> =>
        e.kind === 'evidence_event' && e.stage === 'focused_closure_citation_audit',
    );
    assert.equal(citationEvents.length, 1);
  });

  it('AssessmentReportingStage emits the assessment_stage_seam event at the 5.2 seam', async () => {
    const log: RecordedEvent[] = [];
    const context = makeContext(recordingHost(log), log);

    const assessmentResult = await new AssessmentReportingStage().run(context);
    assert.equal(assessmentResult.stage, 'assessment');
    assert.equal(assessmentResult.outcome, 'complete');
    assert.equal(assessmentResult.events.length, 1);
    assert.equal(assessmentResult.events[0]?.name, 'assessment_stage_seam');
    assert.deepEqual(assessmentResult.coverageGaps, []);
    const seamEvents = log.filter(
      (e): e is Extract<RecordedEvent, { kind: 'evidence_event' }> =>
        e.kind === 'evidence_event' && e.stage === 'assessment_stage_seam',
    );
    assert.equal(seamEvents.length, 1);
  });

  it('produces the golden event sequence when all four stages run against the stub host', async () => {
    const log: RecordedEvent[] = [];
    const host = recordingHost(log);
    const context = makeContext(host, log);

    const staticResult = await new StaticInvestigationStage().run(context);
    log.push({ kind: 'stage_result', stage: staticResult.stage, outcome: staticResult.outcome });

    const packetResult = await new VerificationPacketBuilderStage().run(context);
    log.push({ kind: 'stage_result', stage: packetResult.stage, outcome: packetResult.outcome });

    const localLiveResult = await new LocalLiveStage(experimentStore).run(context);
    log.push({ kind: 'stage_result', stage: localLiveResult.stage, outcome: localLiveResult.outcome });

    const testSynthResult = await new TestSynthesisStage(experimentStore).run(context);
    log.push({ kind: 'stage_result', stage: testSynthResult.stage, outcome: testSynthResult.outcome });

    // The golden sequence. If this ever changes, it means the stage
    // seam has leaked a new side effect into the run — which is the
    // exact class of regression this test exists to catch.
    const golden: RecordedEvent[] = [
      // StaticInvestigationStage.run() is a seam for 5.1 — no friend
      // calls, no events. Its body still lives inline in the runner.
      { kind: 'stage_result', stage: 'static', outcome: 'complete' },
      // VerificationPacketBuilderStage calls `buildVerificationPackets`
      // exactly once and returns a deterministic outcome based on the
      // packet count from the host.
      { kind: 'friend_call', method: 'buildVerificationPackets' },
      { kind: 'stage_result', stage: 'verification_packet_build', outcome: 'complete' },
      // LocalLiveStage delegates to `runLocalLiveLane` exactly once.
      { kind: 'friend_call', method: 'runLocalLiveLane' },
      { kind: 'stage_result', stage: 'local_live', outcome: 'complete' },
      // TestSynthesisStage delegates to `runTestSynthesisLane` exactly once.
      { kind: 'friend_call', method: 'runTestSynthesisLane' },
      { kind: 'stage_result', stage: 'test_synthesis', outcome: 'complete' },
    ];
    assert.deepEqual(log, golden);
  });

  it('stage outcome enum is strictly a subset of ExecutionStatus (no new values)', async () => {
    const log: RecordedEvent[] = [];
    const context = makeContext(recordingHost(log), log);
    const results = [
      await new StaticInvestigationStage().run(context),
      await new VerificationPacketBuilderStage().run(context),
      await new LocalLiveStage(experimentStore).run(context),
      await new TestSynthesisStage(experimentStore).run(context),
    ];
    const allowed = new Set(['complete', 'degraded', 'incomplete', 'blocked']);
    for (const result of results) {
      assert.ok(allowed.has(result.outcome), `unexpected outcome ${result.outcome}`);
    }
  });

  it('invokes each delegated friend method exactly once per stage run', async () => {
    const log: RecordedEvent[] = [];
    const host = recordingHost(log);
    const context = makeContext(host, log);

    await new StaticInvestigationStage().run(context);
    await new VerificationPacketBuilderStage().run(context);
    await new LocalLiveStage(experimentStore).run(context);
    await new TestSynthesisStage(experimentStore).run(context);

    const friendCalls = log
      .filter((e): e is Extract<RecordedEvent, { kind: 'friend_call' }> => e.kind === 'friend_call')
      .map((e) => e.method);
    assert.deepEqual(friendCalls, [
      'buildVerificationPackets',
      'runLocalLiveLane',
      'runTestSynthesisLane',
    ]);
  });
});
