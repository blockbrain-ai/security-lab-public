/**
 * Section 5.1 — TestSynthesisStage.
 *
 * Wraps the runner's `runTestSynthesisLane()` as a `Stage`. In Section 5.1
 * the stage delegates to the runner-owned lane implementation through the
 * `StageRunnerHost` friend interface so behavior is bit-identical with the
 * pre-5.1 monolith. Section 5.2 will move the lane body into this module
 * including the Section 3.1 compile-retry loop.
 *
 * The stage is named `test_synthesis` (SL6, Section 1.1).
 */

import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import type { ExperimentStoreHandle, RunnerFriend, Stage, StageContext, StageResult } from './contracts.js';
import { mapLaneStatus } from './local-live.js';
import type { VerificationLanesSummary, VerificationLaneSummary } from '../investigation-runner.js';
import {
  addLaneCoverageGap,
  countLaneVerdict,
  createLaneSummary,
  usableAdapter,
} from '../investigation-runner.js';
import {
  interpretResult,
  retrySystemPromptForAttempt,
  runSynthesizedTest,
  synthesizeTest,
  type SynthesizedTest,
  type TestExecutionResult,
} from '../../verification/test-synthesis/index.js';
import type { VerificationExperiment } from '../../verification/shared/index.js';
import type { LocalLiveLaneArgs } from './contracts.js';

/**
 * Section 5.1 — runTestSynthesisLaneImpl.
 *
 * The body of this function is the previously-inline
 * `InvestigationRunner.runTestSynthesisLane()` method. It was moved here as
 * part of the Section 5.1 extraction so the stage module owns the lane
 * implementation. Behavior is bit-identical to the pre-5.1 monolith; all
 * runner internals are accessed via the `RunnerFriend` typed friend
 * interface (see `contracts.ts`) — the pre-revision `unknown` cast has
 * been removed.
 */
export async function runTestSynthesisLaneImpl(
  runner: RunnerFriend,
  args: LocalLiveLaneArgs,
  experimentStore: { record: (experiment: VerificationExperiment) => Promise<void> },
): Promise<NonNullable<VerificationLanesSummary['testSynthesis']>> {
  const startedAt = Date.now();
  const summary: VerificationLaneSummary = createLaneSummary(runner.laneRequiredFriend(args.target, 'test-synthesis'));
  if (!args.target.repoRoot) {
    addLaneCoverageGap(summary, 'Target has no repoRoot for test synthesis.', summary.required ? 'incomplete' : 'degraded');
    summary.durationMs = Date.now() - startedAt;
    await args.evidenceStore.appendEvent('verification_test_synthesis_skipped', {
      reason: 'target has no repoRoot',
      required: summary.required,
    });
    return summary;
  }

  for (const gap of await runner.preflightTargetCoverageFriend(args.target, 'test-synthesis')) {
    addLaneCoverageGap(summary, gap.message, gap.severity);
  }
  if (summary.status === 'incomplete' && summary.required && !runner.allowDegradedFriend) {
    summary.durationMs = Date.now() - startedAt;
    await args.evidenceStore.appendEvent('verification_test_synthesis_incomplete', {
      coverageGaps: summary.coverageGaps,
    });
    return summary;
  }

  const requests = await runner.buildTestSynthesisRequestsFriend(args.target.repoRoot, args.memory);
  if (requests.length === 0) {
    summary.skipped += 1;
    summary.durationMs = Date.now() - startedAt;
    return summary;
  }

  const synthesizerAdapter = usableAdapter(runner.synthesizerAdapterFriend)
    ?? usableAdapter(runner.plannerAdapterFriend);
  const counterReviewer = usableAdapter(runner.counterPlannerAdapterFriend);
  if (!synthesizerAdapter) {
    addLaneCoverageGap(
      summary,
      'No usable model adapter is available for test synthesis. Configure provider credentials or rerun this lane with a model-backed synthesizer.',
      summary.required ? 'incomplete' : 'degraded',
    );
    summary.durationMs = Date.now() - startedAt;
    await args.evidenceStore.appendEvent('verification_test_synthesis_incomplete', {
      coverageGaps: summary.coverageGaps,
      reason: 'missing_synthesizer_adapter',
    });
    return summary;
  }
  if (runner.counterPlannerAdapterFriend && !counterReviewer) {
    addLaneCoverageGap(
      summary,
      'Counter-review model is unavailable; synthesized tests will run without cross-model soundness review.',
      'degraded',
    );
  }

  const modelTimeoutMs = runner.resolveModelRequestTimeoutMsFriend(args.target, 'test-synthesis');
  const worktreeDir = resolve(args.campaignDir, 'test-synthesis');
  const fallbackSynthesizer = counterReviewer && counterReviewer !== synthesizerAdapter
    ? counterReviewer
    : undefined;
  for (const request of (requests as unknown as Array<Parameters<typeof synthesizeTest>[0]>).slice(0, runner.resolveTestSynthesisLimitFriend(args.target))) {
    await args.evidenceStore.appendEvent('verification_test_synthesis_started', {
      findingId: request.findingId,
      suspectFile: request.suspectFile,
      modelTimeoutMs,
      executionTimeoutMs: runner.resolveTestTimeoutMsFriend(args.target),
    });

    try {
      // Section 3.1: retry synthesis up to 3 times with simpler system prompts on compile error.
      const maxAttempts = 3;
      let synthesized!: SynthesizedTest;
      let result!: TestExecutionResult;
      let activeSynthesizer = synthesizerAdapter;
      let activeCounterReviewer = counterReviewer;
      let usedFallbackSynthesizer = false;
      const retryHistory: Array<{ attempt: number; testId: string; compileError?: string }> = [];
      for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        const priorErrors = retryHistory
          .map((a) => a.compileError)
          .filter((e): e is string => Boolean(e))
          .join('\n---\n');
        const userPromptSuffix = priorErrors
          ? `## Previous Compile Errors (attempt ${attempt - 1})\n\`\`\`\n${priorErrors}\n\`\`\`\n\nGenerate a SIMPLER test that avoids these errors.`
          : undefined;
        try {
          synthesized = await synthesizeTest(request, {
            repoRoot: args.target.repoRoot,
            synthesizer: activeSynthesizer,
            // Counter-review must always run on the happy path — the retry
            // loop is a degradation path layered on top, not a licence to
            // skip the cross-model soundness check. When retries are needed
            // we accept the extra cost on compile-failing attempts.
            counterReviewer: activeCounterReviewer,
            invokeOptions: {
              requestTimeoutMs: modelTimeoutMs,
            },
            counterInvokeOptions: {
              requestTimeoutMs: modelTimeoutMs,
            },
            systemPromptOverride: attempt === 1 ? undefined : retrySystemPromptForAttempt(attempt),
            userPromptSuffix,
          });
        } catch (error) {
          const reason = error instanceof Error ? error.message : String(error);
          const timeoutLike = /\bETIMEDOUT\b|timed out|timeout/i.test(reason);
          if (!usedFallbackSynthesizer && fallbackSynthesizer && timeoutLike) {
            usedFallbackSynthesizer = true;
            activeSynthesizer = fallbackSynthesizer;
            activeCounterReviewer = activeSynthesizer === counterReviewer ? undefined : counterReviewer;
            await args.evidenceStore.appendEvent('verification_test_synthesis_fallback_synthesizer', {
              findingId: request.findingId,
              suspectFile: request.suspectFile,
              originalProvider: synthesizerAdapter.provider,
              originalModel: synthesizerAdapter.model,
              fallbackProvider: fallbackSynthesizer.provider,
              fallbackModel: fallbackSynthesizer.model,
              reason,
              attempt,
            });
            attempt -= 1;
            continue;
          }
          throw error;
        }
        result = await runSynthesizedTest(synthesized, {
          repoRoot: args.target.repoRoot,
          campaignId: args.memory.campaignId,
          baseWorktreeDir: worktreeDir,
          timeoutMs: runner.resolveTestTimeoutMsFriend(args.target),
        });
        retryHistory.push({
          attempt,
          testId: synthesized.testId,
          compileError: result.compiled ? undefined : result.compileErrors,
        });
        await args.evidenceStore.appendEvent('verification_test_synthesis_attempt', {
          findingId: request.findingId,
          attempt,
          testId: synthesized.testId,
          compiled: result.compiled,
          compileErrors: result.compiled ? null : (result.compileErrors ?? null),
        });
        if (result.compiled) break;
      }
      const exhaustedRetries = !result.compiled;
      if (exhaustedRetries) {
        const gapPayload = {
          code: 'test_synthesis_compile_retry_exhausted',
          reason: 'test_synthesis_compile_retry_exhausted',
          stage: 'test_synthesis',
          findingId: request.findingId,
          suspectFile: request.suspectFile,
          attempts: retryHistory,
        };
        await args.evidenceStore.appendEvent('coverage_gap', gapPayload);
        runner.recordProbeCoverageGapFriend(gapPayload);
      }
      if (synthesized.synthesizerInvocation) {
        const synthesisSessionKey = runner.getRoleSessionKeyFriend('anthropic_synthesizer', synthesizerAdapter, request.findingId);
        runner.recordModelInvocationFriend(
          args.telemetry,
          args.state,
          args.memory,
          'synthesizer',
          synthesized.synthesizerInvocation.response,
          synthesisSessionKey,
        );
        summary.costUsd += synthesized.synthesizerInvocation.response.usage.costUsd;
        await runner.checkpointVolatileStateFriend(args.stateStore, args.state);
        if (args.archiver) {
          await args.archiver.archive(
            'synthesizer',
            synthesized.synthesizerInvocation.systemPrompt,
            synthesized.synthesizerInvocation.prompt,
            synthesized.synthesizerInvocation.response,
            synthesized.synthesizerInvocation.parseSuccess,
          );
        }
        await runner.appendRoleEntryFriend(
          (entry: unknown) => args.roleSessions.appendSynthesizerEntry(request.findingId, entry as never),
          {
            role: 'test_synthesizer',
            iteration: args.state.iteration + 1,
            provider: synthesized.synthesizerInvocation.response.provider,
            model: synthesized.synthesizerInvocation.response.model,
            summary: `Synthesized verification test for ${request.suspectFile}`,
            evidenceRefs: [request.findingId, request.suspectFile],
            response: synthesized.synthesizerInvocation.response,
          },
        );
      }
      if (synthesized.counterReviewInvocation && counterReviewer) {
        const counterSessionKey = runner.getRoleSessionKeyFriend('counter_planner', counterReviewer, request.findingId);
        runner.recordModelInvocationFriend(
          args.telemetry,
          args.state,
          args.memory,
          'counter_plan',
          synthesized.counterReviewInvocation.response,
          counterSessionKey,
        );
        summary.costUsd += synthesized.counterReviewInvocation.response.usage.costUsd;
        await runner.checkpointVolatileStateFriend(args.stateStore, args.state);
        if (args.archiver) {
          await args.archiver.archive(
            'counter_planner',
            synthesized.counterReviewInvocation.systemPrompt,
            synthesized.counterReviewInvocation.prompt,
            synthesized.counterReviewInvocation.response,
            synthesized.counterReviewInvocation.parseSuccess,
          );
        }
        await runner.appendRoleEntryFriend(
          (entry: unknown) => args.roleSessions.appendCounterPlannerEntry(entry as never),
          {
            role: 'test_counter_review',
            iteration: args.state.iteration + 1,
            provider: synthesized.counterReviewInvocation.response.provider,
            model: synthesized.counterReviewInvocation.response.model,
            summary: synthesized.counterReviewNotes?.slice(0, 400) ?? `Reviewed synthesized test for ${request.suspectFile}`,
            evidenceRefs: [request.findingId, request.suspectFile],
            response: synthesized.counterReviewInvocation.response,
          },
        );
      }

      const interpreted = interpretResult(result, request);
      summary.attempted += 1;
      countLaneVerdict(summary, interpreted.verdict);

      const experimentId = createHash('sha256')
        .update(`${request.findingId}:${synthesized.testId}:${Date.now()}`)
        .digest('hex')
        .slice(0, 16);
      await experimentStore.record({
        experimentId: `exp-test_synthesis-${experimentId}`,
        findingId: request.findingId,
        route: 'test_synthesis',
        at: new Date().toISOString(),
        hypothesis: request.hypothesis,
        prerequisites: [request.suspectFile],
        intervention: `Synthesized ${request.testFramework} test for ${request.suspectFile}`,
        expectedSafeOutcome: `Test blocks or rejects "${request.hostileInputPattern}"`,
        expectedExploitableOutcome: request.dangerousBehaviour,
        actualObservation: interpreted.reasoning,
        verdict: interpreted.verdict,
        confidence: interpreted.confidence,
        evidenceRefs: [synthesized.testId],
        notes: synthesized.counterReviewNotes,
      });
      await args.evidenceStore.appendEvent('verification_test_synthesis_executed', {
        findingId: request.findingId,
        suspectFile: request.suspectFile,
        testId: synthesized.testId,
        verdict: interpreted.verdict,
      });
    } catch (error) {
      summary.attempted += 1;
      summary.inconclusive += 1;
      const reason = error instanceof Error ? error.message : String(error);
      if (/\bETIMEDOUT\b|timed out|timeout/i.test(reason)) {
        summary.timeout += 1;
      } else {
        summary.runtimeError += 1;
      }
      await experimentStore.record({
        experimentId: `exp-test_synthesis-${createHash('sha256').update(`${request.findingId}:${Date.now()}`).digest('hex').slice(0, 16)}`,
        findingId: request.findingId,
        route: 'test_synthesis',
        at: new Date().toISOString(),
        hypothesis: request.hypothesis,
        prerequisites: [request.suspectFile],
        intervention: `Synthesize ${request.testFramework} test for ${request.suspectFile}`,
        expectedSafeOutcome: `Test blocks or rejects "${request.hostileInputPattern}"`,
        expectedExploitableOutcome: request.dangerousBehaviour,
        actualObservation: `Test synthesis failed before execution: ${reason}`,
        verdict: 'inconclusive',
        confidence: 0.3,
        evidenceRefs: [request.suspectFile],
      });
      await args.evidenceStore.appendEvent('verification_test_synthesis_failed', {
        findingId: request.findingId,
        suspectFile: request.suspectFile,
        error: reason,
        modelTimeoutMs,
      });
    }
  }

  summary.durationMs = Date.now() - startedAt;
  return summary;
}

export class TestSynthesisStage implements Stage {
  readonly name = 'test_synthesis' as const;

  constructor(private readonly experimentStore: ExperimentStoreHandle) {}

  async run(context: StageContext): Promise<StageResult> {
    const lane = await context.runner.runTestSynthesisLaneFriend(
      {
        target: context.target,
        memory: context.memory,
        state: context.state,
        stateStore: context.stateStore,
        evidenceStore: context.evidenceStore,
        campaignDir: context.campaignDir,
        telemetry: context.telemetry,
        roleSessions: context.roleSessions,
        archiver: context.archiver,
      },
      this.experimentStore,
    );

    return {
      stage: 'test_synthesis',
      outcome: mapLaneStatus(lane),
      events: [],
      coverageGaps: [],
      metadata: { lane },
    };
  }
}
