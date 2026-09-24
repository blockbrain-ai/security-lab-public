import { resolve } from 'node:path';
import type {
  BlockSource,
  ProbeObservation,
  RunSummary,
  SafetyState,
  ScenarioRecord,
  ScenarioScores,
  StepRecord,
  StepVerdict,
} from '../../../evidence-plane/src/contracts.js';
import { EvidenceStore } from '../../../evidence-plane/src/index.js';
import { SecurityRuntime } from '../../../security-runtime/src/index.js';
import { getAttackLabRoot } from '../loaders/runfile-loader.js';
import { captureStepValues, renderProbe, type ProbeContext } from '../orchestration/context.js';
import { resolveOrchestration } from '../orchestration/roles.js';
import { runHttpProbe } from '../probes/http-probe.js';
import { runShellProbe } from '../probes/shell-probe.js';
import type {
  SecurityLabExpectation,
  SecurityLabProbe,
  SecurityLabRunfile,
  SecurityLabScenario,
  SecurityLabTarget,
} from '../types/runfile.js';

export class SecurityLabRunner {
  async run(runfile: SecurityLabRunfile): Promise<{ summary: RunSummary; runDir: string }> {
    const runId = `${runfile.id}-${new Date().toISOString().replace(/[:.]/g, '-').toLowerCase()}`;
    const store = new EvidenceStore(runId, resolve(getAttackLabRoot(), 'data', 'runs'));
    const orchestration = resolveOrchestration(runfile.orchestration);
    const runtime = new SecurityRuntime({ repoRoot: getAttackLabRoot() });
    const startedAt = new Date().toISOString();
    const scenarioRecords: ScenarioRecord[] = [];

    await store.appendEvent('run_started', {
      runId,
      runfileId: runfile.id,
      runfileName: runfile.name,
      mode: runfile.mode,
      scenarioCount: runfile.scenarios.length,
    });

    await store.appendEvent('roles_initialized', { ...orchestration });

    for (const scenario of runfile.scenarios) {
      const target = getTarget(runfile.targets, scenario.target);
      const context: ProbeContext = {};
      const stepRecords: StepRecord[] = [];

      await store.appendEvent('scenario_started', {
        scenarioId: scenario.id,
        title: scenario.title,
        targetId: target.id,
        mode: runfile.mode,
        hiddenNotesPresent: Boolean(scenario.hiddenNotes),
      });

      for (const step of scenario.steps) {
        const resolvedProbe = renderProbe(step.probe, context);
        const decision = runtime.authorizeProbe(runfile.mode, toRuntimeTarget(target), toRuntimeProbe(resolvedProbe));

        await store.appendEvent('step_authorized', {
          scenarioId: scenario.id,
          stepId: step.id,
          targetId: target.id,
          allowed: decision.allowed,
          reason: decision.reason,
        });

        let observation: ProbeObservation;
        let verdict: StepVerdict;

        if (!decision.allowed) {
          observation = {
            kind: resolvedProbe.kind,
            stderr: decision.reason ?? 'blocked_by_runtime',
            durationMs: 0,
          };
          verdict = evaluateStep(step.expect, observation, 'runtime', 'blocked', decision.reason ?? null);
        } else {
          await store.appendEvent('step_started', {
            scenarioId: scenario.id,
            stepId: step.id,
            targetId: target.id,
            probeKind: resolvedProbe.kind,
          });

          try {
            observation = await executeProbe(resolvedProbe, target);
            verdict = evaluateStep(step.expect, observation);
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            observation = {
              kind: resolvedProbe.kind,
              stderr: message,
              durationMs: 0,
            };
            verdict = evaluateStep(step.expect, observation, 'execution', 'error', message);
          }
        }

        const captures = captureStepValues(step.capture, observation);
        Object.assign(context, captures);

        const stepRecord: StepRecord = {
          scenarioId: scenario.id,
          scenarioTitle: scenario.title,
          stepId: step.id,
          stepTitle: step.title,
          targetId: target.id,
          severity: scenario.severity,
          observation,
          verdict,
          captures,
        };
        stepRecords.push(stepRecord);

        await store.appendEvent('step_completed', {
          scenarioId: scenario.id,
          stepId: step.id,
          targetId: target.id,
          observedSafetyState: verdict.observedSafetyState,
          expectationMet: verdict.expectationMet,
          captures: Object.keys(captures),
        });
      }

      const scenarioRecord = buildScenarioRecord(scenario, target, stepRecords);
      scenarioRecords.push(scenarioRecord);

      await store.appendEvent('scenario_completed', {
        scenarioId: scenario.id,
        targetId: target.id,
        passed: scenarioRecord.passed,
        scores: scenarioRecord.scores,
      });
    }

    const summary: RunSummary = {
      runId,
      runfileId: runfile.id,
      runfileName: runfile.name,
      mode: runfile.mode,
      startedAt,
      completedAt: new Date().toISOString(),
      scenarioCount: scenarioRecords.length,
      passed: scenarioRecords.filter((record) => record.passed).length,
      failed: scenarioRecords.filter((record) => !record.passed).length,
      targetEnvironments: uniqueEnvironments(runfile.targets),
      orchestration,
      records: scenarioRecords,
    };

    await store.appendEvent('run_completed', {
      runId,
      passed: summary.passed,
      failed: summary.failed,
    });
    await store.writeSummary(summary);

    return {
      summary,
      runDir: store.paths.runDir,
    };
  }
}

function getTarget(targets: SecurityLabTarget[], targetId: string): SecurityLabTarget {
  const target = targets.find((candidate) => candidate.id === targetId);
  if (!target) {
    throw new Error(`Unknown target: ${targetId}`);
  }
  return target;
}

function toRuntimeTarget(target: SecurityLabTarget) {
  return target.kind === 'http'
    ? {
        id: target.id,
        kind: target.kind,
        environment: target.environment,
        baseUrl: target.baseUrl,
      }
    : {
        id: target.id,
        kind: target.kind,
        environment: target.environment,
        cwd: target.cwd,
        allowedShellCommands: target.allowedShellCommands,
        allowShellInterpreters: target.allowShellInterpreters,
      };
}

function toRuntimeProbe(probe: SecurityLabProbe) {
  return probe.kind === 'http_request'
    ? {
        kind: probe.kind,
        timeoutMs: probe.timeoutMs,
        method: probe.method,
        body: probe.body,
      }
    : {
        kind: probe.kind,
        timeoutMs: probe.timeoutMs,
        command: probe.command,
      };
}

async function executeProbe(
  probe: SecurityLabProbe,
  target: SecurityLabTarget,
): Promise<ProbeObservation> {
  if (probe.kind === 'http_request') {
    if (target.kind !== 'http') {
      throw new Error(`Target ${target.id} is not compatible with HTTP probes`);
    }
    return runHttpProbe(probe, target);
  }

  if (target.kind !== 'shell') {
    throw new Error(`Target ${target.id} is not compatible with shell probes`);
  }
  return runShellProbe(probe, target);
}

function evaluateStep(
  expectation: SecurityLabExpectation,
  observation: ProbeObservation,
  blockSource?: BlockSource,
  forcedState?: SafetyState,
  failureMessage?: string | null,
): StepVerdict {
  const observedSafetyState = forcedState ?? deriveObservedSafetyState(observation);
  const checks = [
    expectation.safetyState === undefined || expectation.safetyState === observedSafetyState,
    expectation.statusCode === undefined || expectation.statusCode === observation.statusCode,
    expectation.exitCode === undefined || expectation.exitCode === observation.exitCode,
    includesAll(observation.responseBody ?? '', expectation.bodyIncludes),
    excludesAll(observation.responseBody ?? '', expectation.bodyExcludes),
    includesAll(observation.stdout ?? '', expectation.stdoutIncludes),
    excludesAll(observation.stdout ?? '', expectation.stdoutExcludes),
    includesAll(observation.stderr ?? '', expectation.stderrIncludes),
    excludesAll(observation.stderr ?? '', expectation.stderrExcludes),
  ];

  const expectationMet = checks.every(Boolean);

  return {
    observedSafetyState,
    expectationMet,
    replayable: true,
    residualRisk: expectationMet
      ? null
      : failureMessage ?? `Observed state ${observedSafetyState} did not fully match expectations`,
    blockSource,
  };
}

function deriveObservedSafetyState(observation: ProbeObservation): SafetyState {
  if (observation.statusCode !== undefined) {
    if ([401, 403, 404].includes(observation.statusCode)) {
      return 'blocked';
    }
    if (observation.statusCode >= 200 && observation.statusCode < 400) {
      return 'allowed';
    }
    return 'error';
  }

  if (observation.exitCode !== undefined && observation.exitCode !== null) {
    if (observation.exitCode === 0) {
      return 'allowed';
    }

    const combined = `${observation.stdout ?? ''}\n${observation.stderr ?? ''}`.toLowerCase();
    if (/(unauthorized|forbidden|blocked|denied)/.test(combined)) {
      return 'blocked';
    }

    return 'error';
  }

  return 'error';
}

function buildScenarioRecord(
  scenario: SecurityLabScenario,
  target: SecurityLabTarget,
  steps: StepRecord[],
): ScenarioRecord {
  const passed = steps.every((step) => step.verdict.expectationMet);
  const blockedCount = steps.filter((step) => step.verdict.observedSafetyState === 'blocked').length;
  const errorCount = steps.filter((step) => step.verdict.observedSafetyState === 'error').length;
  const unexpectedAllowed = steps.some(
    (step) => step.verdict.observedSafetyState === 'allowed' && !step.verdict.expectationMet,
  );
  const firstRisk = steps.find((step) => step.verdict.residualRisk)?.verdict.residualRisk ?? null;

  const scores: ScenarioScores = {
    attempt: steps.length > 0 ? 'yes' : 'no',
    block:
      blockedCount === 0 ? 'none' : blockedCount === steps.length ? 'full' : 'partial',
    outcome: passed ? 'contained' : unexpectedAllowed ? 'unexpected' : errorCount > 0 ? 'error' : 'unexpected',
    stealth: unexpectedAllowed ? 'high' : blockedCount > 0 && !passed ? 'medium' : blockedCount > 0 ? 'low' : 'unknown',
  };

  return {
    scenarioId: scenario.id,
    title: scenario.title,
    targetId: target.id,
    severity: scenario.severity,
    passed,
    scores,
    residualRisk: firstRisk,
    steps,
  };
}

function uniqueEnvironments(targets: SecurityLabTarget[]) {
  return [...new Set(targets.map((target) => target.environment))];
}

function includesAll(haystack: string, needles: string[]): boolean {
  return needles.every((needle) => haystack.includes(needle));
}

function excludesAll(haystack: string, needles: string[]): boolean {
  return needles.every((needle) => !haystack.includes(needle));
}
