import type { ProbeObservation } from '../../../evidence-plane/src/contracts.js';
import { executeGeneratedProbe } from './probe-executor.js';
import type { GeneratedProbe } from './probe-generator.js';
import { BoundedScheduler, type SchedulerConfig } from './scheduler.js';
import type { InvestigationTarget } from './target-profile.js';

export interface ProbeBatchTask {
  index: number;
  probe: GeneratedProbe;
  target: InvestigationTarget;
}

export interface ProbeBatchResult {
  index: number;
  probe: GeneratedProbe;
  observation: ProbeObservation;
  error?: Error;
}

export async function executeProbeBatch(
  tasks: ProbeBatchTask[],
  config: SchedulerConfig,
): Promise<ProbeBatchResult[]> {
  const scheduler = new BoundedScheduler<ProbeBatchResult>(config);

  for (const task of tasks) {
    scheduler.enqueue({
      id: task.probe.fingerprint,
      targetId: task.target.id,
      probeKind: task.probe.kind,
      priority: priorityForProbe(task.probe.kind),
      execute: async () => ({
        index: task.index,
        probe: task.probe,
        observation: await executeGeneratedProbe(task.probe, task.target),
      }),
    });
  }

  const results = await scheduler.runAll();
  return results
    .map((result) => {
      if (result.result) {
        return result.result;
      }

      const task = tasks.find((candidate) => candidate.probe.fingerprint === result.taskId);
      if (!task) {
        throw new Error(`WorkerPool lost task metadata for ${result.taskId}`);
      }

      return {
        index: task.index,
        probe: task.probe,
        observation: {
          kind: task.probe.kind,
          stderr: result.error?.message ?? 'Probe execution failed',
          exitCode: 1,
          durationMs: 0,
        },
        error: result.error,
      };
    })
    .sort((left, right) => left.index - right.index);
}

function priorityForProbe(kind: GeneratedProbe['kind']): number {
  switch (kind) {
    case 'process_check': return 5;
    case 'persistence_check': return 4;
    case 'state_check': return 4;
    case 'evidence_check': return 4;
    case 'prompt_injection': return 3;
    case 'dependency_read': return 3;
    case 'code_read': return 2;
    case 'http_request': return 2;
    case 'shell_command': return 1;
    default: return 1;
  }
}
