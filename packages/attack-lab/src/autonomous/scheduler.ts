/**
 * Bounded parallel campaign scheduler — runs independent investigation
 * branches concurrently with per-target and per-kind concurrency caps.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SchedulerConfig {
  /** Maximum concurrent probe executions across all branches. */
  maxConcurrency: number;
  /** Maximum concurrent probes per target. */
  maxPerTarget: number;
  /** Maximum concurrent probes per probe kind. */
  maxPerKind: number;
  /** Budget-aware: stop scheduling when cost exceeds limit. */
  maxCostUsd: number;
}

export interface ScheduledTask<T> {
  id: string;
  targetId: string;
  probeKind: string;
  priority: number;
  execute: () => Promise<T>;
}

export interface SchedulerStats {
  totalScheduled: number;
  totalCompleted: number;
  totalFailed: number;
  activeTasks: number;
  queuedTasks: number;
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

export class BoundedScheduler<T> {
  private readonly config: SchedulerConfig;
  private readonly queue: ScheduledTask<T>[] = [];
  private readonly active = new Map<string, Promise<T>>();
  private readonly targetCounts = new Map<string, number>();
  private readonly kindCounts = new Map<string, number>();
  private totalCompleted = 0;
  private totalFailed = 0;
  private currentCostUsd = 0;
  private killed = false;

  constructor(config: SchedulerConfig) {
    this.config = config;
  }

  /**
   * Add a task to the queue. Tasks are executed in priority order
   * (higher priority first) as concurrency slots become available.
   */
  enqueue(task: ScheduledTask<T>): void {
    if (this.killed) return;
    this.queue.push(task);
    // Sort by priority descending
    this.queue.sort((a, b) => b.priority - a.priority);
  }

  /**
   * Run all queued tasks with bounded concurrency.
   * Returns results in completion order.
   */
  async runAll(): Promise<Array<{ taskId: string; result?: T; error?: Error }>> {
    const results: Array<{ taskId: string; result?: T; error?: Error }> = [];

    while (this.queue.length > 0 || this.active.size > 0) {
      if (this.killed) break;
      if (this.currentCostUsd >= this.config.maxCostUsd) break;

      // Fill available slots
      while (this.queue.length > 0 && this.canSchedule(this.queue[0]!)) {
        const task = this.queue.shift()!;
        this.startTask(task, results);
      }

      // Wait for any active task to complete
      if (this.active.size > 0) {
        await Promise.race([...this.active.values()].map((p) => p.catch(() => {})));
      } else if (this.queue.length > 0) {
        // Can't schedule anything and nothing is running — deadlock or all slots blocked
        break;
      }
    }

    // Wait for remaining active tasks
    await Promise.allSettled([...this.active.values()]);

    return results;
  }

  /**
   * Stop scheduling new tasks. Active tasks will complete.
   */
  kill(): void {
    this.killed = true;
    this.queue.length = 0;
  }

  /**
   * Report current cost for budget tracking.
   */
  addCost(costUsd: number): void {
    this.currentCostUsd += costUsd;
  }

  getStats(): SchedulerStats {
    return {
      totalScheduled: this.totalCompleted + this.totalFailed + this.active.size + this.queue.length,
      totalCompleted: this.totalCompleted,
      totalFailed: this.totalFailed,
      activeTasks: this.active.size,
      queuedTasks: this.queue.length,
    };
  }

  // ---------------------------------------------------------------------------
  // Internal
  // ---------------------------------------------------------------------------

  private canSchedule(task: ScheduledTask<T>): boolean {
    if (this.active.size >= this.config.maxConcurrency) return false;

    const targetCount = this.targetCounts.get(task.targetId) ?? 0;
    if (targetCount >= this.config.maxPerTarget) return false;

    const kindCount = this.kindCounts.get(task.probeKind) ?? 0;
    if (kindCount >= this.config.maxPerKind) return false;

    return true;
  }

  private startTask(
    task: ScheduledTask<T>,
    results: Array<{ taskId: string; result?: T; error?: Error }>,
  ): void {
    this.incrementCount(this.targetCounts, task.targetId);
    this.incrementCount(this.kindCounts, task.probeKind);

    const promise = task
      .execute()
      .then((result) => {
        results.push({ taskId: task.id, result });
        this.totalCompleted++;
        return result;
      })
      .catch((error: Error) => {
        results.push({ taskId: task.id, error });
        this.totalFailed++;
        return undefined as unknown as T;
      })
      .finally(() => {
        this.active.delete(task.id);
        this.decrementCount(this.targetCounts, task.targetId);
        this.decrementCount(this.kindCounts, task.probeKind);
      });

    this.active.set(task.id, promise);
  }

  private incrementCount(map: Map<string, number>, key: string): void {
    map.set(key, (map.get(key) ?? 0) + 1);
  }

  private decrementCount(map: Map<string, number>, key: string): void {
    const count = (map.get(key) ?? 1) - 1;
    if (count <= 0) map.delete(key);
    else map.set(key, count);
  }
}
