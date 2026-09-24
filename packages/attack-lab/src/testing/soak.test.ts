import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { InvokeOptions, ModelAdapter, ModelResponse } from '../providers/contracts.js';
import { InvestigationRunner } from '../autonomous/investigation-runner.js';

class QueueAdapter implements ModelAdapter {
  readonly provider = 'test';
  readonly model = 'queue-adapter';
  private readonly queue: string[];

  constructor(responses: string[]) {
    this.queue = [...responses];
  }

  async invoke<T = unknown>(_options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    const content = this.queue.shift() ?? JSON.stringify({
      newSignals: [],
      probeRequests: [],
      newChainHypotheses: [],
      markDormant: [],
      reactivations: [],
      reasoning: 'No new work.',
    });

    return {
      content,
      usage: {
        inputTokens: 20,
        outputTokens: 30,
        costUsd: 0.01,
      },
      durationMs: 2,
      provider: this.provider,
      model: this.model,
    };
  }
}

test('soak run completes and resumes without corrupting evidence', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-soak-'));

  try {
    const repoRoot = join(root, 'target');
    const campaignDir = join(root, 'campaigns');
    await mkdir(join(repoRoot, 'src'), { recursive: true });
    await writeFile(join(repoRoot, 'package.json'), JSON.stringify({ name: 'soak-fixture', version: '1.0.0' }, null, 2), 'utf8');
    await writeFile(join(repoRoot, 'src', 'app.ts'), 'export const route = "/soak";\n', 'utf8');

    const planner = new QueueAdapter([
      JSON.stringify({
        newSignals: [],
        probeRequests: [
          {
            targetKind: 'code',
            action: 'read_file',
            rationale: 'Read source during soak run',
            parameters: { action: 'read_file', filePath: 'src/app.ts', timeoutMs: 1000 },
          },
        ],
        newChainHypotheses: [],
        markDormant: [],
        reactivations: [],
        reasoning: 'Run one real code probe.',
      }),
    ]);

    const firstRun = await new InvestigationRunner({
      targetRef: repoRoot,
      mode: 'declared',
      plannerAdapter: planner,
      judgeAdapter: new QueueAdapter([]),
      maxIterations: 4,
      maxCostUsd: 5,
      campaignDir,
    }).run();

    assert.equal(firstRun.status, 'iteration_limit');

    const resumed = await new InvestigationRunner({
      targetRef: repoRoot,
      mode: 'declared',
      plannerAdapter: new QueueAdapter([]),
      judgeAdapter: new QueueAdapter([]),
      maxIterations: 6,
      maxCostUsd: 5,
      campaignDir,
      resumeCampaignId: firstRun.campaignId,
    }).run();

    assert.ok(['iteration_limit', 'completed', 'budget_exhausted', 'already_completed'].includes(resumed.status));

    const events = (await readFile(join(resumed.runDir, 'events.jsonl'), 'utf8'))
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as { index: number });

    for (let index = 0; index < events.length; index += 1) {
      assert.equal(events[index]?.index, index);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
