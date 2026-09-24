/**
 * Experiment store — append-only persistence for verification experiments.
 * Every experiment from every lane is recorded here so the campaign report
 * can trace back from a final verdict to the actual evidence.
 */

import { appendFile, readFile, mkdir } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import type { VerificationExperiment } from './contracts.js';

export class ExperimentStore {
  private readonly experimentsPath: string;

  constructor(campaignDir: string) {
    this.experimentsPath = resolve(campaignDir, 'verification', 'experiments.jsonl');
  }

  async prepare(): Promise<void> {
    await mkdir(dirname(this.experimentsPath), { recursive: true });
  }

  async record(experiment: VerificationExperiment): Promise<void> {
    await this.prepare();
    await appendFile(this.experimentsPath, JSON.stringify(experiment) + '\n', 'utf8');
  }

  async readAll(): Promise<VerificationExperiment[]> {
    try {
      const content = await readFile(this.experimentsPath, 'utf8');
      return content
        .trim()
        .split('\n')
        .filter(Boolean)
        .map((line) => JSON.parse(line) as VerificationExperiment);
    } catch {
      return [];
    }
  }

  async readByFinding(findingId: string): Promise<VerificationExperiment[]> {
    const all = await this.readAll();
    return all.filter((e) => e.findingId === findingId);
  }

  async readByRoute(route: VerificationExperiment['route']): Promise<VerificationExperiment[]> {
    const all = await this.readAll();
    return all.filter((e) => e.route === route);
  }
}
