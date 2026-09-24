/**
 * Response archiver — records every model invocation with full context
 * so the evidence trail shows what was asked, what was answered, and how
 * the response was interpreted.
 */

import { appendFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import type { ArchivedResponse, ModelResponse } from './contracts.js';

export class ResponseArchiver {
  private readonly archivePath: string;

  constructor(runDir: string) {
    this.archivePath = resolve(runDir, 'model-responses.jsonl');
  }

  async prepare(): Promise<void> {
    const dir = resolve(this.archivePath, '..');
    await mkdir(dir, { recursive: true });
  }

  async archive(
    role: ArchivedResponse['role'],
    systemPrompt: string | null,
    prompt: string,
    response: ModelResponse,
    parseSuccess: boolean,
  ): Promise<ArchivedResponse> {
    response.promptHash = createHash('sha256').update(prompt).digest('hex');
    response.responseHash = createHash('sha256').update(response.content).digest('hex');

    const record: ArchivedResponse = {
      id: `${role}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      at: new Date().toISOString(),
      role,
      provider: response.provider,
      model: response.model,
      systemPrompt,
      prompt,
      responseContent: response.content,
      structuredOutput: response.structured ?? null,
      usage: response.usage,
      durationMs: response.durationMs,
      parseSuccess,
      sessionId: response.sessionId,
    };

    await appendFile(this.archivePath, JSON.stringify(record) + '\n', 'utf8');
    return record;
  }
}
