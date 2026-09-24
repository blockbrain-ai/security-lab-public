import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ModelAdapter, ModelConfig, ModelResponse, InvokeOptions } from './contracts.js';
import { tryParseStructured } from './parse-structured.js';
import { WORKER_CONTRACT } from './worker-contract.js';

const execFileAsync = promisify(execFile);

export class PiCliAdapter implements ModelAdapter {
  readonly provider = 'pi_cli' as const;
  readonly model: string;
  readonly supportsNativeSessionResume = false;
  readonly isLocalInference: boolean;

  private readonly defaultRequestTimeoutMs: number;
  private readonly workingDirectory?: string;
  private readonly baseUrl: string;
  private readonly piProviderName: string;
  private readonly piConfigDir?: string;
  private readonly piToolAllowlist?: string[];
  private readonly piMaxTokens: number;
  private readonly piOutputMode: 'text' | 'json' | 'rpc';
  private readonly binaryPath: string;

  constructor(config: ModelConfig) {
    this.model = config.model;
    this.defaultRequestTimeoutMs = config.requestTimeoutMs ?? 900_000;
    this.workingDirectory = config.workingDirectory;
    this.baseUrl = (config.baseUrl ?? 'http://127.0.0.1:8080/v1').replace(/\/+$/, '');
    this.isLocalInference = config.localInference ?? true;
    this.piProviderName = config.piProviderName ?? 'securitylab-local';
    this.piConfigDir = config.piConfigDir;
    this.piToolAllowlist = config.piToolAllowlist;
    this.piMaxTokens = config.piMaxTokens ?? 16384;
    this.piOutputMode = config.piOutputMode ?? 'text';
    this.binaryPath = config.binaryPath ?? 'pi';
  }

  async invoke<T = unknown>(options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    const startedAt = Date.now();
    const requestTimeoutMs = options.requestTimeoutMs ?? this.defaultRequestTimeoutMs;
    const cwd = options.workingDirectory ?? this.workingDirectory;

    const configDir = await this.ensureConfigDir();
    const prompt = buildPrompt(options.systemPrompt, options.prompt);

    const args = this.buildSpawnArgs(prompt);

    let stdout: string;
    let stderr: string;
    try {
      const result = await execFileAsync(this.binaryPath, args, {
        cwd,
        timeout: requestTimeoutMs,
        maxBuffer: 50 * 1024 * 1024,
        env: {
          ...process.env,
          PI_CODING_AGENT_DIR: configDir,
        },
      });
      stdout = result.stdout;
      stderr = result.stderr;
    } catch (error) {
      if (error && typeof error === 'object' && 'code' in error && (error as { code: string }).code === 'ENOENT') {
        throw new Error(
          `pi_cli: Pi binary not found at "${this.binaryPath}". ` +
          `Install with: npm install -g @mariozechner/pi-coding-agent`,
        );
      }
      if (error && typeof error === 'object' && 'killed' in error && (error as { killed: boolean }).killed) {
        throw new Error(
          `pi_cli: process killed (timeout ${requestTimeoutMs}ms)`,
        );
      }
      if (error && typeof error === 'object' && 'stdout' in error && 'stderr' in error) {
        stdout = (error as { stdout: string }).stdout ?? '';
        stderr = (error as { stderr: string }).stderr ?? '';
      } else {
        throw error;
      }
    }

    const durationMs = Date.now() - startedAt;
    const parsed = parsePiOutput(stdout, stderr);
    const structured = tryParseStructured(parsed.content, options.schema);

    return {
      content: parsed.content,
      structured,
      usage: {
        inputTokens: parsed.inputTokens,
        outputTokens: parsed.outputTokens,
        costUsd: this.isLocalInference ? 0 : parsed.costUsd,
      },
      durationMs,
      provider: this.provider,
      model: this.model,
    };
  }

  private buildSpawnArgs(prompt: string): string[] {
    const args: string[] = [];

    if (this.piOutputMode === 'text') {
      args.push('-p');
    } else {
      args.push('--mode', this.piOutputMode);
    }

    args.push(
      '--model', `${this.piProviderName}/${this.model}`,
      '--no-context-files',
      '--no-session',
      '--no-extensions',
      '--no-skills',
      '--no-prompt-templates',
      '--thinking', 'off',
    );

    if (this.piToolAllowlist && this.piToolAllowlist.length > 0) {
      args.push('--tools', this.piToolAllowlist.join(','));
    }

    args.push(prompt);
    return args;
  }

  private async ensureConfigDir(): Promise<string> {
    if (this.piConfigDir) return this.piConfigDir;

    const dir = await mkdtemp(join(tmpdir(), 'pi-securitylab-'));
    const modelsJson = {
      providers: {
        [this.piProviderName]: {
          baseUrl: this.baseUrl,
          api: 'openai-completions',
          apiKey: 'local',
          compat: {
            supportsDeveloperRole: false,
            supportsReasoningEffort: false,
          },
          models: [
            {
              id: this.model,
              name: `Security Lab Local ${this.model}`,
              reasoning: false,
              input: ['text'],
              contextWindow: 32768,
              maxTokens: this.piMaxTokens,
              cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
            },
          ],
        },
      },
    };

    await writeFile(join(dir, 'models.json'), JSON.stringify(modelsJson, null, 2));
    await writeFile(join(dir, 'settings.json'), '{}');
    await writeFile(join(dir, 'auth.json'), '{}');

    return dir;
  }
}

function buildPrompt(systemPrompt: string | undefined, prompt: string): string {
  const parts = [WORKER_CONTRACT, ''];
  if (systemPrompt?.trim()) {
    parts.push(systemPrompt.trim(), '');
  }
  parts.push('Return your final answer directly. When JSON is requested, respond with JSON only.', '', prompt);
  return parts.join('\n');
}

interface ParsedPiOutput {
  content: string;
  inputTokens: number;
  outputTokens: number;
  costUsd: number;
}

function parsePiOutput(stdout: string, stderr: string): ParsedPiOutput {
  let content = '';
  let inputTokens = 0;
  let outputTokens = 0;
  let costUsd = 0;

  const combined = `${stdout}\n${stderr}`;

  for (const rawLine of combined.split('\n')) {
    const line = rawLine.trim();
    if (!line.startsWith('{')) continue;

    let event: Record<string, unknown>;
    try {
      event = JSON.parse(line) as Record<string, unknown>;
    } catch {
      continue;
    }

    // Pi print mode outputs text directly (not JSON events) when not in RPC/json mode.
    // But when using --mode json or RPC, it emits structured events.
    if (event.type === 'agent_end') {
      const messages = event.messages as Array<Record<string, unknown>> | undefined;
      if (messages) {
        for (const msg of messages) {
          if (msg.role === 'assistant') {
            const msgContent = msg.content;
            if (typeof msgContent === 'string') {
              content = msgContent;
            } else if (Array.isArray(msgContent)) {
              for (const block of msgContent) {
                if (typeof block === 'object' && block !== null && (block as Record<string, unknown>).type === 'text') {
                  content = (block as Record<string, unknown>).text as string;
                }
              }
            }
            const usage = msg.usage as Record<string, unknown> | undefined;
            if (usage) {
              inputTokens = (usage.input as number) ?? inputTokens;
              outputTokens = (usage.output as number) ?? outputTokens;
              const costObj = usage.cost as Record<string, unknown> | undefined;
              if (costObj) {
                costUsd = (costObj.total as number) ?? costUsd;
              }
            }
          }
        }
      }
    }

    if (event.type === 'message_end') {
      const msg = event.message as Record<string, unknown> | undefined;
      if (msg?.role === 'assistant') {
        const msgContent = msg.content;
        if (typeof msgContent === 'string') {
          content = msgContent;
        } else if (Array.isArray(msgContent)) {
          for (const block of msgContent) {
            if (typeof block === 'object' && block !== null && (block as Record<string, unknown>).type === 'text') {
              content = (block as Record<string, unknown>).text as string;
            }
          }
        }
        const usage = msg.usage as Record<string, unknown> | undefined;
        if (usage) {
          inputTokens = (usage.input as number) ?? inputTokens;
          outputTokens = (usage.output as number) ?? outputTokens;
        }
      }
    }
  }

  // Pi in print mode (-p) outputs the final text directly to stdout, not as JSON events.
  // If we got no content from event parsing, use the raw stdout (stripped of Pi
  // session/control JSON lines — these have a "type" field like session/agent_start/etc).
  if (!content) {
    const nonEventLines = combined.split('\n').filter((l) => {
      const trimmed = l.trim();
      if (!trimmed) return false;
      if (trimmed.startsWith('{')) {
        try {
          const obj = JSON.parse(trimmed);
          return typeof obj.type !== 'string';
        } catch { return true; }
      }
      return true;
    });
    content = nonEventLines.join('\n').trim();
  }

  return { content, inputTokens, outputTokens, costUsd };
}
