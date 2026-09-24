import { spawn } from 'node:child_process';
import type { ModelAdapter, ModelConfig, ModelResponse, InvokeOptions, TokenUsage } from './contracts.js';
import { getProviderTimeoutListener } from './timeout.js';
import { argvLimitError, promptExceedsArgvLimit } from './argv-limits.js';
import { tryParseStructured } from './parse-structured.js';
import { WORKER_CONTRACT } from './worker-contract.js';

interface ClaudeStreamAssistantEvent {
  type: 'assistant';
  session_id?: string;
  message?: {
    content?: Array<{ type?: string; text?: string }>;
  };
}

interface ClaudeStreamResultEvent {
  type: 'result';
  session_id?: string;
  result?: string;
  total_cost_usd?: number;
  duration_ms?: number;
  usage?: {
    input_tokens?: number;
    output_tokens?: number;
  };
}

export class ClaudeCodeAdapter implements ModelAdapter {
  readonly provider = 'claude_code';
  readonly model: string;
  readonly supportsNativeSessionResume = true;

  private readonly defaultRequestTimeoutMs: number;
  private readonly workingDirectory?: string;
  private readonly additionalDirectories: string[];
  private readonly effort?: 'low' | 'medium' | 'high' | 'max';
  private readonly binaryPath: string;

  constructor(config: ModelConfig) {
    this.model = config.model;
    this.defaultRequestTimeoutMs = config.requestTimeoutMs ?? 300_000;
    this.workingDirectory = config.workingDirectory;
    this.additionalDirectories = config.additionalDirectories ?? [];
    this.effort = config.effort;
    this.binaryPath = config.binaryPath ?? 'claude';
  }

  async invoke<T = unknown>(options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    return this.invokeWithOptionalResume(options, true);
  }

  private async invokeWithOptionalResume<T>(
    options: InvokeOptions<T>,
    allowResume: boolean,
  ): Promise<ModelResponse<T>> {
    try {
      const prompt = buildPrompt(options.systemPrompt, options.prompt);
      if (promptExceedsArgvLimit(prompt)) {
        throw argvLimitError(
          'ClaudeCodeAdapter',
          prompt,
          'Attach InvokeOptions.briefMode so large context stays on disk and the prompt stays small.',
        );
      }
      const args = [
        '-p',
        '--verbose',
        prompt,
        '--model',
        this.model,
        '--output-format',
        'stream-json',
        '--permission-mode',
        'bypassPermissions',
      ];

      const effort = options.effort ?? this.effort;
      if (effort) {
        args.push('--effort', effort);
      }
      const extraDirs = [...(options.additionalDirectories ?? this.additionalDirectories)];
      if (options.briefMode) extraDirs.push(options.briefMode.artifactsDir);
      for (const directory of dedupePaths(extraDirs)) {
        args.push('--add-dir', directory);
      }
      if (allowResume && options.sessionId) {
        args.push('--resume', options.sessionId);
      }

      const requestTimeoutMs = options.requestTimeoutMs ?? this.defaultRequestTimeoutMs;
      const startedAt = Date.now();
      const { stdout, stderr } = await runClaudeCommand(this.binaryPath, args, {
        cwd: options.workingDirectory ?? this.workingDirectory,
        timeoutMs: requestTimeoutMs,
        env: process.env,
        onTimeout: (elapsedMs) => {
          const listener = getProviderTimeoutListener();
          if (listener) listener({ provider: 'claude_code', model: this.model, label: `claude_code:${this.model}`, elapsedMs, timeoutMs: requestTimeoutMs });
        },
      });
      const durationMs = Date.now() - startedAt;
      const parsed = parseClaudeStream(stdout, stderr);
      const content = parsed.content.trim() || parsed.resultText.trim();
      const structured = tryParseStructured(content, options.schema);

      return {
        content,
        structured,
        usage: parsed.usage,
        durationMs: parsed.durationMs ?? durationMs,
        provider: this.provider,
        model: this.model,
        sessionId: parsed.sessionId,
      };
    } catch (error) {
      if (allowResume && options.sessionId) {
        return this.invokeWithOptionalResume({ ...options, sessionId: undefined }, false);
      }
      throw error;
    }
  }
}

async function runClaudeCommand(
  command: string,
  args: string[],
  options: {
    cwd?: string;
    timeoutMs: number;
    env: NodeJS.ProcessEnv;
    onTimeout?: (elapsedMs: number) => void;
  },
): Promise<{ stdout: string; stderr: string }> {
  const startMs = Date.now();
  return await new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    let settled = false;
    const maxBuffer = 50 * 1024 * 1024;

    const fail = (error: Error): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timeoutHandle);
      reject(error);
    };

    const pushChunk = (current: string, chunk: Buffer | string): string => {
      const next = current + chunk.toString();
      if (next.length > maxBuffer) {
        fail(new Error(`Command exceeded maxBuffer of ${maxBuffer} bytes: ${command}`));
        return current;
      }
      return next;
    };

    child.stdout.on('data', (chunk) => {
      stdout = pushChunk(stdout, chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderr = pushChunk(stderr, chunk);
    });
    child.on('error', (error) => {
      fail(error);
    });

    const timeoutHandle = setTimeout(() => {
      child.kill('SIGTERM');
      setTimeout(() => child.kill('SIGKILL'), 2_000).unref();
      const elapsedMs = Date.now() - startMs;
      options.onTimeout?.(elapsedMs);
      fail(new Error(`Command timed out after ${options.timeoutMs}ms: ${command} ${args.join(' ')}`));
    }, options.timeoutMs);

    child.on('close', (code, signal) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timeoutHandle);
      if (code === 0) {
        resolve({ stdout, stderr });
        return;
      }
      const renderedSignal = signal ? ` signal=${signal}` : '';
      const details = stderr.trim() || stdout.trim();
      reject(new Error(`Command failed with code ${code ?? 'null'}${renderedSignal}: ${command} ${args.join(' ')}${details ? `\n${details}` : ''}`));
    });
  });
}

function buildPrompt(systemPrompt: string | undefined, prompt: string): string {
  if (!systemPrompt?.trim()) {
    return [
      WORKER_CONTRACT,
      '',
      'Return your final answer directly. When JSON is requested, respond with JSON only.',
      '',
      prompt,
    ].join('\n');
  }
  return [
    WORKER_CONTRACT,
    '',
    systemPrompt.trim(),
    '',
    'Return your final answer directly. When JSON is requested, respond with JSON only.',
    '',
    prompt,
  ].join('\n');
}

function parseClaudeStream(stdout: string, stderr: string): {
  content: string;
  resultText: string;
  usage: TokenUsage;
  sessionId?: string;
  durationMs?: number;
} {
  const assistantParts: string[] = [];
  let resultText = '';
  let sessionId: string | undefined;
  let durationMs: number | undefined;
  let usage: TokenUsage = { inputTokens: 0, outputTokens: 0, costUsd: 0 };

  for (const rawLine of `${stdout}\n${stderr}`.split('\n')) {
    const line = rawLine.trim();
    if (!line.startsWith('{')) {
      continue;
    }
    let event: Record<string, unknown>;
    try {
      event = JSON.parse(line) as Record<string, unknown>;
    } catch {
      continue;
    }

    if (event.type === 'assistant') {
      const assistant = event as unknown as ClaudeStreamAssistantEvent;
      sessionId ??= assistant.session_id;
      for (const block of assistant.message?.content ?? []) {
        if (block.type === 'text' && typeof block.text === 'string') {
          assistantParts.push(block.text);
        }
      }
    }

    if (event.type === 'result') {
      const result = event as unknown as ClaudeStreamResultEvent;
      sessionId ??= result.session_id;
      resultText = typeof result.result === 'string' ? result.result : resultText;
      durationMs = typeof result.duration_ms === 'number' ? result.duration_ms : durationMs;
      usage = {
        inputTokens: result.usage?.input_tokens ?? usage.inputTokens,
        outputTokens: result.usage?.output_tokens ?? usage.outputTokens,
        costUsd: typeof result.total_cost_usd === 'number' ? result.total_cost_usd : usage.costUsd,
      };
    }
  }

  return {
    content: assistantParts.join('\n').trim(),
    resultText,
    usage,
    sessionId,
    durationMs,
  };
}

function dedupePaths(paths: string[]): string[] {
  return [...new Set(paths.filter(Boolean))];
}
