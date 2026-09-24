import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import type { ModelAdapter, ModelConfig, ModelResponse, InvokeOptions, TokenUsage } from './contracts.js';
import { getProviderTimeoutListener } from './timeout.js';
import { tryParseStructured } from './parse-structured.js';
import { WORKER_CONTRACT } from './worker-contract.js';

const execFileAsync = promisify(execFile);

// Standard short-context API rates (per 1M tokens), checked 2026-04-26.
// No long-context tier detection — add if needed.
const COST_TABLE: Record<string, { input: number; output: number }> = {
  'gpt-5.5': { input: 5, output: 30 },
  'gpt-5.5-pro': { input: 30, output: 180 },
  'gpt-5.4': { input: 2.5, output: 15 },
  'gpt-5.4-mini': { input: 0.75, output: 4.5 },
};

// Defensive guard: Codex CLI has no prompt cache, so every large prompt
// pays full freight. A prompt this size (>100K tokens) without a brief
// manifest is almost certainly a bug in the caller — the point of brief
// mode is to put large content on disk behind --add-dir and send a tiny
// pointer prompt. See docs/CODEX-BRIEF-MODE-FIX.md for the fixture-target
// campaign that triggered this guard.
const LARGE_PROMPT_TOKEN_THRESHOLD = 100_000;
const CHARS_PER_TOKEN_APPROX = 4;

// Linux caps a single argv entry at ~128 KB (MAX_ARG_STRLEN), so a prompt of
// that size cannot be passed as an argument: the spawn fails with E2BIG. macOS
// allows far more, which is why this only shows up in CI/Linux. Prompts above
// this size are piped to the CLI on stdin instead ("-" reads stdin).
const MAX_ARGV_PROMPT_BYTES = 100_000;

interface CodexThreadEvent {
  type: 'thread.started';
  thread_id?: string;
}

interface CodexAgentMessageEvent {
  type: 'item.completed';
  item?: {
    type?: string;
    text?: string;
  };
}

interface CodexTurnCompletedEvent {
  type: 'turn.completed';
  usage?: {
    input_tokens?: number;
    output_tokens?: number;
    cached_input_tokens?: number;
  };
}

export class CodexCliAdapter implements ModelAdapter {
  readonly provider = 'codex_cli';
  readonly model: string;
  readonly supportsNativeSessionResume = true;
  readonly isLocalInference: boolean;

  private readonly defaultRequestTimeoutMs: number;
  private readonly workingDirectory?: string;
  private readonly additionalDirectories: string[];
  private readonly effort?: 'low' | 'medium' | 'high' | 'max';
  private readonly cliLocalProvider?: 'ollama' | 'lmstudio';
  private readonly cliProfile?: string;
  private readonly binaryPath: string;

  constructor(config: ModelConfig) {
    this.model = config.model;
    this.defaultRequestTimeoutMs = config.requestTimeoutMs ?? 300_000;
    this.workingDirectory = config.workingDirectory;
    this.additionalDirectories = config.additionalDirectories ?? [];
    this.effort = config.effort;
    this.cliLocalProvider = config.cliLocalProvider;
    this.cliProfile = config.cliProfile;
    this.isLocalInference = config.localInference ?? (config.cliLocalProvider !== undefined);
    this.binaryPath = config.binaryPath ?? 'codex';
  }

  async invoke<T = unknown>(options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    return this.invokeWithOptionalResume(options, true);
  }

  private async invokeWithOptionalResume<T>(options: InvokeOptions<T>, allowResume: boolean): Promise<ModelResponse<T>> {
    const requestTimeoutMs = options.requestTimeoutMs ?? this.defaultRequestTimeoutMs;
    const startedAt = Date.now();
    try {
      const prompt = buildPrompt(options.systemPrompt, options.prompt);

      // Large-prompt guard — see LARGE_PROMPT_TOKEN_THRESHOLD docstring.
      // Only enforced when no brief-mode manifest is attached; with brief
      // mode, large context is on disk and the prompt itself stays small.
      const approxPromptTokens = Math.round(prompt.length / CHARS_PER_TOKEN_APPROX);
      if (approxPromptTokens > LARGE_PROMPT_TOKEN_THRESHOLD && !options.briefMode) {
        throw new Error(
          `CodexCliAdapter refusing prompt of ~${approxPromptTokens.toLocaleString()} tokens without brief mode ` +
            `(threshold ${LARGE_PROMPT_TOKEN_THRESHOLD.toLocaleString()}). Codex CLI has no prompt cache — ` +
            `this would pay full freight on every retry. Supply InvokeOptions.briefMode with a file-backed ` +
            `brief manifest, or narrow the target scope. See docs/CODEX-BRIEF-MODE-FIX.md.`,
        );
      }

      const cwd = options.workingDirectory ?? this.workingDirectory;
      const resuming = Boolean(options.sessionId && allowResume);
      const args = resuming
        ? ['exec', 'resume', options.sessionId!, '--json', '-m', this.model, '--dangerously-bypass-approvals-and-sandbox']
        : ['exec', '--json', '-m', this.model, '--dangerously-bypass-approvals-and-sandbox'];

      if (resuming && this.cliLocalProvider) {
        args.push('--oss', '--local-provider', this.cliLocalProvider);
      }
      if (!resuming) {
        args.push(...this.buildFreshTransportArgs());
      }
      if (cwd && !resuming) {
        args.push('-C', cwd);
      }
      const effort = options.effort ?? this.effort;
      if (effort) {
        // Codex CLI's config.toml enum is {none, minimal, low, medium, high, xhigh}.
        // InvokeOptions.effort uses {low, medium, high, max} (the Claude Code set).
        // Map 'max' → 'xhigh' so a caller asking for the highest reasoning effort
        // works uniformly across providers without the profile needing to know
        // Codex-specific strings.
        const codexEffort = effort === 'max' ? 'xhigh' : effort;
        args.push('-c', `model_reasoning_effort=${codexEffort}`);
      }
      if (!resuming) {
        const extraDirs = [...(options.additionalDirectories ?? this.additionalDirectories)];
        if (options.briefMode) extraDirs.push(options.briefMode.artifactsDir);
        for (const directory of dedupePaths(extraDirs)) {
          args.push('--add-dir', directory);
        }
      }
      const promptViaStdin = Buffer.byteLength(prompt, 'utf8') > MAX_ARGV_PROMPT_BYTES;
      args.push(promptViaStdin ? '-' : prompt);
      const { stdout, stderr } = promptViaStdin
        ? await this.runCodexWithStdin(args, { cwd, timeoutMs: requestTimeoutMs, stdinPayload: prompt })
        : await execFileAsync(this.binaryPath, args, {
            cwd,
            timeout: requestTimeoutMs,
            maxBuffer: 50 * 1024 * 1024,
            env: process.env,
          });
      const durationMs = Date.now() - startedAt;
      const parsed = parseCodexJson(stdout, stderr, this.model, this.isLocalInference);
      const structured = tryParseStructured(parsed.content, options.schema);

      return {
        content: parsed.content,
        structured,
        usage: parsed.usage,
        durationMs,
        provider: this.provider,
        model: this.model,
        sessionId: parsed.sessionId,
      };
    } catch (error) {
      // Emit provider_timeout event when the process was killed by timeout
      if (error && typeof error === 'object' && 'killed' in error && (error as { killed: boolean }).killed) {
        const elapsedMs = Date.now() - startedAt;
        const listener = getProviderTimeoutListener();
        if (listener)
          listener({
            provider: 'codex_cli',
            model: this.model,
            label: `codex_cli:${this.model}`,
            elapsedMs,
            timeoutMs: requestTimeoutMs,
          });
      }
      if (allowResume && options.sessionId) {
        return this.invokeWithOptionalResume({ ...options, sessionId: undefined }, false);
      }
      throw error;
    }
  }

  /**
   * Run the CLI with the prompt supplied on stdin. Used for prompts that are
   * too large for an argv entry (see MAX_ARGV_PROMPT_BYTES). Rejects with an
   * error carrying `killed: true` on timeout so the caller emits the same
   * provider_timeout event as the execFile path.
   */
  private runCodexWithStdin(
    args: string[],
    options: { cwd?: string; timeoutMs: number; stdinPayload: string },
  ): Promise<{ stdout: string; stderr: string }> {
    return new Promise((resolvePromise, rejectPromise) => {
      const child = spawn(this.binaryPath, args, {
        cwd: options.cwd,
        env: process.env,
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      let stdout = '';
      let stderr = '';
      let settled = false;
      const MAX_OUTPUT_BYTES = 50 * 1024 * 1024;

      const finish = (error: Error | null): void => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timer);
        if (error) {
          rejectPromise(error);
          return;
        }
        resolvePromise({ stdout, stderr });
      };

      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        const error = new Error(`Codex CLI timed out after ${options.timeoutMs}ms`) as Error & { killed: boolean };
        error.killed = true;
        finish(error);
      }, options.timeoutMs);

      child.stdout?.on('data', (chunk: Buffer) => {
        stdout += chunk.toString('utf8');
        if (stdout.length > MAX_OUTPUT_BYTES) {
          child.kill('SIGKILL');
          finish(new Error('Codex CLI produced more output than the 50MB buffer allows'));
        }
      });
      child.stderr?.on('data', (chunk: Buffer) => {
        stderr += chunk.toString('utf8');
      });
      child.on('error', (error) => finish(error));
      child.on('close', (code) => {
        if (code !== 0 && stdout.trim() === '') {
          finish(new Error(`Codex CLI exited with code ${code ?? 'unknown'}: ${stderr.trim().slice(0, 500)}`));
          return;
        }
        finish(null);
      });

      child.stdin?.on('error', () => {
        // The CLI may exit before consuming stdin; the close handler decides.
      });
      child.stdin?.end(options.stdinPayload, 'utf8');
    });
  }

  private buildFreshTransportArgs(): string[] {
    const args: string[] = [];
    if (this.cliProfile) {
      args.push('-p', this.cliProfile);
    }
    if (this.cliLocalProvider) {
      args.push('--oss', '--local-provider', this.cliLocalProvider);
    } else if (this.isLocalInference && !this.cliProfile) {
      args.push('--oss');
    }
    return args;
  }
}

function buildPrompt(systemPrompt: string | undefined, prompt: string): string {
  if (!systemPrompt?.trim()) {
    return [WORKER_CONTRACT, '', 'Return your final answer directly. When JSON is requested, respond with JSON only.', '', prompt].join('\n');
  }
  return [WORKER_CONTRACT, '', systemPrompt.trim(), '', 'Return your final answer directly. When JSON is requested, respond with JSON only.', '', prompt].join('\n');
}

function parseCodexJson(
  stdout: string,
  stderr: string,
  model: string,
  isLocalInference: boolean,
): {
  content: string;
  usage: TokenUsage;
  sessionId?: string;
} {
  let sessionId: string | undefined;
  let content = '';
  let inputTokens = 0;
  let outputTokens = 0;
  let lastReasoning = '';
  const commandOutputs: string[] = [];

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

    if (event.type === 'thread.started') {
      sessionId = (event as unknown as CodexThreadEvent).thread_id ?? sessionId;
    }
    if (event.type === 'item.completed') {
      const message = event as unknown as CodexAgentMessageEvent;
      if (message.item?.type === 'agent_message' && typeof message.item.text === 'string') {
        content = message.item.text;
      } else if (message.item?.type === 'reasoning' && typeof message.item.text === 'string') {
        lastReasoning = message.item.text;
      } else if (message.item?.type === 'command_execution' && typeof (message.item as Record<string, unknown>).aggregated_output === 'string') {
        commandOutputs.push((message.item as Record<string, unknown>).aggregated_output as string);
      }
    }
    if (event.type === 'turn.completed') {
      const turn = event as unknown as CodexTurnCompletedEvent;
      inputTokens = turn.usage?.input_tokens ?? inputTokens;
      outputTokens = turn.usage?.output_tokens ?? outputTokens;
    }
  }

  // Fallback: if the model never produced an agent_message, try to extract
  // JSON from reasoning or command outputs. Local models using Codex often
  // exhaust their context on tool calls and never emit a final message.
  if (!content && (lastReasoning || commandOutputs.length > 0)) {
    const candidates = [lastReasoning, ...commandOutputs.reverse()];
    for (const candidate of candidates) {
      const jsonMatch = candidate.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
      if (jsonMatch) {
        content = jsonMatch[1]!;
        break;
      }
      // Try raw JSON object
      const braceMatch = candidate.match(/\{[\s\S]*"newSignals"[\s\S]*\}/);
      if (braceMatch) {
        content = braceMatch[0];
        break;
      }
    }
    // Last resort: use the last reasoning as content for the summary extractor
    if (!content && lastReasoning.length > 100) {
      content = lastReasoning;
    }
  }

  return {
    content,
    sessionId,
    usage: {
      inputTokens,
      outputTokens,
      costUsd: estimateCodexCliCost(model, inputTokens, outputTokens, isLocalInference),
    },
  };
}

function estimateCodexCliCost(model: string, inputTokens: number, outputTokens: number, isLocalInference: boolean): number {
  if (isLocalInference) {
    return 0;
  }
  const rates = COST_TABLE[model] ?? COST_TABLE['gpt-5.4'];
  return (inputTokens * rates.input + outputTokens * rates.output) / 1_000_000;
}

function dedupePaths(paths: string[]): string[] {
  return [...new Set(paths.filter(Boolean))];
}
