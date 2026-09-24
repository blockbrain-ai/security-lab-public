/**
 * Claude model adapter — uses the Anthropic SDK for structured output.
 */

import type { ModelAdapter, ModelConfig, ModelResponse, InvokeOptions, TokenUsage } from './contracts.js';
import { withRetry } from './retry.js';
import { withRequestTimeout, getProviderTimeoutListener } from './timeout.js';
import { tryParseStructured } from './parse-structured.js';

// Cost per million tokens (approximate, updated periodically)
const COST_TABLE: Record<string, { input: number; output: number }> = {
  'claude-opus-4-6': { input: 15, output: 75 },
  'claude-sonnet-4-6': { input: 3, output: 15 },
  'claude-haiku-4-5': { input: 0.8, output: 4 },
};

function estimateCost(model: string, usage: { inputTokens: number; outputTokens: number }): number {
  const rates = COST_TABLE[model] ?? { input: 3, output: 15 };
  return (usage.inputTokens * rates.input + usage.outputTokens * rates.output) / 1_000_000;
}

export class ClaudeAdapter implements ModelAdapter {
  readonly provider = 'anthropic';
  readonly model: string;
  readonly supportsNativeSessionResume = false;
  private readonly apiKey: string;
  private readonly defaultMaxTokens: number;
  private readonly defaultTemperature: number;
  private readonly defaultRequestTimeoutMs: number;

  constructor(config: ModelConfig) {
    this.model = config.model;
    this.apiKey = config.apiKey ?? process.env['ANTHROPIC_API_KEY'] ?? '';
    this.defaultMaxTokens = config.maxTokens ?? 4096;
    this.defaultTemperature = config.temperature ?? 0;
    this.defaultRequestTimeoutMs = config.requestTimeoutMs ?? 180_000;

    if (!this.apiKey) {
      throw new Error('ClaudeAdapter: ANTHROPIC_API_KEY is required');
    }
  }

  async invoke<T = unknown>(options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    const { default: Anthropic } = await import('@anthropic-ai/sdk');
    const client = new Anthropic({ apiKey: this.apiKey });
    const maxTokens = options.maxTokens ?? this.defaultMaxTokens;
    const temperature = options.temperature ?? this.defaultTemperature;
    const requestTimeoutMs = options.requestTimeoutMs ?? this.defaultRequestTimeoutMs;

    const start = Date.now();

    const messages: Array<{ role: 'user'; content: string }> = [
      { role: 'user', content: options.prompt },
    ];

    const response = await withRetry(
      async () =>
        withRequestTimeout(
          () =>
            client.messages.create({
              model: this.model,
              max_tokens: maxTokens,
              temperature,
              system: options.systemPrompt ?? '',
              messages,
            }),
          { timeoutMs: requestTimeoutMs, label: `anthropic:${this.model}`, onTimeout: (info) => {
            const listener = getProviderTimeoutListener();
            if (listener) listener({ provider: 'anthropic', model: this.model, ...info });
          } },
        ),
      {
        onRetry: (attempt, delayMs) => {
          console.warn(`[claude-adapter] Retry ${attempt}, waiting ${delayMs / 1000}s...`);
        },
      },
    );

    const durationMs = Date.now() - start;

    const content = response.content
      .filter((block) => block.type === 'text')
      .map((block) => 'text' in block ? (block as { text: string }).text : '')
      .join('\n');

    const usage: TokenUsage = {
      inputTokens: response.usage.input_tokens,
      outputTokens: response.usage.output_tokens,
      costUsd: estimateCost(this.model, {
        inputTokens: response.usage.input_tokens,
        outputTokens: response.usage.output_tokens,
      }),
    };

    const structured = tryParseStructured(content, options.schema);

    return {
      content,
      structured,
      usage,
      durationMs,
      provider: this.provider,
      model: this.model,
    };
  }
}
