/**
 * OpenAI model adapter — uses the OpenAI SDK for structured output.
 */

import type { ModelAdapter, ModelConfig, ModelResponse, InvokeOptions, TokenUsage } from './contracts.js';
import { withRetry } from './retry.js';
import { withRequestTimeout, getProviderTimeoutListener } from './timeout.js';
import { tryParseStructured } from './parse-structured.js';

// Standard short-context API rates (per 1M tokens), checked 2026-04-26.
// No long-context tier detection — add if needed.
const COST_TABLE: Record<string, { input: number; output: number }> = {
  'gpt-5.5': { input: 5, output: 30 },
  'gpt-5.5-pro': { input: 30, output: 180 },
  'gpt-5.4': { input: 2.5, output: 15 },
  'gpt-5.4-mini': { input: 0.75, output: 4.5 },
  'gpt-4o': { input: 2.5, output: 10 },
  'gpt-4o-mini': { input: 0.15, output: 0.6 },
  'qwen3.6-27b': { input: 0, output: 0 },
};

function estimateCost(
  model: string,
  usage: { inputTokens: number; outputTokens: number },
  baseUrl?: string,
): number {
  if (baseUrl) {
    return 0;
  }
  const rates = COST_TABLE[model] ?? { input: 2.5, output: 10 };
  return (usage.inputTokens * rates.input + usage.outputTokens * rates.output) / 1_000_000;
}

interface OpenAIUsageLike {
  prompt_tokens?: number;
  completion_tokens?: number;
}

interface OpenAIResponseLike {
  choices?: Array<{ message?: { content?: string | null } }>;
  usage?: OpenAIUsageLike;
}

interface OpenAIClientLike {
  chat: {
    completions: {
      create(params: {
        model: string;
        max_completion_tokens: number;
        temperature: number;
        messages: Array<{ role: 'system' | 'user'; content: string }>;
        stream: false;
      }): Promise<OpenAIResponseLike>;
    };
  };
}

let openAIClientFactory:
  | ((config: { apiKey: string; baseURL?: string }) => Promise<OpenAIClientLike>)
  | null = null;

async function createOpenAIClient(config: { apiKey: string; baseURL?: string }): Promise<OpenAIClientLike> {
  if (openAIClientFactory) {
    return openAIClientFactory(config);
  }

  const { default: OpenAI } = await import('openai');
  return new OpenAI(config) as unknown as OpenAIClientLike;
}

export function setOpenAIClientFactoryForTests(
  factory: ((config: { apiKey: string; baseURL?: string }) => Promise<OpenAIClientLike>) | null,
): void {
  openAIClientFactory = factory;
}

export class OpenAIAdapter implements ModelAdapter {
  readonly provider = 'openai';
  readonly model: string;
  readonly supportsNativeSessionResume = false;
  private readonly apiKey: string;
  private readonly baseUrl: string | undefined;
  private readonly defaultMaxTokens: number;
  private readonly defaultTemperature: number;
  private readonly defaultRequestTimeoutMs: number;

  constructor(config: ModelConfig) {
    this.model = config.model;
    this.baseUrl = config.baseUrl;
    this.apiKey = config.apiKey ?? process.env['OPENAI_API_KEY'] ?? (config.baseUrl ? 'local' : '');
    this.defaultMaxTokens = config.maxTokens ?? 4096;
    this.defaultTemperature = config.temperature ?? 0;
    this.defaultRequestTimeoutMs = config.requestTimeoutMs ?? 180_000;

    if (!this.apiKey) {
      throw new Error('OpenAIAdapter: OPENAI_API_KEY is required');
    }
  }

  async invoke<T = unknown>(options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    const client = await createOpenAIClient({ apiKey: this.apiKey, ...(this.baseUrl && { baseURL: this.baseUrl }) });
    const maxTokens = options.maxTokens ?? this.defaultMaxTokens;
    const temperature = options.temperature ?? this.defaultTemperature;
    const requestTimeoutMs = options.requestTimeoutMs ?? this.defaultRequestTimeoutMs;

    const start = Date.now();

    const messages: Array<{ role: 'system' | 'user'; content: string }> = [];
    if (options.systemPrompt) {
      messages.push({ role: 'system', content: options.systemPrompt });
    }
    messages.push({ role: 'user', content: options.prompt });

    const response = await withRetry(
      async () =>
        withRequestTimeout(
          () =>
            client.chat.completions.create({
              model: this.model,
              max_completion_tokens: maxTokens,
              temperature,
              messages,
              stream: false,
            }),
          { timeoutMs: requestTimeoutMs, label: `openai:${this.model}`, onTimeout: (info) => {
            const listener = getProviderTimeoutListener();
            if (listener) listener({ provider: 'openai', model: this.model, ...info });
          } },
        ),
      {
        onRetry: (attempt, delayMs) => {
          console.warn(`[openai-adapter] Retry ${attempt}, waiting ${delayMs / 1000}s...`);
        },
      },
    );

    const durationMs = Date.now() - start;
    const content = response.choices?.[0]?.message?.content ?? '';

    const usage: TokenUsage = {
      inputTokens: response.usage?.prompt_tokens ?? 0,
      outputTokens: response.usage?.completion_tokens ?? 0,
      costUsd: estimateCost(this.model, {
        inputTokens: response.usage?.prompt_tokens ?? 0,
        outputTokens: response.usage?.completion_tokens ?? 0,
      }, this.baseUrl),
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
