/**
 * Gemini model adapter — uses the Google Generative AI SDK.
 */

import type { ModelAdapter, ModelConfig, ModelResponse, InvokeOptions, TokenUsage } from './contracts.js';
import { withRetry } from './retry.js';
import { withRequestTimeout, getProviderTimeoutListener } from './timeout.js';
import { tryParseStructured } from './parse-structured.js';

const COST_TABLE: Record<string, { input: number; output: number }> = {
  'gemini-3.1-pro': { input: 1.25, output: 5 },
  'gemini-3.1-pro-preview': { input: 1.25, output: 5 },
  'gemini-2.5-flash': { input: 0.075, output: 0.3 },
  'gemini-2.5-flash-lite': { input: 0.02, output: 0.1 },
};

function estimateCost(model: string, usage: { inputTokens: number; outputTokens: number }): number {
  const rates = COST_TABLE[model] ?? { input: 1.25, output: 5 };
  return (usage.inputTokens * rates.input + usage.outputTokens * rates.output) / 1_000_000;
}

interface GeminiUsageMetadata {
  promptTokenCount?: number;
  candidatesTokenCount?: number;
}

interface GeminiResponseLike {
  text(): string;
  usageMetadata?: GeminiUsageMetadata;
}

interface GeminiModelLike {
  generateContent(prompt: string): Promise<{ response: GeminiResponseLike }>;
}

interface GeminiClientLike {
  getGenerativeModel(config: {
    model: string;
    generationConfig: {
      maxOutputTokens: number;
      temperature: number;
    };
    systemInstruction?: string;
  }): GeminiModelLike;
}

let geminiClientFactory: ((apiKey: string) => Promise<GeminiClientLike>) | null = null;

async function createGeminiClient(apiKey: string): Promise<GeminiClientLike> {
  if (geminiClientFactory) {
    return geminiClientFactory(apiKey);
  }

  const { GoogleGenerativeAI } = await import('@google/generative-ai');
  return new GoogleGenerativeAI(apiKey) as unknown as GeminiClientLike;
}

export function setGeminiClientFactoryForTests(
  factory: ((apiKey: string) => Promise<GeminiClientLike>) | null,
): void {
  geminiClientFactory = factory;
}

export class GeminiAdapter implements ModelAdapter {
  readonly provider = 'gemini';
  readonly model: string;
  readonly supportsNativeSessionResume = false;
  private readonly apiKey: string;
  private readonly defaultMaxTokens: number;
  private readonly defaultTemperature: number;
  private readonly defaultRequestTimeoutMs: number;

  constructor(config: ModelConfig) {
    this.model = normalizeModelName(config.model);
    this.apiKey = config.apiKey ?? process.env['GOOGLE_AI_API_KEY'] ?? process.env['GEMINI_API_KEY'] ?? '';
    this.defaultMaxTokens = config.maxTokens ?? 4096;
    this.defaultTemperature = config.temperature ?? 0;
    this.defaultRequestTimeoutMs = config.requestTimeoutMs ?? 180_000;

    if (!this.apiKey) {
      throw new Error('GeminiAdapter: GOOGLE_AI_API_KEY is required');
    }
  }

  async invoke<T = unknown>(options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    const genAI = await createGeminiClient(this.apiKey);
    const maxTokens = options.maxTokens ?? this.defaultMaxTokens;
    const temperature = options.temperature ?? this.defaultTemperature;
    const requestTimeoutMs = options.requestTimeoutMs ?? this.defaultRequestTimeoutMs;

    const start = Date.now();

    const model = genAI.getGenerativeModel({
      model: this.model,
      generationConfig: {
        maxOutputTokens: maxTokens,
        temperature,
      },
      systemInstruction: options.systemPrompt ?? undefined,
    });

    const result = await withRetry(
      async () =>
        withRequestTimeout(
          () => model.generateContent(options.prompt),
          { timeoutMs: requestTimeoutMs, label: `gemini:${this.model}`, onTimeout: (info) => {
            const listener = getProviderTimeoutListener();
            if (listener) listener({ provider: 'gemini', model: this.model, ...info });
          } },
        ),
      {
        onRetry: (attempt, delayMs) => {
          console.warn(`[gemini-adapter] Retry ${attempt}, waiting ${delayMs / 1000}s...`);
        },
      },
    );

    const durationMs = Date.now() - start;
    const response = result.response;
    const content = response.text();

    const usageMeta = response.usageMetadata;
    const usage: TokenUsage = {
      inputTokens: usageMeta?.promptTokenCount ?? 0,
      outputTokens: usageMeta?.candidatesTokenCount ?? 0,
      costUsd: estimateCost(this.model, {
        inputTokens: usageMeta?.promptTokenCount ?? 0,
        outputTokens: usageMeta?.candidatesTokenCount ?? 0,
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

function normalizeModelName(model: string): string {
  return model.startsWith('models/') ? model.slice('models/'.length) : model;
}
