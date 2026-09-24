import test from 'node:test';
import assert from 'node:assert/strict';
import { GeminiAdapter, setGeminiClientFactoryForTests } from './gemini-adapter.js';

test('GeminiAdapter normalizes model names and accepts GEMINI_API_KEY alias', () => {
  const previousGoogle = process.env['GOOGLE_AI_API_KEY'];
  const previousGemini = process.env['GEMINI_API_KEY'];

  delete process.env['GOOGLE_AI_API_KEY'];
  process.env['GEMINI_API_KEY'] = 'test-gemini-key';

  try {
    const adapter = new GeminiAdapter({
      provider: 'gemini',
      model: 'models/gemini-3.1-pro-preview',
    });
    assert.equal(adapter.model, 'gemini-3.1-pro-preview');
  } finally {
    if (previousGoogle == null) {
      delete process.env['GOOGLE_AI_API_KEY'];
    } else {
      process.env['GOOGLE_AI_API_KEY'] = previousGoogle;
    }
    if (previousGemini == null) {
      delete process.env['GEMINI_API_KEY'];
    } else {
      process.env['GEMINI_API_KEY'] = previousGemini;
    }
  }
});

test('GeminiAdapter invoke uses the configured client factory and returns structured usage', async () => {
  const previousGoogle = process.env['GOOGLE_AI_API_KEY'];
  process.env['GOOGLE_AI_API_KEY'] = 'test-gemini-key';

  setGeminiClientFactoryForTests(async (apiKey) => {
    assert.equal(apiKey, 'test-gemini-key');
    return {
      getGenerativeModel(config) {
        assert.equal(config.model, 'gemini-3.1-pro-preview');
        assert.equal(config.generationConfig.maxOutputTokens, 256);
        assert.equal(config.generationConfig.temperature, 0.2);
        assert.equal(config.systemInstruction, 'system prompt');
        return {
          async generateContent(prompt) {
            assert.equal(prompt, 'test prompt');
            return {
              response: {
                text: () => '{"verdict":"confirmed_finding"}',
                usageMetadata: {
                  promptTokenCount: 120,
                  candidatesTokenCount: 80,
                },
              },
            };
          },
        };
      },
    };
  });

  try {
    const adapter = new GeminiAdapter({
      provider: 'gemini',
      model: 'gemini-3.1-pro-preview',
      maxTokens: 256,
      temperature: 0.2,
      requestTimeoutMs: 1000,
    });
    const response = await adapter.invoke({
      prompt: 'test prompt',
      systemPrompt: 'system prompt',
      schema: undefined,
    });
    assert.equal(response.provider, 'gemini');
    assert.equal(response.model, 'gemini-3.1-pro-preview');
    assert.equal(response.content, '{"verdict":"confirmed_finding"}');
    assert.equal(response.structured, undefined);
    assert.equal(response.usage.inputTokens, 120);
    assert.equal(response.usage.outputTokens, 80);
    assert.ok(response.usage.costUsd > 0);
  } finally {
    setGeminiClientFactoryForTests(null);
    if (previousGoogle == null) {
      delete process.env['GOOGLE_AI_API_KEY'];
    } else {
      process.env['GOOGLE_AI_API_KEY'] = previousGoogle;
    }
  }
});
