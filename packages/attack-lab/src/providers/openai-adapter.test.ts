import test from 'node:test';
import assert from 'node:assert/strict';
import { OpenAIAdapter, setOpenAIClientFactoryForTests } from './openai-adapter.js';

test('OpenAIAdapter uses local defaults for OpenAI-compatible base URLs and records zero cost', async () => {
  const previousOpenAI = process.env['OPENAI_API_KEY'];
  delete process.env['OPENAI_API_KEY'];

  setOpenAIClientFactoryForTests(async (config) => {
    assert.equal(config.apiKey, 'local');
    assert.equal(config.baseURL, 'http://localhost:8080/v1');

    return {
      chat: {
        completions: {
          async create(params) {
            assert.equal(params.model, 'qwen3.6-32b');
            assert.equal(params.max_completion_tokens, 16_384);
            assert.equal(params.temperature, 0.1);
            assert.deepEqual(params.messages, [
              { role: 'system', content: 'system prompt' },
              { role: 'user', content: 'test prompt' },
            ]);
            return {
              choices: [{ message: { content: '{"verdict":"confirmed_finding"}' } }],
              usage: {
                prompt_tokens: 120,
                completion_tokens: 80,
              },
            };
          },
        },
      },
    };
  });

  try {
    const adapter = new OpenAIAdapter({
      provider: 'openai',
      model: 'qwen3.6-32b',
      baseUrl: 'http://localhost:8080/v1',
      maxTokens: 16_384,
      temperature: 0.1,
      requestTimeoutMs: 1000,
    });
    const response = await adapter.invoke({
      prompt: 'test prompt',
      systemPrompt: 'system prompt',
    });

    assert.equal(response.provider, 'openai');
    assert.equal(response.model, 'qwen3.6-32b');
    assert.equal(response.content, '{"verdict":"confirmed_finding"}');
    assert.equal(response.usage.inputTokens, 120);
    assert.equal(response.usage.outputTokens, 80);
    assert.equal(response.usage.costUsd, 0);
  } finally {
    setOpenAIClientFactoryForTests(null);
    if (previousOpenAI == null) {
      delete process.env['OPENAI_API_KEY'];
    } else {
      process.env['OPENAI_API_KEY'] = previousOpenAI;
    }
  }
});

test('OpenAIAdapter keeps hosted pricing when no base URL override is configured', async () => {
  const previousOpenAI = process.env['OPENAI_API_KEY'];
  process.env['OPENAI_API_KEY'] = 'test-openai-key';

  setOpenAIClientFactoryForTests(async (config) => {
    assert.equal(config.apiKey, 'test-openai-key');
    assert.equal(config.baseURL, undefined);

    return {
      chat: {
        completions: {
          async create() {
            return {
              choices: [{ message: { content: 'ok' } }],
              usage: {
                prompt_tokens: 1_000,
                completion_tokens: 500,
              },
            };
          },
        },
      },
    };
  });

  try {
    const adapter = new OpenAIAdapter({
      provider: 'openai',
      model: 'gpt-4o-mini',
      requestTimeoutMs: 1000,
    });
    const response = await adapter.invoke({ prompt: 'test prompt' });

    assert.ok(response.usage.costUsd > 0);
  } finally {
    setOpenAIClientFactoryForTests(null);
    if (previousOpenAI == null) {
      delete process.env['OPENAI_API_KEY'];
    } else {
      process.env['OPENAI_API_KEY'] = previousOpenAI;
    }
  }
});
