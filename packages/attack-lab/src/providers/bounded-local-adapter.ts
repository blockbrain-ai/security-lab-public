import { readdir, readFile, stat } from 'node:fs/promises';
import { resolve, relative, join } from 'node:path';
import { spawn } from 'node:child_process';
import type { ModelAdapter, ModelConfig, ModelResponse, InvokeOptions, BoundedLocalConfig } from './contracts.js';
import { tryParseStructured } from './parse-structured.js';
import { WORKER_CONTRACT } from './worker-contract.js';

const DEFAULT_MAX_TURNS = 15;
const DEFAULT_READ_BUDGET = 15;
const DEFAULT_TOOL_MAX_TOKENS = 1_024;
const DEFAULT_SYNTHESIS_MAX_TOKENS = 2_048;
const DEFAULT_MAX_READ_CHARS = 12_000;
const DEFAULT_MAX_FILE_BYTES = 512_000;
const DEFAULT_MAX_CONTEXT_CHARS = 80_000;

const DEFAULT_SHELL_BUDGET = 25;
const DEFAULT_HTTP_BUDGET = 15;
const DEFAULT_SHELL_TIMEOUT_MS = 30_000;
const DEFAULT_SHELL_MAX_OUTPUT_CHARS = 8_000;
const DEFAULT_HTTP_TIMEOUT_MS = 10_000;
const DEFAULT_HTTP_MAX_RESPONSE_CHARS = 8_000;

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', '__pycache__', '.venv',
  '.next', '.nuxt', 'coverage', '.tox', 'venv',
]);

const TOOL_SCHEMAS = [
  {
    type: 'function' as const,
    function: {
      name: 'read_file',
      description: 'Read the contents of a file. Returns truncated content for large files.',
      parameters: {
        type: 'object',
        properties: {
          path: { type: 'string', description: 'File path relative to the working directory' },
        },
        required: ['path'],
      },
    },
  },
  {
    type: 'function' as const,
    function: {
      name: 'list_dir',
      description: 'List directory contents. Directories are listed first, then files.',
      parameters: {
        type: 'object',
        properties: {
          path: { type: 'string', description: 'Directory path relative to the working directory' },
        },
        required: ['path'],
      },
    },
  },
  {
    type: 'function' as const,
    function: {
      name: 'grep',
      description: 'Search for a regex pattern across files. Returns up to 50 matches with line numbers.',
      parameters: {
        type: 'object',
        properties: {
          pattern: { type: 'string', description: 'Regex pattern to search for' },
          path: { type: 'string', description: 'Directory to search in (default: working directory)' },
          glob: { type: 'string', description: 'File extension filter, e.g. "*.ts" (default: all files)' },
        },
        required: ['pattern'],
      },
    },
  },
];

const RUNTIME_TOOL_SCHEMAS = [
  {
    type: 'function' as const,
    function: {
      name: 'shell_exec',
      description: 'Execute a shell command. Use for Docker operations, service startup, log inspection, and running reproducers. Output is truncated. Commands time out after 30s by default. Do not use for broad file searches — use grep instead.',
      parameters: {
        type: 'object',
        properties: {
          command: { type: 'string', description: 'Shell command to execute (passed to /bin/sh -c)' },
          cwd: { type: 'string', description: 'Working directory (default: target repo root)' },
        },
        required: ['command'],
      },
    },
  },
  {
    type: 'function' as const,
    function: {
      name: 'http_request',
      description: 'Make an HTTP request to a local service (localhost/127.0.0.1 only). Use for probing endpoints after Docker/service startup. Prefer this over curl in shell_exec for HTTP probes.',
      parameters: {
        type: 'object',
        properties: {
          url: { type: 'string', description: 'URL to request (must be localhost or 127.0.0.1)' },
          method: { type: 'string', description: 'HTTP method: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS. Default: GET' },
          headers: { type: 'string', description: 'JSON string of headers, e.g. {"Authorization":"Bearer token"}' },
          body: { type: 'string', description: 'Request body (for POST/PUT/PATCH)' },
        },
        required: ['url'],
      },
    },
  },
];

interface ChatMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content?: string | null;
  tool_calls?: ToolCall[];
  tool_call_id?: string;
}

interface ToolCall {
  id: string;
  type: 'function';
  function: { name: string; arguments: string };
}

interface ChatCompletionResponse {
  choices: Array<{
    message: {
      role: string;
      content?: string | null;
      tool_calls?: ToolCall[];
    };
    finish_reason?: string;
  }>;
  usage?: {
    prompt_tokens?: number;
    completion_tokens?: number;
    total_tokens?: number;
  };
}

interface SynthesisResult {
  content?: string;
  inputTokens: number;
  outputTokens: number;
}

let fetchImpl: typeof globalThis.fetch = globalThis.fetch;

export function setFetchForTests(impl: typeof globalThis.fetch): void {
  fetchImpl = impl;
}

export class BoundedLocalAdapter implements ModelAdapter {
  readonly provider = 'bounded_local' as const;
  readonly model: string;
  readonly supportsNativeSessionResume = false;
  readonly isLocalInference = true;

  private readonly baseUrl: string;
  private readonly maxTokens: number;
  private readonly defaultRequestTimeoutMs: number;
  private readonly workingDirectory: string;
  private readonly allowedDirs: string[];
  private readonly maxTurns: number;
  private readonly readBudget: number;
  private readonly toolMaxTokens: number;
  private readonly synthesisMaxTokens: number;
  private readonly maxReadChars: number;
  private readonly maxFileBytes: number;
  private readonly maxContextChars: number;
  private readonly disableThinking: boolean;
  private readonly runtimeTools: boolean;
  private readonly shellBudget: number;
  private readonly httpBudget: number;
  private readonly shellTimeoutMs: number;
  private readonly shellMaxOutputChars: number;
  private readonly shellPolicy: 'source' | 'runtime';
  private readonly httpTimeoutMs: number;
  private readonly httpMaxResponseChars: number;
  private readonly allowedHttpHosts: string[];

  constructor(config: ModelConfig) {
    this.model = config.model;
    this.baseUrl = (config.baseUrl ?? 'http://127.0.0.1:8080/v1').replace(/\/+$/, '');
    this.maxTokens = config.maxTokens ?? 16_384;
    this.defaultRequestTimeoutMs = config.requestTimeoutMs ?? 900_000;
    this.workingDirectory = config.workingDirectory ?? process.cwd();
    this.allowedDirs = [
      resolve(this.workingDirectory),
      ...(config.additionalDirectories ?? []).map((d) => resolve(d)),
    ];

    const bc: BoundedLocalConfig = config.boundedConfig ?? {};
    this.maxTurns = bc.maxTurns ?? DEFAULT_MAX_TURNS;
    this.readBudget = bc.readBudget ?? DEFAULT_READ_BUDGET;
    this.toolMaxTokens = bc.toolMaxTokens ?? DEFAULT_TOOL_MAX_TOKENS;
    this.synthesisMaxTokens = bc.synthesisMaxTokens ?? DEFAULT_SYNTHESIS_MAX_TOKENS;
    this.maxReadChars = bc.maxReadChars ?? DEFAULT_MAX_READ_CHARS;
    this.maxFileBytes = bc.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
    this.maxContextChars = bc.maxContextChars ?? DEFAULT_MAX_CONTEXT_CHARS;
    this.disableThinking = bc.disableThinking ?? true;
    this.runtimeTools = bc.runtimeTools ?? false;
    this.shellBudget = bc.shellBudget ?? DEFAULT_SHELL_BUDGET;
    this.httpBudget = bc.httpBudget ?? DEFAULT_HTTP_BUDGET;
    this.shellTimeoutMs = bc.shellTimeoutMs ?? DEFAULT_SHELL_TIMEOUT_MS;
    this.shellMaxOutputChars = bc.shellMaxOutputChars ?? DEFAULT_SHELL_MAX_OUTPUT_CHARS;
    this.shellPolicy = bc.shellPolicy ?? 'source';
    this.httpTimeoutMs = bc.httpTimeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
    this.httpMaxResponseChars = bc.httpMaxResponseChars ?? DEFAULT_HTTP_MAX_RESPONSE_CHARS;
    this.allowedHttpHosts = bc.allowedHttpHosts ?? ['localhost', '127.0.0.1', '::1'];
  }

  async invoke<T = unknown>(options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    const startedAt = Date.now();
    const requestTimeoutMs = options.requestTimeoutMs ?? this.defaultRequestTimeoutMs;
    const workDir = options.workingDirectory ?? this.workingDirectory;

    const systemPrompt = buildSystemPrompt(options.systemPrompt, options.prompt, this.runtimeTools);
    const messages: ChatMessage[] = [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: options.prompt },
    ];

    const readCache = new Map<string, string>();
    let readCount = 0;
    let shellCount = 0;
    let httpCount = 0;
    let shellBudgetNotified = false;
    let httpBudgetNotified = false;
    let toolsDisabled = false;
    let totalInputTokens = 0;
    let totalOutputTokens = 0;
    let finalContent = '';
    const toolTranscript: import('./contracts.js').ToolTranscriptEntry[] = [];

    for (let turn = 0; turn < this.maxTurns; turn++) {
      trimOldToolResults(messages, this.maxContextChars);
      const requestedMaxTokens = options.maxTokens ?? this.maxTokens;
      const turnMaxTokens = toolsDisabled
        ? Math.min(requestedMaxTokens, this.synthesisMaxTokens)
        : Math.min(requestedMaxTokens, this.toolMaxTokens);

      const body: Record<string, unknown> = {
        model: this.model,
        messages,
        max_tokens: turnMaxTokens,
        temperature: options.temperature ?? 0.6,
      };

      if (!toolsDisabled) {
        body.tools = this.runtimeTools
          ? [...TOOL_SCHEMAS, ...this.getActiveRuntimeSchemas(shellCount, httpCount)]
          : TOOL_SCHEMAS;
      }

      if (this.disableThinking) {
        body.chat_template_kwargs = { enable_thinking: false };
      }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), requestTimeoutMs);

      let response: ChatCompletionResponse;
      try {
        const res = await fetchImpl(`${this.baseUrl}/chat/completions`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
          signal: controller.signal,
        });
        if (!res.ok) {
          const text = await res.text().catch(() => '');
          if (res.status === 500 && text.includes('Context size')) {
            toolsDisabled = true;
            trimOldToolResults(messages, this.maxContextChars * 0.5);
            messages.push({
              role: 'system',
              content: 'Context limit reached. Tools are disabled. Produce your final answer now using the information you have gathered.',
            });
            continue;
          }
          throw new Error(`bounded_local: HTTP ${res.status} from ${this.baseUrl}: ${text.slice(0, 500)}`);
        }
        response = (await res.json()) as ChatCompletionResponse;
      } finally {
        clearTimeout(timeout);
      }

      if (response.usage) {
        totalInputTokens += response.usage.prompt_tokens ?? 0;
        totalOutputTokens += response.usage.completion_tokens ?? 0;
      }

      const choice = response.choices?.[0];
      if (!choice) {
        break;
      }

      const assistantMsg: ChatMessage = { role: 'assistant' };
      if (choice.message.content) {
        assistantMsg.content = choice.message.content;
      }
      if (choice.message.tool_calls?.length) {
        assistantMsg.tool_calls = choice.message.tool_calls;
      }
      messages.push(assistantMsg);

      // Track any content the model produces — even alongside tool_calls.
      // Local models sometimes produce text explanations alongside tool calls.
      if (choice.message.content) {
        finalContent = choice.message.content;
      }

      if (!choice.message.tool_calls?.length) {
        break;
      }

      for (const toolCall of choice.message.tool_calls) {
        let args: Record<string, string>;
        try {
          args = JSON.parse(toolCall.function.arguments) as Record<string, string>;
        } catch {
          messages.push({
            role: 'tool',
            tool_call_id: toolCall.id,
            content: 'Error: malformed tool arguments',
          });
          continue;
        }

        let result: string;
        try {
          switch (toolCall.function.name) {
            case 'read_file':
              ({ result, readCount } = await this.executeReadFile(
                args['path'] ?? '', workDir, readCache, readCount,
              ));
              break;
            case 'list_dir':
              result = await this.executeListDir(args['path'] ?? '', workDir);
              break;
            case 'grep':
              result = await this.executeGrep(
                args['pattern'] ?? '', args['path'] ?? '', args['glob'] ?? '', workDir,
              );
              break;
            case 'shell_exec':
              result = await this.executeShellExec(args['command'] ?? '', args['cwd'] ?? '', workDir);
              shellCount++;
              break;
            case 'http_request':
              result = await this.executeHttpRequest(
                args['url'] ?? '', args['method'] ?? 'GET', args['headers'] ?? '', args['body'] ?? '',
              );
              httpCount++;
              break;
            default:
              result = `Error: unknown tool "${toolCall.function.name}"`;
          }
        } catch (err) {
          result = `Error: ${err instanceof Error ? err.message : String(err)}`;
        }

        const entry: import('./contracts.js').ToolTranscriptEntry = {
          tool: toolCall.function.name,
          args,
          output: result,
        };
        if (toolCall.function.name === 'shell_exec') {
          const exitMatch = result.match(/Exit code: (\d+)/);
          if (exitMatch) entry.exitCode = parseInt(exitMatch[1]!, 10);
          entry.truncated = result.includes('[TRUNCATED]');
        }
        toolTranscript.push(entry);

        messages.push({
          role: 'tool',
          tool_call_id: toolCall.id,
          content: result,
        });
      }

      if (this.runtimeTools && shellCount >= this.shellBudget && !shellBudgetNotified) {
        shellBudgetNotified = true;
        messages.push({
          role: 'system',
          content: `SHELL BUDGET EXHAUSTED: ${shellCount} shell commands used (limit ${this.shellBudget}). shell_exec is no longer available. Use remaining tools to finish verification.`,
        });
      }
      if (this.runtimeTools && httpCount >= this.httpBudget && !httpBudgetNotified) {
        httpBudgetNotified = true;
        messages.push({
          role: 'system',
          content: `HTTP BUDGET EXHAUSTED: ${httpCount} HTTP requests used (limit ${this.httpBudget}). http_request is no longer available. Use remaining tools to finish verification.`,
        });
      }

      const readBudgetExhausted = readCount >= this.readBudget;
      const runtimeBudgetsExhausted = !this.runtimeTools
        || (shellCount >= this.shellBudget && httpCount >= this.httpBudget);
      if (readBudgetExhausted && runtimeBudgetsExhausted && !toolsDisabled) {
        toolsDisabled = true;
        messages.push({
          role: 'system',
          content: 'ALL BUDGETS EXHAUSTED. Tools are now disabled. Produce your final answer using the information gathered.',
        });
      } else if (readBudgetExhausted && !this.runtimeTools && !toolsDisabled) {
        toolsDisabled = true;
        messages.push({
          role: 'system',
          content: `BUDGET EXHAUSTED: ${readCount} file reads used (limit ${this.readBudget}). Tools are now disabled. Produce your final answer using the information you have gathered.`,
        });
      }

      if (turn === this.maxTurns - 3 && !toolsDisabled) {
        toolsDisabled = true;
        messages.push({
          role: 'system',
          content: 'You have used most of your turns. Tools are now disabled. Produce your final JSON answer using the information gathered so far. Respond ONLY with the JSON object.',
        });
      }
    }

    if (!finalContent) {
      const lastAssistant = [...messages].reverse().find((m) => m.role === 'assistant' && m.content);
      finalContent = lastAssistant?.content ?? '';
    }

    if (shouldForceSynthesis(finalContent, messages)) {
      const synthResult = await this.forceSynthesis(
        messages, options, requestTimeoutMs,
      );
      totalInputTokens += synthResult.inputTokens;
      totalOutputTokens += synthResult.outputTokens;
      if (isBetterFinalAnswer(synthResult.content, finalContent)) {
        finalContent = synthResult.content!;
      }
    }

    const structured = tryParseStructured(finalContent, options.schema);
    const durationMs = Date.now() - startedAt;

    return {
      content: finalContent,
      structured,
      usage: {
        inputTokens: totalInputTokens,
        outputTokens: totalOutputTokens,
        costUsd: 0,
      },
      durationMs,
      provider: this.provider,
      model: this.model,
      toolTranscript: toolTranscript.length > 0 ? toolTranscript : undefined,
    };
  }

  private async forceSynthesis<T>(
    messages: ChatMessage[],
    options: InvokeOptions<T>,
    requestTimeoutMs: number,
  ): Promise<SynthesisResult> {
    const evidenceSummary = buildSynthesisEvidenceSummary(messages, Math.floor(this.maxContextChars * 0.45));
    if (!evidenceSummary) {
      return { content: undefined, inputTokens: 0, outputTokens: 0 };
    }

    const systemPrompt = buildSynthesisSystemPrompt(options.systemPrompt);
    const userPrompt = buildSynthesisUserPrompt(options.prompt, evidenceSummary);

    const body: Record<string, unknown> = {
      model: this.model,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
      max_tokens: Math.min(options.maxTokens ?? this.maxTokens, this.synthesisMaxTokens),
      temperature: 0.2,
    };

    if (this.disableThinking) {
      body.chat_template_kwargs = { enable_thinking: false };
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), requestTimeoutMs);

    try {
      const res = await fetchImpl(`${this.baseUrl}/chat/completions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      if (!res.ok) {
        const text = await res.text().catch(() => '');
        return {
          content: text || undefined,
          inputTokens: 0,
          outputTokens: 0,
        };
      }

      const response = (await res.json()) as ChatCompletionResponse;
      const choice = response.choices?.[0];
      return {
        content: choice?.message?.content ?? undefined,
        inputTokens: response.usage?.prompt_tokens ?? 0,
        outputTokens: response.usage?.completion_tokens ?? 0,
      };
    } catch {
      return { content: undefined, inputTokens: 0, outputTokens: 0 };
    } finally {
      clearTimeout(timeout);
    }
  }

  private resolveSandboxed(inputPath: string, workDir: string): string {
    const resolved = resolve(workDir, inputPath);
    const allowed = this.allowedDirs.some((dir) => resolved.startsWith(dir + '/') || resolved === dir);
    if (!allowed) {
      throw new Error(`Path outside sandbox: ${inputPath}`);
    }
    return resolved;
  }

  private async executeReadFile(
    filePath: string, workDir: string,
    cache: Map<string, string>, readCount: number,
  ): Promise<{ result: string; readCount: number }> {
    const resolved = this.resolveSandboxed(filePath, workDir);

    const cached = cache.get(resolved);
    if (cached !== undefined) {
      return { result: cached, readCount };
    }

    const fileStat = await stat(resolved);
    if (fileStat.size > this.maxFileBytes) {
      const msg = `File too large: ${fileStat.size} bytes (limit ${this.maxFileBytes})`;
      return { result: msg, readCount };
    }

    const buffer = await readFile(resolved);

    if (buffer.includes(0)) {
      return { result: 'Error: binary file, cannot read', readCount };
    }

    let content = buffer.toString('utf8');
    if (content.length > this.maxReadChars) {
      const headLen = Math.floor(this.maxReadChars * 0.6);
      const tailLen = this.maxReadChars - headLen;
      content = content.slice(0, headLen) +
        `\n\n... [${content.length - this.maxReadChars} chars truncated] ...\n\n` +
        content.slice(-tailLen);
    }

    cache.set(resolved, content);
    return { result: content, readCount: readCount + 1 };
  }

  private async executeListDir(dirPath: string, workDir: string): Promise<string> {
    const resolved = this.resolveSandboxed(dirPath || '.', workDir);
    const entries = await readdir(resolved, { withFileTypes: true });
    const dirs: string[] = [];
    const files: string[] = [];
    for (const entry of entries) {
      if (entry.isDirectory()) {
        dirs.push(entry.name + '/');
      } else {
        files.push(entry.name);
      }
    }
    dirs.sort();
    files.sort();
    return [...dirs, ...files].join('\n') || '(empty directory)';
  }

  private async executeGrep(
    pattern: string, searchPath: string, glob: string, workDir: string,
  ): Promise<string> {
    const resolved = this.resolveSandboxed(searchPath || '.', workDir);
    let regex: RegExp;
    try {
      regex = new RegExp(pattern, 'i');
    } catch {
      return `Error: invalid regex pattern "${pattern}"`;
    }

    const extFilter = glob ? glob.replace('*', '') : '';
    const matches: string[] = [];
    const maxMatches = 50;

    const walk = async (dir: string): Promise<void> => {
      if (matches.length >= maxMatches) return;
      let entries;
      try {
        entries = await readdir(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const entry of entries) {
        if (matches.length >= maxMatches) return;
        if (entry.isDirectory()) {
          if (!SKIP_DIRS.has(entry.name)) {
            await walk(join(dir, entry.name));
          }
        } else if (entry.isFile()) {
          if (extFilter && !entry.name.endsWith(extFilter)) continue;
          const filePath = join(dir, entry.name);
          try {
            const fileStat = await stat(filePath);
            if (fileStat.size > this.maxFileBytes) continue;
            const buf = await readFile(filePath);
            if (buf.includes(0)) continue;
            const text = buf.toString('utf8');
            const lines = text.split('\n');
            for (let i = 0; i < lines.length && matches.length < maxMatches; i++) {
              if (regex.test(lines[i]!)) {
                const relPath = relative(workDir, filePath);
                const line = lines[i]!.length > 200 ? lines[i]!.slice(0, 200) + '...' : lines[i]!;
                matches.push(`${relPath}:${i + 1}: ${line}`);
              }
            }
          } catch {
            // skip unreadable files
          }
        }
      }
    };

    await walk(resolved);
    return matches.length > 0
      ? matches.join('\n')
      : `No matches for /${pattern}/${extFilter ? ` in ${glob} files` : ''}`;
  }

  private getActiveRuntimeSchemas(
    shellCount: number, httpCount: number,
  ): typeof RUNTIME_TOOL_SCHEMAS {
    const schemas: typeof RUNTIME_TOOL_SCHEMAS[number][] = [];
    if (shellCount < this.shellBudget) {
      schemas.push(RUNTIME_TOOL_SCHEMAS[0]!);
    }
    if (httpCount < this.httpBudget) {
      schemas.push(RUNTIME_TOOL_SCHEMAS[1]!);
    }
    return schemas;
  }

  private async executeShellExec(
    command: string, cwd: string, workDir: string,
  ): Promise<string> {
    if (!this.runtimeTools) {
      return 'Error: shell_exec is not available (runtimeTools disabled)';
    }

    const blocked = validateRuntimeShellCommand(command, this.shellPolicy);
    if (blocked) return `Error: command blocked by runtime shell policy: ${blocked}`;

    const execCwd = cwd ? this.resolveSandboxed(cwd, workDir) : workDir;
    const timeoutMs = this.shellTimeoutMs;
    const maxOutput = this.shellMaxOutputChars;

    return new Promise<string>((resolvePromise) => {
      const child = spawn('/bin/sh', ['-c', command], {
        cwd: execCwd,
        env: { ...process.env },
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      let stdout = '';
      let stderr = '';
      let killed = false;

      const timer = setTimeout(() => {
        killed = true;
        child.kill('SIGKILL');
      }, timeoutMs);

      child.stdout?.on('data', (chunk: Buffer) => {
        stdout += chunk.toString('utf8');
        if (stdout.length > maxOutput * 2) {
          stdout = stdout.slice(-maxOutput);
        }
      });
      child.stderr?.on('data', (chunk: Buffer) => {
        stderr += chunk.toString('utf8');
        if (stderr.length > maxOutput * 2) {
          stderr = stderr.slice(-maxOutput);
        }
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        resolvePromise(formatShellOutput(stdout, stderr, code, killed, maxOutput));
      });
      child.on('error', (err) => {
        clearTimeout(timer);
        resolvePromise(`Error executing command: ${err.message}`);
      });
    });
  }

  private async executeHttpRequest(
    url: string, method: string, headersJson: string, body: string,
  ): Promise<string> {
    if (!this.runtimeTools) {
      return 'Error: http_request is not available (runtimeTools disabled)';
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(url);
    } catch {
      return 'Error: invalid URL';
    }

    const host = parsedUrl.hostname;
    if (!this.allowedHttpHosts.includes(host)) {
      return `Error: http_request only allows hosts: ${this.allowedHttpHosts.join(', ')}. Got: ${host}`;
    }

    let headers: Record<string, string> = {};
    if (headersJson) {
      try {
        headers = JSON.parse(headersJson) as Record<string, string>;
      } catch {
        return 'Error: headers must be a valid JSON object string';
      }
    }

    const upperMethod = method.toUpperCase();
    try {
      const fetchBody = ['POST', 'PUT', 'PATCH'].includes(upperMethod) ? body || undefined : undefined;
      const res = await fetchImpl(url, {
        method: upperMethod,
        headers,
        body: fetchBody,
        signal: AbortSignal.timeout(this.httpTimeoutMs),
      });

      let responseBody = await res.text();
      if (responseBody.length > this.httpMaxResponseChars) {
        responseBody = responseBody.slice(0, this.httpMaxResponseChars)
          + `\n[...${responseBody.length - this.httpMaxResponseChars} chars truncated]`;
      }

      const resHeaders: Record<string, string> = {};
      res.headers.forEach((v, k) => { resHeaders[k] = v; });

      return `HTTP ${res.status} ${res.statusText}\nHeaders: ${JSON.stringify(resHeaders)}\nBody:\n${responseBody}`;
    } catch (err) {
      return `Error: HTTP request failed: ${err instanceof Error ? err.message : String(err)}`;
    }
  }
}

// ---------------------------------------------------------------------------
// Runtime shell policy validation
// ---------------------------------------------------------------------------

const BLOCKED_SHELL_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /npm\s+run\s+(investigate|verify)/, reason: 'recursive Security Lab invocation' },
  { pattern: /tsx\s+src\/autonomous\//, reason: 'recursive Security Lab invocation' },
  { pattern: /\b(rm|rmdir)\b/, reason: 'destructive filesystem mutation' },
  { pattern: /\b(mv|cp)\s/, reason: 'destructive filesystem mutation' },
  { pattern: /\b(touch|chmod|chown|truncate|dd|mkfs|tee)\b/, reason: 'destructive filesystem mutation' },
  { pattern: /(?:^|[^-])(?:\s+>|>>|&>|\d+>)(?!\s*\/dev\/null)(?!\s*&\d)[^>&|]/, reason: 'shell write redirection' },
  { pattern: /\bgit\s+(checkout|switch|reset|restore|clean|commit|merge|rebase|pull|push)\b/, reason: 'destructive git operation' },
  { pattern: /\b(npm|pnpm|yarn)\s+(install|add|update|remove)\b/, reason: 'host package mutation' },
  { pattern: /\b(pip|pip3)\s+install\b/, reason: 'host package mutation' },
  { pattern: /\b(poetry|uv|cargo)\s+(add|install)\b/, reason: 'host package mutation' },
  { pattern: /\b(go\s+get)\b/, reason: 'host package mutation' },
  { pattern: /\b(brew|apt|apt-get|apk|yum|dnf)\s/, reason: 'host package manager' },
  { pattern: /\b(nmap|ssh|scp)\b/, reason: 'external network tool' },
];

const BLOCKED_EXTERNAL_NETWORK: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /\b(curl|wget|nc)\s/, reason: 'external network probe from shell' },
];

function isLoopbackTarget(command: string): boolean {
  return /\b(localhost|127\.0\.0\.1|::1|0\.0\.0\.0)\b/.test(command);
}

export function validateRuntimeShellCommand(
  command: string, policy: 'source' | 'runtime',
): string | null {
  for (const { pattern, reason } of BLOCKED_SHELL_PATTERNS) {
    if (pattern.test(command)) return reason;
  }

  if (policy === 'source') {
    if (/\b(docker|docker-compose)\b/.test(command)) {
      return 'Docker commands not allowed in source verification mode';
    }
  }

  for (const { pattern, reason } of BLOCKED_EXTERNAL_NETWORK) {
    if (pattern.test(command) && !isLoopbackTarget(command)) {
      return reason;
    }
  }

  if (/\bfind\s+\/\s/.test(command) && !/\bfind\s+\/tmp/.test(command)) {
    return 'broad filesystem search (use find with a specific directory)';
  }

  return null;
}

// ---------------------------------------------------------------------------
// Shell output formatting
// ---------------------------------------------------------------------------

function formatShellOutput(
  stdout: string, stderr: string,
  exitCode: number | null, killed: boolean,
  maxChars: number,
): string {
  const parts: string[] = [];
  if (killed) parts.push('[TIMEOUT — command killed]');
  parts.push(`Exit code: ${exitCode ?? -1}`);

  if (stdout.trim()) {
    let out = stdout.trim();
    if (out.length > maxChars) {
      const head = Math.floor(maxChars * 0.6);
      const tail = maxChars - head;
      out = out.slice(0, head)
        + `\n[...${out.length - head - tail} chars truncated...]\n`
        + out.slice(-tail);
    }
    parts.push(`STDOUT:\n${out}`);
  }

  if (stderr.trim()) {
    let err = stderr.trim();
    const stderrMax = Math.floor(maxChars * 0.5);
    if (err.length > stderrMax) {
      err = err.slice(0, stderrMax) + '\n[stderr truncated]';
    }
    parts.push(`STDERR:\n${err}`);
  }

  return parts.join('\n');
}

function estimateMessageChars(messages: ChatMessage[]): number {
  let total = 0;
  for (const msg of messages) {
    total += msg.content?.length ?? 0;
    if (msg.tool_calls) {
      for (const tc of msg.tool_calls) {
        total += tc.function.name.length + tc.function.arguments.length + 50;
      }
    }
  }
  return total;
}

function trimOldToolResults(messages: ChatMessage[], maxChars: number): void {
  if (estimateMessageChars(messages) <= maxChars) return;
  for (let i = 0; i < messages.length; i++) {
    if (estimateMessageChars(messages) <= maxChars) break;
    const msg = messages[i]!;
    if (msg.role === 'tool' && msg.content && msg.content.length > 200) {
      msg.content = msg.content.slice(0, 100) + '\n[truncated — context budget]';
    }
  }
}

function shouldForceSynthesis(content: string, messages: ChatMessage[]): boolean {
  if (messages.length <= 2) return false;
  const trimmed = content.trim();
  if (!trimmed) return true;
  if (/<tool_call>|<function=|<\/tool_call>/i.test(trimmed)) return true;
  if (trimmed.startsWith('```json') || trimmed.startsWith('{')) return false;
  if (trimmed.includes('"newSignals"') || trimmed.includes('"probeRequests"') || trimmed.includes('"reasoning"')) return false;
  return !(trimmed.includes('{') && trimmed.includes('}'));
}

function isBetterFinalAnswer(candidate: string | undefined, previous: string): boolean {
  if (!candidate?.trim()) return false;
  const trimmed = candidate.trim();
  if (/<tool_call>|<function=|<\/tool_call>/i.test(trimmed)) return false;
  if (trimmed.startsWith('{') || trimmed.startsWith('```json')) return true;
  if (trimmed.includes('"newSignals"') || trimmed.includes('"probeRequests"') || trimmed.includes('"reasoning"')) return true;
  return previous.trim().length === 0;
}

function buildSynthesisSystemPrompt(systemPrompt: string | undefined): string {
  const parts = [
    WORKER_CONTRACT,
    '',
    'You are in final synthesis mode.',
    'The tool-use phase is over. Tools are unavailable.',
    'Do NOT emit <tool_call>, <function>, XML, or requests to read more files.',
    'Respond with the final JSON answer only.',
    'If evidence is incomplete, use empty arrays where appropriate and explain the uncertainty in the reasoning field.',
  ];
  if (systemPrompt?.trim()) {
    parts.push('', systemPrompt.trim());
  }
  return parts.join('\n');
}

function buildSynthesisUserPrompt(originalPrompt: string, evidenceSummary: string): string {
  return [
    'Produce the final answer from the already-collected evidence below.',
    'Do not ask for more exploration. Do not output tool calls.',
    'Your response must start with `{` or a ```json code fence and contain the final answer only.',
    '',
    'Original task and instructions (compressed):',
    summarizeForSynthesis(originalPrompt, 4_000),
    '',
    'Evidence collected during the tool-use phase:',
    evidenceSummary,
    '',
    'Return the final JSON now.',
  ].join('\n');
}

function buildSynthesisEvidenceSummary(messages: ChatMessage[], maxChars: number): string {
  const relevant = messages
    .filter((msg) => msg.role === 'tool' || msg.role === 'assistant')
    .slice(-18);

  const parts: string[] = [];
  for (const msg of relevant) {
    if (msg.role === 'assistant' && msg.tool_calls?.length) {
      for (const call of msg.tool_calls) {
        parts.push(`Tool request: ${call.function.name} ${summarizeForSynthesis(call.function.arguments, 240)}`);
      }
      continue;
    }

    if (msg.role === 'assistant' && msg.content?.trim()) {
      const normalized = msg.content.trim();
      if (!/<tool_call>|<function=|<\/tool_call>/i.test(normalized)) {
        parts.push(`Assistant note: ${summarizeForSynthesis(normalized, 600)}`);
      }
      continue;
    }

    if (msg.role === 'tool' && msg.content?.trim()) {
      parts.push(`Tool result:\n${summarizeToolResult(msg.content, 1_400)}`);
    }
  }

  if (parts.length === 0) return '';

  let summary = parts.join('\n\n');
  if (summary.length > maxChars) {
    summary = summarizeForSynthesis(summary, maxChars);
  }
  return summary;
}

function summarizeToolResult(content: string, maxChars: number): string {
  const lines = content
    .split('\n')
    .map((line) => line.trimEnd())
    .filter(Boolean)
    .slice(0, 20);
  return summarizeForSynthesis(lines.join('\n'), maxChars);
}

function summarizeForSynthesis(content: string, maxChars: number): string {
  if (content.length <= maxChars) return content;
  const headLen = Math.max(400, Math.floor(maxChars * 0.35));
  const tailLen = Math.max(400, maxChars - headLen - 64);
  return (
    content.slice(0, headLen) +
    `\n\n... [${content.length - headLen - tailLen} chars omitted] ...\n\n` +
    content.slice(-tailLen)
  );
}

function buildSystemPrompt(systemPrompt: string | undefined, _prompt: string, runtimeTools: boolean): string {
  const toolList = runtimeTools
    ? 'You have access to five tools: read_file, list_dir, grep, shell_exec, http_request.'
    : 'You have access to three tools: read_file, list_dir, grep.';

  const strategy = runtimeTools
    ? [
      'Strategy:',
      '- You have a limited budget for each tool. Be deliberate — plan before executing.',
      '- Use shell_exec for Docker/service management, log inspection, and running reproducers.',
      '- Use http_request for probing HTTP endpoints. Prefer http_request over curl for HTTP probes.',
      '- Do not use shell_exec for broad file searches — use grep and read_file.',
      '- Do not edit files, install packages on the host, or run git mutation commands.',
      '- After probing, synthesize your findings. Do not keep probing variants once you have a clear result.',
      '- When tools are disabled, answer with what you have.',
    ]
    : [
      'Strategy:',
      '- Start with list_dir and grep to orient, then read_file for specifics.',
      '- Prefer depth over breadth. Read fewer files carefully rather than many files shallowly.',
      '- After using ~60% of your budget, stop gathering and start synthesizing.',
      '- When tools are disabled, answer with what you have. Do not apologize for incomplete coverage.',
    ];

  const parts = [
    WORKER_CONTRACT,
    '',
    toolList,
    'Use them to explore the target codebase and answer the question.',
    '',
    ...strategy,
    '',
    'CRITICAL: Your final response must be valid JSON matching the schema specified in the prompt.',
    'Do not describe what you would do. Do not list probe requests. Produce the JSON directly.',
    'When the prompt asks for JSON output, respond ONLY with the JSON object — no prose, no markdown fences.',
  ];
  if (systemPrompt?.trim()) {
    parts.push('', systemPrompt.trim());
  }
  return parts.join('\n');
}
