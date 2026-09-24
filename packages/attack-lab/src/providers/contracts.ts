/**
 * Provider adapter contracts — provider-agnostic interface for invoking
 * Claude, GPT, Gemini, or any future model as planner, judge, or tribunal.
 */

import type { z } from 'zod';

// ---------------------------------------------------------------------------
// Token usage and cost
// ---------------------------------------------------------------------------

export interface TokenUsage {
  inputTokens: number;
  outputTokens: number;
  /** Estimated cost in USD for this invocation. */
  costUsd: number;
}

// ---------------------------------------------------------------------------
// Model response
// ---------------------------------------------------------------------------

export interface ToolTranscriptEntry {
  tool: string;
  args: Record<string, string>;
  output: string;
  durationMs?: number;
  exitCode?: number;
  truncated?: boolean;
}

export interface ModelResponse<T = unknown> {
  /** Raw text content from the model. */
  content: string;
  /** Parsed structured output if a schema was provided. */
  structured?: T;
  /** Token usage and cost. */
  usage: TokenUsage;
  /** Provider-specific session/thread ID for resumption. */
  sessionId?: string;
  /** Hash of the prompt content if the caller computed it. */
  promptHash?: string;
  /** Hash of the response content if the adapter computed it. */
  responseHash?: string;
  /** Wall-clock time for the invocation. */
  durationMs: number;
  /** Provider name (e.g. 'anthropic', 'openai', 'gemini'). */
  provider: string;
  /** Model identifier used. */
  model: string;
  /** Raw tool invocation transcripts — exact inputs and outputs. */
  toolTranscript?: ToolTranscriptEntry[];
}

// ---------------------------------------------------------------------------
// Model adapter interface
// ---------------------------------------------------------------------------

export interface ModelAdapter {
  /** Provider name. */
  readonly provider: string;
  /** Model identifier. */
  readonly model: string;
  /** Whether the adapter supports provider-native session/thread continuation. */
  readonly supportsNativeSessionResume?: boolean;
  /** Whether the adapter is executing against a local inference backend. */
  readonly isLocalInference?: boolean;

  /**
   * Invoke the model with a prompt. Optionally provide a Zod schema
   * to request structured output. The adapter handles provider-specific
   * structured output mechanics (tool_use, response_format, etc.).
   */
  invoke<T = unknown>(options: InvokeOptions<T>): Promise<ModelResponse<T>>;
}

export interface InvokeOptions<T = unknown> {
  /** System prompt (role context for the model). */
  systemPrompt?: string;
  /** User prompt (the actual request). */
  prompt: string;
  /** Optional Zod schema for structured output. */
  schema?: z.ZodType<T, z.ZodTypeDef, unknown>;
  /** Maximum tokens to generate. */
  maxTokens?: number;
  /** Temperature (0-1). */
  temperature?: number;
  /** Optional session ID for resumption. */
  sessionId?: string;
  /** Per-request timeout in milliseconds. @default 180000 */
  requestTimeoutMs?: number;
  /** Optional working directory for CLI-backed transports. */
  workingDirectory?: string;
  /** Optional additional writable/readable directories for CLI-backed transports. */
  additionalDirectories?: string[];
  /** Optional effort override for CLI-backed transports. */
  effort?: 'low' | 'medium' | 'high' | 'max';
  /**
   * Brief-mode: instead of packing heavy context into `prompt`, write the
   * decision context to disk and hand the worker a short pointer-style
   * prompt. The adapter MUST expose `artifactsDir` as a readable directory
   * so the worker can open `briefPath` and everything in `evidencePointers`.
   *
   * When `briefMode` is provided the caller is expected to keep `prompt`
   * short (≤ ~1 KB) — the worker builds its own context by reading files.
   * See docs/BRIEF-MODE.md (TODO) and the plan for full semantics.
   */
  briefMode?: BriefModeInvocation;
}

export interface BriefModeInvocation {
  /** Absolute path to the role/scope brief the worker should read first. */
  briefPath: string;
  /** Absolute path to the campaign/artifacts directory (added to --add-dir). */
  artifactsDir: string;
  /** Scope identifier — e.g. hypothesis id, finding id, iteration ref. */
  scopeId: string;
  /** Absolute paths to evidence the worker is expected to inspect. */
  evidencePointers: string[];
}

// ---------------------------------------------------------------------------
// Model configuration
// ---------------------------------------------------------------------------

export interface ModelConfig {
  provider: 'anthropic' | 'openai' | 'gemini' | 'claude_code' | 'codex_cli' | 'bounded_local' | 'pi_cli';
  model: string;
  maxTokens?: number;
  temperature?: number;
  requestTimeoutMs?: number;
  /** API key override (defaults to environment variable). */
  apiKey?: string;
  /** Base URL override for OpenAI-compatible servers (e.g. local llama-server). */
  baseUrl?: string;
  /** Whether this model runs locally and should be treated as zero-cost inference. */
  localInference?: boolean;
  /** Working directory for CLI-backed transports. */
  workingDirectory?: string;
  /** Additional writable/readable directories for CLI-backed transports. */
  additionalDirectories?: string[];
  /** Reasoning effort for CLI-backed transports. */
  effort?: 'low' | 'medium' | 'high' | 'max';
  /** Local open-source provider for Codex CLI (`--oss --local-provider`). */
  cliLocalProvider?: 'ollama' | 'lmstudio';
  /** Named Codex CLI profile from config.toml. */
  cliProfile?: string;
  /** Optional override path to the CLI binary (mainly for tests). */
  binaryPath?: string;
  /** Bounded local adapter config (maxTurns, readBudget, etc.). */
  boundedConfig?: BoundedLocalConfig;
  /** Pi CLI provider name in the generated models.json. */
  piProviderName?: string;
  /** Pi CLI config directory override (default: auto-generated isolated dir). */
  piConfigDir?: string;
  /** Pi CLI tool allowlist — passed as `--tools <comma-separated>`. */
  piToolAllowlist?: string[];
  /** Pi CLI maxTokens override for generated models.json (default: 16384). */
  piMaxTokens?: number;
  /** Pi CLI output mode flag (default: text via `-p`). */
  piOutputMode?: 'text' | 'json' | 'rpc';
}

export interface BoundedLocalConfig {
  maxTurns?: number;
  readBudget?: number;
  toolMaxTokens?: number;
  synthesisMaxTokens?: number;
  maxReadChars?: number;
  maxFileBytes?: number;
  maxContextChars?: number;
  disableThinking?: boolean;
  runtimeTools?: boolean;
  shellBudget?: number;
  httpBudget?: number;
  shellTimeoutMs?: number;
  shellMaxOutputChars?: number;
  shellPolicy?: 'source' | 'runtime';
  httpTimeoutMs?: number;
  httpMaxResponseChars?: number;
  allowedHttpHosts?: string[];
}

// ---------------------------------------------------------------------------
// Response archive record
// ---------------------------------------------------------------------------

export interface ArchivedResponse {
  /** Unique archive entry ID. */
  id: string;
  /** Timestamp. */
  at: string;
  /** Which role made this call. */
  role: 'planner' | 'counter_planner' | 'judge' | 'tribunal' | 'synthesizer' | 'reporter';
  /** Provider and model. */
  provider: string;
  model: string;
  /** The system prompt sent. */
  systemPrompt: string | null;
  /** The user prompt sent. */
  prompt: string;
  /** Raw response content. */
  responseContent: string;
  /** Structured output if parsed. */
  structuredOutput: unknown;
  /** Token usage. */
  usage: TokenUsage;
  /** Duration. */
  durationMs: number;
  /** Whether parsing succeeded. */
  parseSuccess: boolean;
  /** Optional native session/thread identifier. */
  sessionId?: string;
}
