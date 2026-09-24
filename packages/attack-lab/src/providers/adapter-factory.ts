/**
 * Factory function for creating model adapters from configuration.
 */

import type { ModelAdapter, ModelConfig } from './contracts.js';
import { ClaudeAdapter } from './claude-adapter.js';
import { ClaudeCodeAdapter } from './claude-code-adapter.js';
import { OpenAIAdapter } from './openai-adapter.js';
import { GeminiAdapter } from './gemini-adapter.js';
import { CodexCliAdapter } from './codex-cli-adapter.js';
import { BoundedLocalAdapter } from './bounded-local-adapter.js';
import { PiCliAdapter } from './pi-cli-adapter.js';
import { UnavailableAdapter } from './unavailable-adapter.js';
import {
  type HostExecutionPolicy,
  hostExecutionRefusal,
  isHostExecutingProvider,
  resolveHostExecutionPolicy,
} from './execution-policy.js';

/**
 * Create an adapter for the configured provider.
 *
 * Host-executing providers (CLI coding agents, bounded-local shell) are refused
 * unless the operator opted in — see execution-policy.ts. A refusal yields an
 * UnavailableAdapter so the caller degrades honestly instead of silently
 * spawning an unsandboxed agent.
 */
export function createAdapter(
  config: ModelConfig,
  options: { hostExecution?: HostExecutionPolicy } = {},
): ModelAdapter {
  const policy = options.hostExecution ?? resolveHostExecutionPolicy();
  if (isHostExecutingProvider(config.provider) && !policy.allowed) {
    const reason = hostExecutionRefusal(config.provider);
    process.stderr.write(`[security-lab] ${reason}\n`);
    return new UnavailableAdapter(config.model, reason);
  }

  switch (config.provider) {
    case 'anthropic':
      return new ClaudeAdapter(config);
    case 'claude_code':
      return new ClaudeCodeAdapter(config);
    case 'openai':
      return new OpenAIAdapter(config);
    case 'gemini':
      return new GeminiAdapter(config);
    case 'codex_cli':
      return new CodexCliAdapter(config);
    case 'bounded_local':
      return new BoundedLocalAdapter(config);
    case 'pi_cli':
      return new PiCliAdapter(config);
    default: {
      const _exhaustive: never = config.provider;
      throw new Error(`Unknown provider: ${_exhaustive}`);
    }
  }
}
