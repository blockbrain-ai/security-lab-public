import type { ModelConfig } from '../providers/contracts.js';

type WorkerProviderOverride = Extract<ModelConfig['provider'], 'claude_code' | 'codex_cli'>;

export interface RoleConfigOverrides {
  providerOverride?: ModelConfig['provider'];
  workerProviderOverride?: WorkerProviderOverride;
  modelOverride?: string;
  baseUrlOverride?: string;
  maxTokensOverride?: number;
  localInferenceOverride?: boolean;
  cliLocalProviderOverride?: ModelConfig['cliLocalProvider'];
  cliProfileOverride?: string;
  requestTimeoutMs?: number;
  workingDirectory: string;
  additionalDirectories: string[];
}

export function resolveRoleConfig(baseConfig: ModelConfig, overrides: RoleConfigOverrides): ModelConfig {
  const provider = overrides.providerOverride ?? overrides.workerProviderOverride ?? baseConfig.provider;
  const model = overrides.modelOverride ?? baseConfig.model;
  const preserveProfileTransportDefaults =
    provider === baseConfig.provider &&
    model === baseConfig.model &&
    overrides.baseUrlOverride === undefined &&
    overrides.maxTokensOverride === undefined &&
    overrides.localInferenceOverride === undefined &&
    overrides.cliLocalProviderOverride === undefined &&
    overrides.cliProfileOverride === undefined;

  const config: ModelConfig = {
    ...baseConfig,
    provider,
    model,
    requestTimeoutMs: overrides.requestTimeoutMs ?? baseConfig.requestTimeoutMs,
    workingDirectory: overrides.workingDirectory,
    additionalDirectories: overrides.additionalDirectories,
  };

  if (overrides.baseUrlOverride !== undefined) {
    config.baseUrl = overrides.baseUrlOverride;
  } else if (!preserveProfileTransportDefaults) {
    delete config.baseUrl;
  }

  if (overrides.maxTokensOverride !== undefined) {
    config.maxTokens = overrides.maxTokensOverride;
  } else if (!preserveProfileTransportDefaults) {
    delete config.maxTokens;
  }

  if (overrides.localInferenceOverride !== undefined) {
    config.localInference = overrides.localInferenceOverride;
  } else if (!preserveProfileTransportDefaults) {
    delete config.localInference;
  }

  if (overrides.cliLocalProviderOverride !== undefined) {
    config.cliLocalProvider = overrides.cliLocalProviderOverride;
  } else if (!preserveProfileTransportDefaults) {
    delete config.cliLocalProvider;
  }

  if (overrides.cliProfileOverride !== undefined) {
    config.cliProfile = overrides.cliProfileOverride;
  } else if (!preserveProfileTransportDefaults) {
    delete config.cliProfile;
  }

  return config;
}
