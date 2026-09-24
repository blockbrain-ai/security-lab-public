import { z } from 'zod';
import { computeConfigHash } from './verification-manifest.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export const VerificationStageModelSchema = z.object({
  provider: z.enum(['bounded_local', 'pi_cli', 'claude_code', 'codex_cli']),
  model: z.string(),
  baseUrl: z.string().optional(),
});

export type VerificationStageModel = z.infer<typeof VerificationStageModelSchema>;

export type VerificationStageKind =
  | 'source'
  | 'sourceCritic'
  | 'runtimeSetup'
  | 'runtimeProbe';

export interface ModelCapabilities {
  structuredJson: 'good' | 'mixed' | 'unknown';
  readOnlyTools: 'good' | 'mixed' | 'unsupported' | 'unknown';
  runtimeTools: 'good' | 'mixed' | 'unsupported' | 'unknown';
}

export interface LocalModelDescriptor {
  id: string;
  provider: 'bounded_local';
  model: string;
  baseUrl: string;
  capabilities: ModelCapabilities;
  recommendedStages: VerificationStageKind[];
  notes?: string;
}

export interface VerificationProfile {
  id: string;
  name: string;
  description: string;
  source: VerificationStageModel;
  runtime: VerificationStageModel;
  sourceCritic?: VerificationStageModel;
  runtimeSetup?: VerificationStageModel;
  runtimeProbe?: VerificationStageModel;
  tags: string[];
}

export interface ResolvedVerificationProfile {
  id: string | null;
  source: VerificationStageModel;
  sourceCritic: VerificationStageModel;
  runtime: VerificationStageModel;
  runtimeSetup: VerificationStageModel;
  runtimeProbe: VerificationStageModel;
}

// ---------------------------------------------------------------------------
// Model catalog (first wave)
// ---------------------------------------------------------------------------

export const LOCAL_MODEL_CATALOG: readonly LocalModelDescriptor[] = [
  {
    id: 'qwen27_local',
    provider: 'bounded_local',
    model: 'qwen3.6-27b',
    baseUrl: 'http://127.0.0.1:8080/v1',
    capabilities: {
      structuredJson: 'good',
      readOnlyTools: 'good',
      runtimeTools: 'good',
    },
    recommendedStages: ['source', 'sourceCritic', 'runtimeSetup', 'runtimeProbe'],
  },
  {
    id: 'r1_14b_local',
    provider: 'bounded_local',
    model: 'deepseek-r1:14b',
    baseUrl: 'http://127.0.0.1:11434/v1',
    capabilities: {
      structuredJson: 'mixed',
      readOnlyTools: 'mixed',
      runtimeTools: 'unsupported',
    },
    recommendedStages: ['source', 'sourceCritic'],
    notes: 'Reasoning comparator; keep out of runtime tool stages in wave 1',
  },
  {
    id: 'qwen14_local',
    provider: 'bounded_local',
    model: 'qwen3:14b',
    baseUrl: 'http://127.0.0.1:11434/v1',
    capabilities: {
      structuredJson: 'mixed',
      readOnlyTools: 'mixed',
      runtimeTools: 'unsupported',
    },
    recommendedStages: ['source', 'sourceCritic'],
  },
  {
    id: 'gemma12_local',
    provider: 'bounded_local',
    model: 'gemma3:12b',
    baseUrl: 'http://127.0.0.1:11434/v1',
    capabilities: {
      structuredJson: 'mixed',
      readOnlyTools: 'mixed',
      runtimeTools: 'unsupported',
    },
    recommendedStages: ['source', 'sourceCritic'],
  },
  {
    id: 'gemma4_26b_local',
    provider: 'bounded_local',
    model: 'gemma4:26b',
    baseUrl: 'http://127.0.0.1:11434/v1',
    capabilities: {
      structuredJson: 'unknown',
      readOnlyTools: 'unknown',
      runtimeTools: 'unsupported',
    },
    recommendedStages: ['source', 'sourceCritic'],
    notes: 'Gemma 4 workstation model with native function-calling and system role support. Source/critic only until benchmarked.',
  },
];

// ---------------------------------------------------------------------------
// Built-in profiles (first wave)
// ---------------------------------------------------------------------------

export const VERIFICATION_PROFILES: readonly VerificationProfile[] = [
  {
    id: 'qwen_default',
    name: 'Qwen default',
    description: 'Current bounded_local baseline: Qwen 3.6 27B everywhere',
    source: { provider: 'bounded_local', model: 'qwen3.6-27b', baseUrl: 'http://127.0.0.1:8080/v1' },
    runtime: { provider: 'bounded_local', model: 'qwen3.6-27b', baseUrl: 'http://127.0.0.1:8080/v1' },
    tags: ['baseline', 'qwen'],
  },
  {
    id: 'qwen_source_r1_critic',
    name: 'Qwen source + DeepSeek critic',
    description: 'Keep Qwen as primary source/runtime model, swap the defended-finding critic to DeepSeek-R1 14B',
    source: { provider: 'bounded_local', model: 'qwen3.6-27b', baseUrl: 'http://127.0.0.1:8080/v1' },
    sourceCritic: { provider: 'bounded_local', model: 'deepseek-r1:14b', baseUrl: 'http://127.0.0.1:11434/v1' },
    runtime: { provider: 'bounded_local', model: 'qwen3.6-27b', baseUrl: 'http://127.0.0.1:8080/v1' },
    tags: ['mixed', 'critic', 'deepseek'],
  },
  {
    id: 'r1_source_qwen_runtime',
    name: 'DeepSeek source + Qwen runtime',
    description: 'Use DeepSeek-R1 14B for source reasoning, keep Qwen for tool-heavy runtime verification',
    source: { provider: 'bounded_local', model: 'deepseek-r1:14b', baseUrl: 'http://127.0.0.1:11434/v1' },
    runtime: { provider: 'bounded_local', model: 'qwen3.6-27b', baseUrl: 'http://127.0.0.1:8080/v1' },
    tags: ['mixed', 'source', 'deepseek'],
  },
  {
    id: 'qwen14_source_qwen27_runtime',
    name: 'Qwen 14B source + Qwen 27B runtime',
    description: 'Same-family smaller source comparator',
    source: { provider: 'bounded_local', model: 'qwen3:14b', baseUrl: 'http://127.0.0.1:11434/v1' },
    runtime: { provider: 'bounded_local', model: 'qwen3.6-27b', baseUrl: 'http://127.0.0.1:8080/v1' },
    tags: ['qwen', 'same-family', 'smaller-source'],
  },
  {
    id: 'gemma_source_qwen_runtime',
    name: 'Gemma source + Qwen runtime',
    description: 'Lightweight source comparator, Qwen retained for runtime probing',
    source: { provider: 'bounded_local', model: 'gemma3:12b', baseUrl: 'http://127.0.0.1:11434/v1' },
    runtime: { provider: 'bounded_local', model: 'qwen3.6-27b', baseUrl: 'http://127.0.0.1:8080/v1' },
    tags: ['gemma', 'lightweight', 'source'],
  },
  {
    id: 'gemma4_source_qwen_runtime',
    name: 'Gemma 4 source + Qwen runtime',
    description: 'Gemma 4 26B as source verifier with native function-calling, Qwen retained for runtime',
    source: { provider: 'bounded_local', model: 'gemma4:26b', baseUrl: 'http://127.0.0.1:11434/v1' },
    runtime: { provider: 'bounded_local', model: 'qwen3.6-27b', baseUrl: 'http://127.0.0.1:8080/v1' },
    tags: ['gemma4', 'source', 'wave2'],
  },
  {
    id: 'qwen_source_gemma4_critic',
    name: 'Qwen source + Gemma 4 critic',
    description: 'Qwen as primary source verifier, Gemma 4 26B as defense-bypass critic',
    source: { provider: 'bounded_local', model: 'qwen3.6-27b', baseUrl: 'http://127.0.0.1:8080/v1' },
    sourceCritic: { provider: 'bounded_local', model: 'gemma4:26b', baseUrl: 'http://127.0.0.1:11434/v1' },
    runtime: { provider: 'bounded_local', model: 'qwen3.6-27b', baseUrl: 'http://127.0.0.1:8080/v1' },
    tags: ['gemma4', 'critic', 'wave2'],
  },
];

// ---------------------------------------------------------------------------
// Lookup functions
// ---------------------------------------------------------------------------

export function listVerificationProfiles(): VerificationProfile[] {
  return [...VERIFICATION_PROFILES];
}

export function listLocalModelDescriptors(): LocalModelDescriptor[] {
  return [...LOCAL_MODEL_CATALOG];
}

export function getVerificationProfile(id: string): VerificationProfile | null {
  return VERIFICATION_PROFILES.find((p) => p.id === id) ?? null;
}

// ---------------------------------------------------------------------------
// Profile resolution
// ---------------------------------------------------------------------------

export interface ProfileOverrides {
  sourceProvider?: string;
  sourceModel?: string;
  sourceBaseUrl?: string;
  sourceCriticProvider?: string;
  sourceCriticModel?: string;
  sourceCriticBaseUrl?: string;
  runtimeProvider?: string;
  runtimeModel?: string;
  runtimeBaseUrl?: string;
  runtimeSetupProvider?: string;
  runtimeSetupModel?: string;
  runtimeSetupBaseUrl?: string;
  runtimeProbeProvider?: string;
  runtimeProbeModel?: string;
  runtimeProbeBaseUrl?: string;
}

function applyOverrides(
  base: VerificationStageModel,
  provider?: string,
  model?: string,
  baseUrl?: string,
): VerificationStageModel {
  return {
    provider: (provider ?? base.provider) as VerificationStageModel['provider'],
    model: model ?? base.model,
    baseUrl: baseUrl ?? base.baseUrl,
  };
}

export function resolveVerificationProfile(
  profile: VerificationProfile | null,
  overrides: ProfileOverrides,
): ResolvedVerificationProfile {
  const defaultSource: VerificationStageModel = {
    provider: 'bounded_local',
    model: 'qwen3.6-27b',
    baseUrl: 'http://127.0.0.1:8080/v1',
  };
  const defaultRuntime: VerificationStageModel = {
    provider: 'bounded_local',
    model: 'qwen3.6-27b',
    baseUrl: 'http://127.0.0.1:8080/v1',
  };

  const baseSource = profile?.source ?? defaultSource;
  const baseRuntime = profile?.runtime ?? defaultRuntime;

  const source = applyOverrides(
    baseSource,
    overrides.sourceProvider,
    overrides.sourceModel,
    overrides.sourceBaseUrl,
  );

  const runtime = applyOverrides(
    baseRuntime,
    overrides.runtimeProvider,
    overrides.runtimeModel,
    overrides.runtimeBaseUrl,
  );

  const baseCritic = profile?.sourceCritic ?? source;
  const sourceCritic = applyOverrides(
    baseCritic,
    overrides.sourceCriticProvider,
    overrides.sourceCriticModel,
    overrides.sourceCriticBaseUrl,
  );

  const baseSetup = profile?.runtimeSetup ?? runtime;
  const runtimeSetup = applyOverrides(
    baseSetup,
    overrides.runtimeSetupProvider,
    overrides.runtimeSetupModel,
    overrides.runtimeSetupBaseUrl,
  );

  const baseProbe = profile?.runtimeProbe ?? runtime;
  const runtimeProbe = applyOverrides(
    baseProbe,
    overrides.runtimeProbeProvider,
    overrides.runtimeProbeModel,
    overrides.runtimeProbeBaseUrl,
  );

  return {
    id: profile?.id ?? null,
    source,
    sourceCritic,
    runtime,
    runtimeSetup,
    runtimeProbe,
  };
}

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

export function computeVerificationProfileFingerprint(
  resolved: ResolvedVerificationProfile,
): string {
  return computeConfigHash({
    lanes: {
      source: resolved.source,
      sourceCritic: resolved.sourceCritic,
      runtime: resolved.runtime,
      runtimeSetup: resolved.runtimeSetup,
      runtimeProbe: resolved.runtimeProbe,
    },
    mode: 'full',
  });
}
