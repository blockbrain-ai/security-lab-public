import { statSync as fsStatSync } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import { basename, dirname, isAbsolute, resolve } from 'node:path';
import YAML from 'yaml';
import { z } from 'zod';
import type { EnvironmentTier } from '../../../evidence-plane/src/contracts.js';
import { getAttackLabRoot } from '../loaders/runfile-loader.js';
import {
  type BrowserCapability,
  DEFAULT_BROWSER_CAPABILITY,
} from '../verification/browser/browser-runner.js';
import {
  DEFAULT_ADAPTIVE_EXPLORATION_CONFIG,
  type AdaptiveExplorationConfig,
} from '../verification/local-live/contracts.js';
import {
  DEFAULT_MYTHOS_CONFIG,
  type MythosExplorationConfig,
} from '../verification/local-live/mythos-exploration-sublane.js';

/**
 * Section 6.1 — Zod schema for `liveProbing.adaptiveExploration`. Validated
 * at the target-profile trust boundary so the runner gets a typed config
 * instead of parsing raw records (SL1).
 */
const AdaptiveExplorationConfigSchema = z
  .object({
    enabled: z.boolean().optional(),
    maxFollowupsPerSurprise: z.number().int().optional(),
    maxMidRoundHypotheses: z.number().int().optional(),
  })
  .optional();

/**
 * Section 6.2 — Zod schema for `liveProbing.mythos`.
 */
const MythosConfigSchema = z
  .object({
    enabled: z.boolean().optional(),
    timeBudgetMs: z.number().int().positive().optional(),
    probeBudget: z.number().int().positive().optional(),
    invocationsPerCampaign: z.number().int().nonnegative().optional(),
    sourceCorrelation: z
      .object({
        enabled: z.boolean().optional(),
        max: z.number().int().nonnegative().optional(),
      })
      .optional(),
  })
  .optional();

/**
 * Section 11.2 — Zod schema for `liveProbing.probeFamilies`. Targets can
 * declare which probe families they support and provide overrides.
 */
const ProbeFamilyCapabilitySchema = z
  .object({
    family: z.string().min(1),
    disabledVariants: z.array(z.string()).optional(),
    extraHeaders: z.record(z.string()).optional(),
  })
  .passthrough();

const LiveProbingSchema = z
  .object({
    adaptiveExploration: AdaptiveExplorationConfigSchema,
    mythos: MythosConfigSchema,
    probeFamilies: z.array(ProbeFamilyCapabilitySchema).optional(),
  })
  .passthrough();

/**
 * Section 12.1 — Zod schema for `browser`. Targets can declare
 * browser capability to enable Playwright-backed session capture.
 */
const BrowserCapabilitySchema = z
  .object({
    enabled: z.boolean().optional(),
    bootstrapUrl: z.string().url().optional(),
    storageStateExpectations: z
      .object({
        expectedCookies: z.array(z.string()).optional(),
        expectedStorageOrigins: z.array(z.string()).optional(),
      })
      .optional(),
    evidencePaths: z.array(z.string()).optional(),
    launchOptions: z
      .object({
        headless: z.boolean().optional(),
        viewportWidth: z.number().int().positive().optional(),
        viewportHeight: z.number().int().positive().optional(),
        navigationTimeoutMs: z.number().int().positive().optional(),
      })
      .optional(),
  })
  .optional();

const TargetProfileBaseSchema = z
  .object({
    extends: z.string().min(1).optional(),
    id: z.string().min(1).optional(),
    name: z.string().optional(),
    description: z.string().optional(),
    kind: z.enum(['http', 'shell', 'code', 'dependency']).optional(),
    environment: z.enum([
      'fixture',
      'sandbox',
      'local_live',
      'staging',
      'hosted_authorized',
      'production_shadow',
    ]).optional(),
    baseUrl: z.string().optional(),
    defaultHeaders: z.record(z.string()).optional(),
    repoRoot: z.string().optional(),
    repoRootEnv: z.string().min(1).optional(),
    cwd: z.string().optional(),
    env: z.record(z.string()).optional(),
    includePaths: z.array(z.string()).optional(),
    excludePaths: z.array(z.string()).optional(),
    routeRoots: z.array(z.string()).optional(),
    searchRoots: z.array(z.string()).optional(),
    maxRoutes: z.number().int().positive().optional(),
    maxFiles: z.number().int().positive().optional(),
    defaultMode: z.enum(['declared', 'blind']).optional(),
    strictVerification: z.boolean().optional(),
    requiredIdentities: z.array(z.string().min(1)).optional(),
    requiredLanes: z.array(z.string().min(1)).optional(),
    testSynthesis: z.object({
      timeoutMs: z.number().int().positive().max(600_000).optional(),
    }).optional(),
    linuxSidecar: z.record(z.unknown()).optional(),
    verificationPolicy: z.record(z.unknown()).optional(),
    sourceProfileId: z.string().min(1).optional(),
    hints: z.record(z.unknown()).optional(),
    // Verification metadata — used by Modules B and C
    identities: z.array(z.record(z.unknown())).optional(),
    seedData: z.record(z.unknown()).optional(),
    canaries: z.array(z.record(z.unknown())).optional(),
    liveProbing: LiveProbingSchema.optional(),
    rollback: z.record(z.unknown()).optional(),
    localStartup: z.record(z.unknown()).optional(),
    localShutdown: z.record(z.unknown()).optional(),
    authBootstrap: z.record(z.unknown()).optional(),
    processDecoys: z.record(z.unknown()).optional(),
    persistenceCanaries: z.record(z.unknown()).optional(),
    authentication: z.record(z.unknown()).optional(),
    authSources: z.record(z.record(z.unknown())).optional(),
    hostedIdentities: z.array(z.record(z.unknown())).optional(),
    ingressChecks: z.array(z.record(z.unknown())).optional(),
    rateLimit: z.record(z.unknown()).optional(),
    cooldownSeconds: z.number().int().nonnegative().optional(),
    hostedRollback: z.record(z.unknown()).optional(),
    overlay: z.union([
      z.string().min(1),
      z.object({
        stackHints: z.record(z.string()).optional(),
        highValuePatterns: z.array(z.string()).optional(),
        trustBoundaries: z.array(z.object({
          from: z.string(),
          to: z.string(),
          mechanism: z.string(),
          notes: z.string().optional(),
        })).optional(),
        vulnerabilityFamilies: z.array(z.object({
          family: z.string(),
          description: z.string(),
          priority: z.enum(['critical', 'high', 'medium', 'low']).optional(),
          checkLocations: z.array(z.string()).optional(),
        })).optional(),
        engineeringStandards: z.array(z.string()).optional(),
      }),
    ]).optional(),
    authMechanism: z.object({
      tenantHeader: z.string().optional(),
    }).optional(),
    browser: BrowserCapabilitySchema,
  });

const TargetProfileSchema = TargetProfileBaseSchema
  .extend({
    id: z.string().min(1),
    kind: z.enum(['http', 'shell', 'code', 'dependency']),
    environment: z.enum([
      'fixture',
      'sandbox',
      'local_live',
      'staging',
      'hosted_authorized',
      'production_shadow',
    ]),
  })
  .superRefine((value, ctx) => {
    if (value.kind === 'http' && !value.baseUrl) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['baseUrl'], message: 'HTTP targets require baseUrl' });
    }
    if ((value.kind === 'code' || value.kind === 'dependency') && !value.repoRoot && !value.repoRootEnv) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['repoRoot'],
        message: `${value.kind} targets require repoRoot or repoRootEnv`,
      });
    }
  });

type RawTargetProfile = z.infer<typeof TargetProfileBaseSchema>;
type ParsedTargetProfile = z.infer<typeof TargetProfileSchema>;

export interface OverlayTrustBoundary {
  from: string;
  to: string;
  mechanism: string;
  notes?: string;
}

export interface OverlayVulnerabilityFamily {
  family: string;
  description: string;
  priority?: 'critical' | 'high' | 'medium' | 'low';
  checkLocations?: string[];
}

export interface OverlayInline {
  stackHints?: Record<string, string>;
  highValuePatterns?: string[];
  trustBoundaries?: OverlayTrustBoundary[];
  vulnerabilityFamilies?: OverlayVulnerabilityFamily[];
  engineeringStandards?: string[];
}

/**
 * Section 6.1 — adaptive exploration configuration resolved from
 * `liveProbing.adaptiveExploration`. The canonical type lives in
 * `verification/local-live/contracts.ts`; target-profile simply validates
 * the raw YAML slice and fills in defaults.
 */
export type { AdaptiveExplorationConfig } from '../verification/local-live/contracts.js';
export type { MythosExplorationConfig } from '../verification/local-live/mythos-exploration-sublane.js';

/**
 * Section 6.2 — Read `liveProbing.mythos` from the target profile and fill
 * in defaults. In smoke mode Mythos is off by default (it's expensive);
 * serious-mode callers flip `enabled` themselves. The returned config
 * surfaces a `enabledExplicit` hint so the runner can tell "target said
 * no" from "target did not say" and apply run-mode defaults accordingly.
 */
export function resolveMythosExplorationConfig(
  target: Pick<InvestigationTarget, 'liveProbing'>,
): MythosExplorationConfig & { enabledExplicit: boolean } {
  const parsed = LiveProbingSchema.safeParse(target.liveProbing ?? {});
  const raw = parsed.success ? parsed.data.mythos ?? {} : {};
  const enabledExplicit = typeof raw.enabled === 'boolean';
  const enabled = raw.enabled === true;
  const timeBudgetMs =
    typeof raw.timeBudgetMs === 'number' ? raw.timeBudgetMs : DEFAULT_MYTHOS_CONFIG.timeBudgetMs;
  const probeBudget =
    typeof raw.probeBudget === 'number' ? raw.probeBudget : DEFAULT_MYTHOS_CONFIG.probeBudget;
  const invocationsPerCampaign =
    typeof raw.invocationsPerCampaign === 'number'
      ? raw.invocationsPerCampaign
      : DEFAULT_MYTHOS_CONFIG.invocationsPerCampaign;
  const sourceCorrelationEnabled =
    raw.sourceCorrelation?.enabled === false ? false : DEFAULT_MYTHOS_CONFIG.sourceCorrelationEnabled;
  const sourceCorrelationMax =
    typeof raw.sourceCorrelation?.max === 'number'
      ? raw.sourceCorrelation.max
      : DEFAULT_MYTHOS_CONFIG.sourceCorrelationMax;
  return {
    enabled,
    enabledExplicit,
    timeBudgetMs,
    probeBudget,
    invocationsPerCampaign,
    sourceCorrelationEnabled,
    sourceCorrelationMax,
  };
}

/**
 * Read `liveProbing.adaptiveExploration` from the target profile and
 * fill in defaults. Targets without this key get the defaults (enabled,
 * 3 follow-ups per surprise, 5 mid-round hypotheses).
 */
export function resolveAdaptiveExplorationConfig(
  target: Pick<InvestigationTarget, 'liveProbing'>,
): AdaptiveExplorationConfig {
  const parsed = LiveProbingSchema.safeParse(target.liveProbing ?? {});
  const raw = parsed.success ? parsed.data.adaptiveExploration ?? {} : {};
  const enabled = raw.enabled === false ? false : true;
  const maxFollowupsPerSurprise = typeof raw.maxFollowupsPerSurprise === 'number'
    ? Math.max(1, Math.min(10, raw.maxFollowupsPerSurprise))
    : DEFAULT_ADAPTIVE_EXPLORATION_CONFIG.maxFollowupsPerSurprise;
  const maxMidRoundHypotheses = typeof raw.maxMidRoundHypotheses === 'number'
    ? Math.max(0, Math.min(20, raw.maxMidRoundHypotheses))
    : DEFAULT_ADAPTIVE_EXPLORATION_CONFIG.maxMidRoundHypotheses;
  return { enabled, maxFollowupsPerSurprise, maxMidRoundHypotheses };
}

export interface InvestigationTarget {
  id: string;
  name: string;
  description?: string;
  kind: 'http' | 'shell' | 'code' | 'dependency';
  environment: EnvironmentTier;
  baseUrl?: string;
  defaultHeaders?: Record<string, string>;
  repoRoot?: string;
  cwd?: string;
  env?: Record<string, string>;
  includePaths?: string[];
  excludePaths?: string[];
  routeRoots?: string[];
  searchRoots?: string[];
  maxRoutes?: number;
  maxFiles?: number;
  defaultMode?: 'declared' | 'blind';
  strictVerification?: boolean;
  requiredIdentities?: string[];
  requiredLanes?: string[];
  testSynthesis?: { timeoutMs?: number };
  linuxSidecar?: Record<string, unknown>;
  verificationPolicy?: Record<string, unknown>;
  sourceProfileId?: string;
  hints: Record<string, unknown>;
  profilePath?: string;
  supportedProbeKinds: string[];
  // Verification metadata
  identities?: Array<Record<string, unknown>>;
  seedData?: Record<string, unknown>;
  canaries?: Array<Record<string, unknown>>;
  liveProbing?: Record<string, unknown>;
  rollback?: Record<string, unknown>;
  localStartup?: Record<string, unknown>;
  localShutdown?: Record<string, unknown>;
  authBootstrap?: Record<string, unknown>;
  processDecoys?: Record<string, unknown>;
  persistenceCanaries?: Record<string, unknown>;
  authentication?: Record<string, unknown>;
  authSources?: Record<string, Record<string, unknown>>;
  hostedIdentities?: Array<Record<string, unknown>>;
  ingressChecks?: Array<Record<string, unknown>>;
  rateLimit?: Record<string, unknown>;
  cooldownSeconds?: number;
  hostedRollback?: Record<string, unknown>;
  overlay?: string | OverlayInline;
  authMechanism?: { tenantHeader?: string };
  /** Section 12.1 — browser capability configuration. */
  browser?: BrowserCapability;
}

export async function loadInvestigationTarget(
  targetArg: string,
  targetIdOverride?: string,
): Promise<InvestigationTarget> {
  if (/\.(ya?ml)$/i.test(targetArg)) {
    return loadTargetProfile(targetArg, targetIdOverride);
  }

  const maybeProfilePath = await resolveTargetInputPath(targetArg);
  if (maybeProfilePath && /\.(ya?ml)$/i.test(maybeProfilePath)) {
    return loadTargetProfile(maybeProfilePath, targetIdOverride);
  }

  const repoRoot = maybeProfilePath ? resolve(maybeProfilePath) : resolve(targetArg);
  return {
    id: targetIdOverride ?? basename(repoRoot),
    name: targetIdOverride ?? basename(repoRoot),
    kind: 'code',
    environment: 'sandbox',
    repoRoot,
    hints: {},
    supportedProbeKinds: ['code_read', 'dependency_read', 'state_check', 'evidence_check'],
  };
}

export async function loadTargetProfile(
  profilePath: string,
  targetIdOverride?: string,
): Promise<InvestigationTarget> {
  const resolvedPath = resolveProfilePath(profilePath);
  const resolvedProfile = await loadResolvedTargetProfile(resolvedPath, new Set<string>());
  const parsed = TargetProfileSchema.parse(resolvedProfile.profile) as ParsedTargetProfile;
  const profileDir = dirname(resolvedPath);

  const repoRoot = resolveRepoRoot(parsed, profileDir);
  const cwd = parsed.cwd
    ? resolveMaybeRelative(parsed.cwd, profileDir)
    : repoRoot;

  return {
    id: targetIdOverride ?? parsed.id,
    name: parsed.name ?? targetIdOverride ?? parsed.id,
    description: parsed.description,
    kind: parsed.kind,
    environment: parsed.environment,
    baseUrl: parsed.baseUrl,
    defaultHeaders: parsed.defaultHeaders,
    repoRoot,
    cwd,
    env: parsed.env,
    includePaths: normalizeScopeEntries(parsed.includePaths),
    excludePaths: normalizeScopeEntries(parsed.excludePaths),
    routeRoots: normalizeScopeEntries(parsed.routeRoots),
    searchRoots: normalizeScopeEntries(parsed.searchRoots),
    maxRoutes: parsed.maxRoutes,
    maxFiles: parsed.maxFiles,
    defaultMode: parsed.defaultMode,
    strictVerification: parsed.strictVerification,
    requiredIdentities: parsed.requiredIdentities,
    requiredLanes: parsed.requiredLanes,
    testSynthesis: parsed.testSynthesis,
    linuxSidecar: parsed.linuxSidecar,
    verificationPolicy: parsed.verificationPolicy,
    sourceProfileId: resolvedProfile.sourceProfileId,
    hints: parsed.hints ?? {},
    profilePath: resolvedPath,
    supportedProbeKinds: deriveSupportedProbeKinds({
      ...parsed,
      repoRoot,
      cwd,
    }),
    identities: parsed.identities,
    seedData: parsed.seedData,
    canaries: parsed.canaries,
    liveProbing: parsed.liveProbing,
    rollback: parsed.rollback,
    localStartup: parsed.localStartup,
    localShutdown: parsed.localShutdown,
    authBootstrap: parsed.authBootstrap,
    processDecoys: parsed.processDecoys,
    persistenceCanaries: parsed.persistenceCanaries,
    authentication: parsed.authentication,
    authSources: parsed.authSources,
    hostedIdentities: parsed.hostedIdentities,
    ingressChecks: parsed.ingressChecks,
    rateLimit: parsed.rateLimit,
    cooldownSeconds: parsed.cooldownSeconds,
    hostedRollback: parsed.hostedRollback,
    overlay: parsed.overlay,
    authMechanism: parsed.authMechanism,
    browser: resolveBrowserCapability(parsed),
  };
}

export function summarizeTargetProfile(target: InvestigationTarget): string {
  const lines = [
    `# Investigation Target: ${target.name}`,
    `ID: ${target.id}`,
    `Kind: ${target.kind}`,
    `Environment: ${target.environment}`,
  ];

  if (target.description) {
    lines.push(`Description: ${target.description}`);
  }
  if (target.baseUrl) {
    lines.push(`Base URL: ${target.baseUrl}`);
  }
  if (target.repoRoot) {
    lines.push(`Repo Root: ${target.repoRoot}`);
  }
  if (target.cwd) {
    lines.push(`Working Directory: ${target.cwd}`);
  }
  if (target.includePaths?.length) {
    lines.push(`Include Paths: ${target.includePaths.join(', ')}`);
  }
  if (target.excludePaths?.length) {
    lines.push(`Exclude Paths: ${target.excludePaths.join(', ')}`);
  }
  if (target.routeRoots?.length) {
    lines.push(`Route Roots: ${target.routeRoots.join(', ')}`);
  }
  if (target.searchRoots?.length) {
    lines.push(`Search Roots: ${target.searchRoots.join(', ')}`);
  }
  if (target.maxRoutes) {
    lines.push(`Max Routes: ${target.maxRoutes}`);
  }
  if (target.maxFiles) {
    lines.push(`Max Files: ${target.maxFiles}`);
  }
  if (target.defaultMode) {
    lines.push(`Default Mode: ${target.defaultMode}`);
  }
  if (target.strictVerification != null) {
    lines.push(`Strict Verification: ${target.strictVerification ? 'yes' : 'no'}`);
  }
  if (target.requiredLanes?.length) {
    lines.push(`Required Lanes: ${target.requiredLanes.join(', ')}`);
  }
  if (target.requiredIdentities?.length) {
    lines.push(`Required Identities: ${target.requiredIdentities.join(', ')}`);
  }
  if (target.testSynthesis?.timeoutMs) {
    lines.push(`Test Synthesis Timeout: ${target.testSynthesis.timeoutMs}ms`);
  }
  if (target.sourceProfileId) {
    lines.push(`Source Profile ID: ${target.sourceProfileId}`);
  }

  if (target.browser?.enabled) {
    lines.push(`Browser: enabled`);
    if (target.browser.bootstrapUrl) {
      lines.push(`Browser Bootstrap URL: ${target.browser.bootstrapUrl}`);
    }
  }

  lines.push(`Supported Probe Kinds: ${target.supportedProbeKinds.join(', ') || 'none'}`);

  if (Object.keys(target.hints).length > 0) {
    lines.push('', '## Target Hints');
    for (const [key, value] of Object.entries(target.hints)) {
      lines.push(`- ${key}: ${stringifyHint(value)}`);
    }
  }

  return lines.join('\n');
}

interface ResolvedTargetProfile {
  profile: RawTargetProfile;
  profilePath: string;
  sourceProfileId: string;
}

function resolveProfilePath(profilePath: string): string {
  if (isAbsolute(profilePath)) {
    return assertTargetPath(profilePath);
  }

  const attackLabRoot = getAttackLabRoot();
  const securityLabRoot = resolve(attackLabRoot, '..', '..');
  const candidates = [
    resolve(process.cwd(), profilePath),
    resolve(securityLabRoot, profilePath),
    resolve(attackLabRoot, profilePath),
    resolve(attackLabRoot, 'targets', profilePath),
  ];

  for (const candidate of candidates) {
    try {
      return assertTargetPath(candidate);
    } catch {
      // Try next candidate.
    }
  }

  throw new Error(`Target profile not found: ${profilePath}`);
}

async function resolveTargetInputPath(targetArg: string): Promise<string | null> {
  try {
    const resolved = resolveProfilePath(targetArg);
    return resolved;
  } catch {
    try {
      const repoRoot = resolve(targetArg);
      const info = await stat(repoRoot);
      return info.isFile() ? repoRoot : null;
    } catch {
      return null;
    }
  }
}

async function loadResolvedTargetProfile(
  resolvedPath: string,
  visited: Set<string>,
): Promise<ResolvedTargetProfile> {
  if (visited.has(resolvedPath)) {
    throw new Error(`Circular target profile inheritance detected at ${resolvedPath}`);
  }
  visited.add(resolvedPath);

  const raw = await readFile(resolvedPath, 'utf8');
  const expanded = expandEnv(YAML.parse(raw) as unknown);
  const parsed = TargetProfileBaseSchema.parse(expanded) as RawTargetProfile;

  if (!parsed.extends) {
    const id = parsed.id ?? basename(resolvedPath, '.yaml');
    return {
      profile: { ...parsed, id },
      profilePath: resolvedPath,
      sourceProfileId: parsed.sourceProfileId ?? id,
    };
  }

  const parentPath = resolveInheritedProfilePath(parsed.extends, dirname(resolvedPath));
  const parent = await loadResolvedTargetProfile(parentPath, visited);
  const merged = deepMergeProfile(parent.profile, { ...parsed, extends: undefined });
  const id = merged.id ?? parsed.id ?? basename(resolvedPath, '.yaml');
  return {
    profile: { ...merged, id },
    profilePath: resolvedPath,
    sourceProfileId: parent.sourceProfileId,
  };
}

function resolveInheritedProfilePath(reference: string, currentDir: string): string {
  if (isAbsolute(reference)) {
    return assertTargetPath(reference);
  }

  const relativeCandidate = resolve(currentDir, reference);
  try {
    return assertTargetPath(relativeCandidate);
  } catch {
    return resolveProfilePath(reference);
  }
}

function resolveMaybeRelative(filePath: string, root: string): string {
  return isAbsolute(filePath) ? filePath : resolve(root, filePath);
}

function resolveRepoRoot(profile: ParsedTargetProfile, profileDir: string): string | undefined {
  const envValue = profile.repoRootEnv ? process.env[profile.repoRootEnv] : undefined;
  const repoRootSource = envValue ?? profile.repoRoot;
  return repoRootSource ? resolveMaybeRelative(repoRootSource, profileDir) : undefined;
}

function normalizeScopeEntries(entries?: string[]): string[] | undefined {
  if (!entries || entries.length === 0) {
    return undefined;
  }

  return entries
    .map((entry) => entry.replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/+$/, ''))
    .filter((entry) => entry.length > 0);
}

function deriveSupportedProbeKinds(profile: ParsedTargetProfile & { repoRoot?: string; cwd?: string }): string[] {
  const supported = new Set<string>();

  if (profile.baseUrl) {
    supported.add('http_request');
    supported.add('prompt_injection');
  }
  if (profile.repoRoot) {
    supported.add('code_read');
    supported.add('dependency_read');
    supported.add('state_check');
    supported.add('evidence_check');
  }
  if (profile.kind === 'shell' || profile.cwd) {
    supported.add('shell_command');
    supported.add('process_check');
    supported.add('persistence_check');
  }
  // Verification lanes
  if (profile.repoRoot) {
    supported.add('synthesize_test');
  }
  if (profile.canaries || profile.liveProbing) {
    supported.add('local_live_probe');
  }
  if ((profile.authentication || profile.authSources) && profile.environment === 'hosted_authorized') {
    supported.add('hosted_probe');
  }
  if (profile.repoRoot) {
    supported.add('supply_chain_confirm');
  }
  // Section 12.1 — browser probes when browser capability is declared and enabled.
  if (profile.browser?.enabled === true) {
    supported.add('browser_probe');
  }

  return [...supported];
}

/**
 * Section 12.1 — resolve browser capability from the target profile.
 * Returns undefined when not declared (browser is opt-in).
 */
function resolveBrowserCapability(
  parsed: RawTargetProfile,
): BrowserCapability | undefined {
  if (!parsed.browser) return undefined;
  const raw = BrowserCapabilitySchema.parse(parsed.browser);
  if (!raw) return undefined;
  return {
    ...DEFAULT_BROWSER_CAPABILITY,
    ...raw,
    enabled: raw.enabled === true,
  };
}

function expandEnv(value: unknown): unknown {
  if (typeof value === 'string') {
    return value.replace(/\$\{([A-Z][A-Z0-9_]*)\}/g, (_full, variable: string) => {
      const resolved = process.env[variable];
      if (resolved == null) {
        throw new Error(`Missing environment variable ${variable} required by target profile`);
      }
      return resolved;
    });
  }
  if (Array.isArray(value)) {
    return value.map((entry) => expandEnv(entry));
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, entry]) => [key, expandEnv(entry)]),
    );
  }
  return value;
}

function stringifyHint(value: unknown): string {
  if (typeof value === 'string') {
    return value;
  }
  return JSON.stringify(value);
}

function assertTargetPath(candidate: string): string {
  fsStatSync(candidate);
  return candidate;
}

function deepMergeProfile(base: RawTargetProfile, override: RawTargetProfile): RawTargetProfile {
  const result: Record<string, unknown> = { ...base };

  for (const [key, value] of Object.entries(override)) {
    if (value === undefined) {
      continue;
    }

    const existing = result[key];
    if (Array.isArray(value)) {
      result[key] = [...value];
      continue;
    }
    if (isPlainObject(existing) && isPlainObject(value)) {
      result[key] = deepMergeObject(existing, value);
      continue;
    }
    result[key] = value;
  }

  return result as RawTargetProfile;
}

function deepMergeObject(
  base: Record<string, unknown>,
  override: Record<string, unknown>,
): Record<string, unknown> {
  const result: Record<string, unknown> = { ...base };
  for (const [key, value] of Object.entries(override)) {
    if (value === undefined) {
      continue;
    }
    const existing = result[key];
    if (Array.isArray(value)) {
      result[key] = [...value];
      continue;
    }
    if (isPlainObject(existing) && isPlainObject(value)) {
      result[key] = deepMergeObject(existing, value);
      continue;
    }
    result[key] = value;
  }
  return result;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}
