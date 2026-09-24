import { z } from 'zod';
import { SAFE_IDENTIFIER_PATTERN } from '../autonomous/identifiers.js';

const EnvironmentTierSchema = z.enum([
  'fixture',
  'sandbox',
  'local_live',
  'staging',
  'hosted_authorized',
  'production_shadow',
]);
const SecurityModeSchema = z.enum(['declared', 'blind']);
const SeveritySchema = z.enum(['low', 'medium', 'high', 'critical']);

const OrchestrationRoleSchema = z.object({
  strategy: z.enum(['scripted', 'manual', 'provider']).default('scripted'),
  provider: z.string().optional(),
  model: z.string().optional(),
  notes: z.string().optional(),
});

export const SecurityLabOrchestrationSchema = z.object({
  planner: OrchestrationRoleSchema.optional(),
  executor: OrchestrationRoleSchema.optional(),
  judge: OrchestrationRoleSchema.optional(),
  reporter: OrchestrationRoleSchema.optional(),
});

const HttpTargetSchema = z.object({
  id: z.string().min(1),
  kind: z.literal('http'),
  environment: EnvironmentTierSchema,
  baseUrl: z.string().min(1),
  defaultHeaders: z.record(z.string()).optional(),
});

const ShellTargetSchema = z.object({
  id: z.string().min(1),
  kind: z.literal('shell'),
  environment: EnvironmentTierSchema,
  cwd: z.string().optional(),
  env: z.record(z.string()).optional(),
  /**
   * Executable basenames this target permits. Required for shell targets: the
   * runtime refuses shell probes for a target that declares no allow-list
   * rather than relying on a denylist of dangerous fragments.
   */
  allowedShellCommands: z.array(z.string().min(1)).optional(),
  /** Acknowledge that the allow-list contains an interpreter (sh, python, …). */
  allowShellInterpreters: z.boolean().optional(),
});

export const SecurityLabTargetSchema = z.discriminatedUnion('kind', [
  HttpTargetSchema,
  ShellTargetSchema,
]);

const HttpProbeSchema = z.object({
  kind: z.literal('http_request'),
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD']).default('GET'),
  path: z.string().min(1),
  headers: z.record(z.string()).optional(),
  body: z.string().optional(),
  timeoutMs: z.number().int().positive().max(60000).default(10000),
});

const ShellProbeSchema = z.object({
  kind: z.literal('shell_command'),
  command: z.array(z.string()).min(1),
  timeoutMs: z.number().int().positive().max(60000).default(10000),
  cwd: z.string().optional(),
  env: z.record(z.string()).optional(),
});

export const SecurityLabProbeSchema = z.discriminatedUnion('kind', [
  HttpProbeSchema,
  ShellProbeSchema,
]);

const CaptureSourceSchema = z.enum(['responseBody', 'stdout', 'stderr']);

export const SecurityLabCaptureSchema = z.object({
  source: CaptureSourceSchema,
  pattern: z.string().min(1),
});

export const SecurityLabExpectationSchema = z.object({
  safetyState: z.enum(['blocked', 'allowed', 'error']).optional(),
  statusCode: z.number().int().optional(),
  exitCode: z.number().int().optional(),
  bodyIncludes: z.array(z.string()).default([]),
  bodyExcludes: z.array(z.string()).default([]),
  stdoutIncludes: z.array(z.string()).default([]),
  stdoutExcludes: z.array(z.string()).default([]),
  stderrIncludes: z.array(z.string()).default([]),
  stderrExcludes: z.array(z.string()).default([]),
});

export const SecurityLabStepSchema = z.object({
  id: z.string().min(1),
  title: z.string().min(1),
  probe: SecurityLabProbeSchema,
  capture: z.record(SecurityLabCaptureSchema).optional(),
  expect: SecurityLabExpectationSchema,
});

export const SecurityLabScenarioSchema = z.object({
  id: z.string().min(1),
  title: z.string().min(1),
  description: z.string().optional(),
  severity: SeveritySchema.default('medium'),
  target: z.string().min(1),
  hiddenNotes: z.string().optional(),
  steps: z.array(SecurityLabStepSchema).min(1),
});

export const SecurityLabRunfileSchema = z.object({
  // The runfile id becomes part of the run directory name, so it must be a
  // plain identifier (no path separators, no traversal).
  id: z.string().min(1).regex(
    SAFE_IDENTIFIER_PATTERN,
    'runfile id must be a safe identifier (letters, digits, dot, dash, underscore)',
  ),
  name: z.string().min(1),
  description: z.string().optional(),
  mode: SecurityModeSchema.default('declared'),
  orchestration: SecurityLabOrchestrationSchema.optional(),
  targets: z.array(SecurityLabTargetSchema).min(1),
  scenarios: z.array(SecurityLabScenarioSchema).min(1),
});

export type SecurityLabTarget = z.infer<typeof SecurityLabTargetSchema>;
export type SecurityLabProbe = z.infer<typeof SecurityLabProbeSchema>;
export type SecurityLabCapture = z.infer<typeof SecurityLabCaptureSchema>;
export type SecurityLabExpectation = z.infer<typeof SecurityLabExpectationSchema>;
export type SecurityLabStep = z.infer<typeof SecurityLabStepSchema>;
export type SecurityLabScenario = z.infer<typeof SecurityLabScenarioSchema>;
export type SecurityLabRunfile = z.infer<typeof SecurityLabRunfileSchema>;
export type SecurityLabOrchestration = z.infer<typeof SecurityLabOrchestrationSchema>;

