import { z } from 'zod';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export const BugFamilySchema = z.enum([
  'ssrf', 'auth_bypass', 'rce', 'xss', 'cors',
  'deserialization', 'sandbox_escape', 'credential_exposure',
  'supply_chain', 'tenant_boundary', 'prompt_injection',
  'rate_limit_dos',
  'unknown',
]);
export type BugFamily = z.infer<typeof BugFamilySchema>;

export const RiskTierSchema = z.enum(['critical', 'intermediate', 'low']);
export type RiskTier = z.infer<typeof RiskTierSchema>;

export const ReviewModeSchema = z.enum(['always', 'borderline', 'none']);
export type ReviewMode = z.infer<typeof ReviewModeSchema>;

export const ReviewPolicySchema = z.object({
  riskTier: RiskTierSchema,
  reviewMode: ReviewModeSchema,
  hardFailOnMiss: z.boolean(),
  requireRuntime: z.boolean(),
  bugFamily: BugFamilySchema,
  observational: z.boolean(),
});
export type ReviewPolicy = z.infer<typeof ReviewPolicySchema>;

// ---------------------------------------------------------------------------
// Bug family classification — regex keyword matching
// ---------------------------------------------------------------------------

const FAMILY_PATTERNS: Array<{ family: BugFamily; patterns: RegExp[] }> = [
  {
    family: 'ssrf',
    patterns: [
      /\bssrf\b/i,
      /server.side request forgery/i,
      /url\s+(?:fetch|redirect|validation|filter)/i,
      /private.ip\s+(?:filter|block|bypass)/i,
      /dns\s+rebind/i,
    ],
  },
  {
    family: 'auth_bypass',
    patterns: [
      /\bauth(?:entication|orization)?\s+bypass/i,
      /\bauth\s+(?:missing|skip|lack|absent)/i,
      /\bunauth(?:enticated|orized)\s+(?:access|endpoint)/i,
      /route.*(?:missing|without)\s+auth/i,
      /session\s+fixation/i,
      /state\s+fixation/i,
      /\bauth.session.state\s+fixation/i,
    ],
  },
  {
    family: 'rce',
    patterns: [
      /\brce\b/i,
      /remote\s+code\s+execution/i,
      /command\s+(?:injection|exec)/i,
      /\beval\s*\(/i,
      /\bexec\s*\(/i,
      /os\.system/i,
      /subprocess.*(?:user|input|untrusted)/i,
      /child_process.*(?:user|input)/i,
      /code\s+execution/i,
    ],
  },
  {
    family: 'sandbox_escape',
    patterns: [
      /sandbox\s+escape/i,
      /sandbox\s+bypass/i,
      /\b__subclasses__\b/i,
      /\b__globals__\b/i,
      /\b__import__\b/i,
      /breakout/i,
      /dangerous\s+builtin/i,
    ],
  },
  {
    family: 'deserialization',
    patterns: [
      /\bdeserializ/i,
      /\bpickle\b/i,
      /\bshelve\b/i,
      /unsafe\s+(?:load|yaml)/i,
      /\bjsonpickle\b/i,
      /\bmarshal\.loads?\b/i,
      /\b__reduce__\b/i,
    ],
  },
  {
    family: 'xss',
    patterns: [
      /\bxss\b/i,
      /cross.site\s+script/i,
      /\bdangerouslySetInnerHTML\b/i,
      /\bv-html\b/i,
      /\binnerHTML\b.*(?:user|input|untrusted)/i,
      /script\s+injection/i,
      /html\s+injection/i,
      /context.sensitive\s+escaping/i,
    ],
  },
  {
    family: 'cors',
    patterns: [
      /\bcors\b/i,
      /cross.origin.*(?:credential|cookie)/i,
      /Access-Control-Allow-Origin.*(?:reflect|wildcard|\*)/i,
      /origin\s+(?:reflect|validation\s+bypass)/i,
    ],
  },
  {
    family: 'credential_exposure',
    patterns: [
      /\bcredential\s+(?:exposure|leak|exfil)/i,
      /(?:api|secret)\s+key\s+(?:exposure|leak|log|print)/i,
      /hardcoded\s+(?:secret|password|credential|key|token)/i,
      /\btoken\s+(?:leak|exposure|exfil)/i,
      /(?:secret|password)\s+(?:in|via)\s+(?:log|url|header|query)/i,
    ],
  },
  {
    family: 'supply_chain',
    patterns: [
      /supply.chain/i,
      /dependency\s+(?:confusion|inject|hijack)/i,
      /typosquat/i,
      /\bnpm\s+(?:hijack|confus)/i,
      /package\s+(?:hijack|confus)/i,
    ],
  },
  {
    family: 'tenant_boundary',
    patterns: [
      /tenant\s+(?:boundary|isolation|escape|leak|cross)/i,
      /cross.tenant/i,
      /multi.tenant.*(?:leak|escape|bypass)/i,
      /\bidor\b/i,
      /insecure\s+direct\s+object/i,
    ],
  },
  {
    family: 'prompt_injection',
    patterns: [
      /prompt\s+injection/i,
      /\bjailbreak\b/i,
      /llm\s+(?:injection|manipulation)/i,
      /indirect\s+prompt/i,
    ],
  },
  {
    family: 'rate_limit_dos',
    patterns: [
      /rate.limit/i,
      /\bdos\b/i,
      /denial.of.service/i,
      /\bredos\b/i,
      /unbounded\s+(?:query|iteration|loop|resource)/i,
      /resource\s+exhaustion/i,
    ],
  },
];

export function classifyBugFamily(
  claim: string,
  candidateId: string,
  rootCause?: string,
): BugFamily {
  const text = `${claim} ${rootCause ?? ''} ${candidateId}`;
  for (const { family, patterns } of FAMILY_PATTERNS) {
    for (const pattern of patterns) {
      if (pattern.test(text)) return family;
    }
  }
  return 'unknown';
}

// ---------------------------------------------------------------------------
// Tier mapping
// ---------------------------------------------------------------------------

const CRITICAL_FAMILIES = new Set<BugFamily>([
  'ssrf', 'auth_bypass', 'rce', 'deserialization', 'sandbox_escape', 'credential_exposure',
]);

const INTERMEDIATE_FAMILIES = new Set<BugFamily>([
  'xss', 'cors', 'supply_chain', 'tenant_boundary',
]);

const LOW_FAMILIES = new Set<BugFamily>([
  'prompt_injection', 'rate_limit_dos',
]);

type SourceStatus = 'supported' | 'weakened' | 'refuted' | 'needs_runtime';
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export function resolveReviewPolicy(opts: {
  bugFamily: BugFamily;
  severity?: Severity;
  sourceStatus: SourceStatus;
  confidence: number;
  enforcing?: boolean;
}): ReviewPolicy {
  const { bugFamily, severity, sourceStatus, confidence, enforcing = false } = opts;

  const tier = resolveTier(bugFamily, severity, sourceStatus, confidence);
  const policy = buildPolicyForTier(tier, bugFamily, sourceStatus, confidence, enforcing);
  return policy;
}

function resolveTier(
  bugFamily: BugFamily,
  severity: Severity | undefined,
  sourceStatus: SourceStatus,
  confidence: number,
): RiskTier {
  if (CRITICAL_FAMILIES.has(bugFamily)) {
    // credential_exposure with medium severity and no strong support → intermediate
    if (bugFamily === 'credential_exposure' && severity === 'medium' && sourceStatus !== 'supported') {
      return 'intermediate';
    }
    // Critical family but low confidence or low severity → intermediate
    if (confidence < 0.7 && severity !== 'critical' && severity !== 'high') {
      return 'intermediate';
    }
    if (severity === 'medium') {
      return 'intermediate';
    }
    return 'critical';
  }

  if (INTERMEDIATE_FAMILIES.has(bugFamily)) {
    // tenant_boundary stays intermediate unless proven escalation
    return 'intermediate';
  }

  if (LOW_FAMILIES.has(bugFamily)) {
    return 'low';
  }

  // unknown family
  if (confidence < 0.4 || severity === 'low' || severity === 'info') {
    return 'low';
  }
  return 'intermediate';
}

function buildPolicyForTier(
  riskTier: RiskTier,
  bugFamily: BugFamily,
  sourceStatus: SourceStatus,
  confidence: number,
  enforcing: boolean,
): ReviewPolicy {
  const observational = !enforcing;

  switch (riskTier) {
    case 'critical':
      return {
        riskTier: 'critical',
        reviewMode: 'always',
        hardFailOnMiss: true,
        requireRuntime: true,
        bugFamily,
        observational,
      };

    case 'intermediate': {
      const requireRuntime =
        sourceStatus === 'supported' ||
        (sourceStatus === 'weakened' && confidence >= 0.7) ||
        sourceStatus === 'needs_runtime';
      return {
        riskTier: 'intermediate',
        reviewMode: 'borderline',
        hardFailOnMiss: false,
        requireRuntime,
        bugFamily,
        observational,
      };
    }

    case 'low':
      return {
        riskTier: 'low',
        reviewMode: 'none',
        hardFailOnMiss: false,
        requireRuntime: false,
        bugFamily,
        observational,
      };
  }
}
