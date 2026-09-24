export interface CandidateInfo {
  id: string;
  claim: string;
  context: string;
  source?: string;
  severity?: string;
  confidence?: number;
  signalIds?: string[];
  relatedAssets?: string[];
}

export function buildPerCandidateSourcePrompt(
  candidate: CandidateInfo,
  repoRoot: string,
  targetId: string,
): string {
  return `You are a source-code verification agent. Your job is to verify ONE specific security finding claim against the actual source code.

## Target
- Repository: \`${repoRoot}\`
- Target ID: ${targetId}

## Candidate Finding
- **ID**: ${candidate.id}
- **Claim**: ${candidate.claim}

${candidate.context ? `### Additional context from static analysis\n${candidate.context}\n` : ''}
## Task

1. **Read the claimed code path.** Find the exact file(s) and function(s) referenced by the claim. If the claim is vague, search for the most likely location.
2. **Identify the actual root cause.** What specific code construct (default value, missing check, unguarded branch, etc.) creates the vulnerability? Name the file, line, and code.
3. **Find concrete source references.** Provide at least 2 specific file:line references with code snippets that demonstrate the issue. For single-site config/default issues (e.g., a default value in a data class), 1 reference is acceptable.
4. **Identify preconditions.** What must be true for this to be exploitable? (deployment config, feature flags, authentication state, etc.)
5. **List defense mechanisms.** If you observe any defense mechanisms (sanitization, escaping, validation, allowlists, auth checks, rate limiters, CSP headers, etc.), list each one with its exact file:line location in the "defenseMechanismsObserved" field. A defense name alone does not prove the claim is invalid — you must evaluate whether the defense is valid for the exact sink and context.
6. **Proof obligation for defended positive findings.** If you observe one or more defenses but still conclude "supported" or "weakened", you must identify the exact sink that remains reachable after those defenses, the residual post-defense data path, a concrete payload that survives the defenses, and the exact sink fragment after the defenses are applied. If you cannot prove the residual risk at that level, use "needs_runtime" or "refuted" instead.
7. **Assess the claim.** Does the source code support, weaken, or refute the claim? If you cannot determine from source alone, mark it as needing runtime verification. If you found a defense mechanism, explain why it does or does not cover the specific attack vector before concluding "refuted", "weakened", or "supported".

## Rules
- Do NOT attempt runtime verification, Docker, or any live testing
- Do NOT make filing decisions
- Do NOT speculate about impact beyond what the code shows
- If a claim is too vague to verify from source, say so explicitly
- Downgrade architectural hand-waving to "weakened" or "needs_runtime"
- If multiple defenses exist on the path to the sink, account for all of them before concluding that attacker-controlled data still reaches the sink
- Do NOT ignore earlier escaping/validation just because a later sink like innerHTML, eval, or dynamic import exists
- If your residual-risk argument depends on browser behavior, framework semantics, or any behavior not explicit in the source, use "needs_runtime"

## Output Format

Return a single JSON object (no markdown fences, no explanation outside the JSON):

{
  "candidateId": "${candidate.id}",
  "claim": "the original claim in your own words",
  "status": "supported" | "weakened" | "refuted" | "needs_runtime",
  "evidenceClass": "single_site_default" | "multi_site_flow",
  "rootCause": "specific description of the root cause with file:line",
  "sourceRefs": [
    { "file": "path/to/file.py", "line": 42, "snippet": "relevant code" }
  ],
  "exploitPath": "how an attacker would trigger this (if determinable from source)",
  "preconditions": ["list", "of", "required", "conditions"],
  "defenseMechanismsObserved": ["html.escape() at views.py:45", "CSP header in middleware.py:12"],
  "residualSinkRef": { "file": "path/to/file.py", "line": 99, "snippet": "the sink still reachable after defenses" },
  "residualBypassPath": "exact post-defense data flow that still reaches the sink",
  "proofPayload": "minimal payload that survives the defenses",
  "postDefenseSnippet": "the exact sink fragment after the defenses are applied",
  "assumptions": ["any behavior you had to assume rather than prove from source"],
  "dedupNotes": "any overlap with known advisories if apparent from code comments/changelogs",
  "runtimePlan": "what runtime test would confirm this (if status is needs_runtime)",
  "confidence": 0.0 to 1.0
}

- Only populate "residualSinkRef", "residualBypassPath", "proofPayload", "postDefenseSnippet", and "assumptions" when "defenseMechanismsObserved" is non-empty and your final status is "supported" or "weakened".
- If you cannot provide all of those residual-risk proof fields with an empty assumptions list, do not return "supported" or "weakened" for a defended finding.
`;
}

const BUG_CLASS_DESCRIPTIONS = [
  {
    name: 'Config/default fail-open',
    description: 'Security-sensitive configuration fields that default to permissive values (False, None, empty, disabled). Look for boolean auth/security fields defaulting to False, None/null default for keys or secrets that disable validation when absent, and feature gates that fail open.',
  },
  {
    name: 'Auth/session/state fixation',
    description: 'Session identifiers, tokens, or state values that are caller-controlled rather than server-generated. Look for session IDs accepted from request parameters, state tokens not bound to server-side session, and authentication tokens that can be replayed or pre-set by the caller.',
  },
  {
    name: 'Trusted proxy / forwarded header misuse',
    description: 'Code that trusts X-Forwarded-For, X-Real-IP, X-Forwarded-Proto, or similar headers without validation. Look for IP-based access control using forwarded headers, protocol detection from X-Forwarded-Proto affecting security decisions, and host header injection via X-Forwarded-Host.',
  },
  {
    name: 'Route/auth inconsistency',
    description: 'Endpoints registered without authentication dependencies when sibling endpoints require them. Look for router decorators missing auth dependencies that other routes in the same module have, endpoints added to a router that has no default auth middleware, and admin/sensitive functionality accessible without privilege checks.',
  },
  {
    name: 'Python sandbox escape / dangerous builtins',
    description: 'Code execution surfaces that allow breaking out of intended sandbox boundaries. Search for eval(), exec(), __import__(), getattr() on user input, subprocess with user-controlled arguments, importlib with dynamic module names, code objects compiled from user strings. Check sandbox implementations that filter AST or restrict builtins — commonly bypassed via __subclasses__(), __globals__, or frame introspection.',
  },
  {
    name: 'Deserialization / pickle / shelve / unsafe loaders',
    description: 'Untrusted data deserialized through formats supporting arbitrary object instantiation. Search for pickle.loads/load on user-supplied data, shelve.open on user-controlled paths, yaml.load without SafeLoader, marshal.loads, jsonpickle.decode, and custom deserializers using __reduce__ or __setstate__.',
  },
  {
    name: 'SSRF / URL validation / private IP filtering',
    description: 'Server-side code that fetches URLs from user input without destination validation. Search for fetch(), requests.get/post(), httpx.request(), urllib.urlopen(), aiohttp.ClientSession with user-controlled URLs. Check for missing private IP blocking (10.x, 172.16-31.x, 192.168.x, 169.254.x, 127.x, ::1), DNS rebinding, redirect following to internal hosts, URL parsing tricks (decimal/octal IP, IPv6 brackets, scheme://user@host).',
  },
  {
    name: 'XSS context-sensitive escaping',
    description: 'User-controlled content rendered in HTML where escaping does not match the insertion context. Search for HTML escaping in JavaScript contexts (script tags, event handlers), URL contexts (href/src with javascript: protocol), attribute contexts without quote enforcement, template engines with autoescape disabled, raw/safe filters, dangerouslySetInnerHTML or v-html with user input. Key test: does the escaping function handle the exact context where the value is inserted?',
  },
  {
    name: 'Command execution tool boundaries',
    description: 'Tool/plugin systems executing shell commands beyond intended boundaries. Search for tool frameworks calling subprocess.run(), os.system(), child_process.exec() with LLM or user-derived arguments, missing command allowlists, argument injection via shell metacharacters (;, |, $(), backticks), path traversal in tool file arguments.',
  },
  {
    name: 'CORS credential exposure',
    description: 'CORS configurations allowing credentialed cross-origin requests from untrusted origins. Search for Access-Control-Allow-Origin reflecting the request Origin header, Allow-Credentials: true with permissive origin policy, wildcard origin with credentials, origin validation bypasses (substring matching, null origin, scheme-less comparison).',
  },
  {
    name: 'Rate-limit / unauthenticated DoS',
    description: 'Endpoints abusable to exhaust resources without authentication or at minimal cost. Search for unauthenticated endpoints triggering expensive operations (DB queries, external APIs, crypto), missing rate limits on auth endpoints (login, password reset, OTP), unbounded query parameters controlling iteration/response size, ReDoS patterns on user input, nonce/token generation without bounding outstanding tokens.',
  },
];

export function buildBugClassAuditPrompt(
  repoRoot: string,
  targetId: string,
  existingCandidateIds: string[],
): string {
  const classDescriptions = BUG_CLASS_DESCRIPTIONS
    .map((c, i) => `${i + 1}. **${c.name}**: ${c.description}`)
    .join('\n\n');

  const existingList = existingCandidateIds.length > 0
    ? existingCandidateIds.map(id => `- ${id}`).join('\n')
    : '(none)';

  return `You are a source-code audit agent. Your job is to sweep a codebase for specific bug classes that static analysis commonly under-detects.

## Target
- Repository: \`${repoRoot}\`
- Target ID: ${targetId}

## Bug Classes to Sweep

${classDescriptions}

## Already-Known Candidates

The following findings have already been identified. Do NOT duplicate them:
${existingList}

## Task

1. For each bug class, search the codebase methodically. Use \`grep\`, \`find\`, and file reading to locate potential instances.
2. Only report findings you can ground with specific file:line references.
3. Ignore anything that overlaps with the already-known candidates above.
4. For each new finding, provide the same structured output as a per-candidate verification.

## Rules
- Do NOT attempt runtime verification, Docker, or any live testing
- Do NOT make filing decisions
- Only report findings with concrete code evidence — no architectural speculation
- Each finding must have at least 1 specific source reference
- If a finding has observed defenses but remains "supported" or "weakened", include the same residual-risk proof fields used in per-candidate verification

## Output Format

Return a JSON array of finding objects (no markdown fences, no explanation outside the JSON):

[
  {
    "candidateId": "audit-<descriptive-slug>",
    "claim": "description of the finding",
    "status": "supported" | "weakened",
    "evidenceClass": "single_site_default" | "multi_site_flow",
    "rootCause": "specific description with file:line",
    "sourceRefs": [
      { "file": "path/to/file.py", "line": 42, "snippet": "relevant code" }
    ],
    "exploitPath": "how an attacker would trigger this",
    "preconditions": ["required", "conditions"],
    "defenseMechanismsObserved": ["defense description at file:line"],
    "residualSinkRef": { "file": "path/to/file.py", "line": 99, "snippet": "the sink still reachable after defenses" },
    "residualBypassPath": "exact post-defense data flow that still reaches the sink",
    "proofPayload": "minimal payload that survives the defenses",
    "postDefenseSnippet": "the exact sink fragment after the defenses are applied",
    "assumptions": ["any behavior you had to assume rather than prove from source"],
    "confidence": 0.0 to 1.0
  }
]

Return an empty array [] if no new grounded findings are discovered.
`;
}

export function buildDefenseCriticPrompt(
  candidate: CandidateInfo,
  sourceResult: {
    status: string;
    rootCause: string;
    sourceRefs: Array<{ file: string; line?: number; snippet: string }>;
    exploitPath?: string;
    defenseMechanismsObserved: string[];
  },
  repoRoot: string,
): string {
  const refs = sourceResult.sourceRefs
    .map(r => `- ${r.file}${r.line ? `:${r.line}` : ''}: \`${r.snippet}\``)
    .join('\n');

  const defenses = sourceResult.defenseMechanismsObserved
    .map(d => `- ${d}`)
    .join('\n');

  return `You are a defense-bypass critic. A source-code verifier concluded that a security finding is **refuted** because it observed defense mechanisms. Your job is to determine whether those defenses are actually valid for the exact sink and context.

## Original Claim
- **ID**: ${candidate.id}
- **Claim**: ${candidate.claim}

## Source Verifier's Assessment
- **Status**: ${sourceResult.status}
- **Root cause**: ${sourceResult.rootCause}
${sourceResult.exploitPath ? `- **Exploit path**: ${sourceResult.exploitPath}` : ''}

### Source References
${refs || '(none provided)'}

### Cited Defense Mechanisms
${defenses}

## Repository
\`${repoRoot}\`

## Task

Read the source code around the cited defense mechanisms and the vulnerable sink. Evaluate whether the defense is valid for the EXACT context:

1. **Context match**: Does the defense operate on the same data flow that reaches the sink? A defense in a different handler, template, or data path does not count.
2. **Completeness**: Does the defense cover ALL relevant attack vectors, or only a subset?
3. **Bypass categories to check**:
   - Context-breaking payloads (e.g., HTML escaping in a JavaScript context)
   - Wrong-layer escaping (e.g., URL-encoding where HTML-encoding is needed)
   - Encoding gaps (e.g., double-encoding, Unicode normalization)
   - Parser differentials (e.g., browser vs. server interpretation)
   - Conditional defenses (e.g., only applied in certain branches or configurations)
   - Incomplete allowlists or denylists
   - Feature-gated controls (e.g., defense only active with certain flags/settings)
4. **Proof obligation for any override**: If you think the refutation is wrong, identify the exact sink file:line, the exact data path that reaches it after the cited defense, and a concrete payload that would survive the defense. Show the resulting sink fragment after the defense.
5. **Verdict**: Is the defense valid and complete for this exact sink, or does it leave the vulnerability exploitable?

## Rules
- You MAY read nearby source code files to evaluate the defense
- Do NOT attempt runtime verification
- A defense function existing is NOT sufficient — you must verify it covers the exact sink/context
- Do NOT claim a defense is incomplete unless you can point to the exact sink/context mismatch in the code
- If your bypass depends on browser behavior, library semantics, encoding assumptions, or any behavior not explicit in the source, use "needs_runtime", not "weakened"
- Do NOT claim that a standard escaping or validation helper misses a character or case unless you can justify that claim from the code path and resulting sink fragment
- If the defense is genuinely valid and complete, say so

## Output Format

Return a single JSON object (no markdown fences, no explanation outside the JSON):

{
  "defenseValid": true | false,
  "reasoning": "detailed explanation of why the defense does or does not apply",
  "sinkRef": { "file": "path/to/file.py", "line": 42, "snippet": "exact sink or sink-adjacent code" },
  "bypassPath": "specific description of the remaining untrusted data flow after the defense",
  "proofPayload": "minimal payload showing the claimed bypass",
  "postDefenseSnippet": "the exact sink fragment or constructed string after the defense is applied",
  "assumptions": ["any behavior you had to assume rather than prove from source"],
  "overrideStatus": "weakened" | "needs_runtime"
}

- Set "defenseValid" to true if the defense fully covers the attack vector → no override needed (omit overrideStatus).
- Set "defenseValid" to false if the defense is incomplete or mismatched.
- Only set "overrideStatus" to "weakened" if you can provide all of: sinkRef, bypassPath, proofPayload, postDefenseSnippet, and an empty assumptions array.
- Set "overrideStatus" to "needs_runtime" if the gap is plausible but depends on unverified behavior, incomplete source coverage, or any non-empty assumptions list.
`;
}
