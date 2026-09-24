import type { SourceVerificationResult } from './source-verify-schemas.js';
import type { ServiceInfo } from './runtime-verify-schemas.js';

export interface RuntimeCandidateInfo {
  id: string;
  claim: string;
  sourceVerification?: SourceVerificationResult;
}

export function buildDockerSetupPrompt(
  repoRoot: string,
  targetId: string,
  projectName: string,
): string {
  return `You are a runtime environment setup agent. Your job is to start the target application using Docker so it can be probed for security vulnerabilities.

## Target
- Repository: \`${repoRoot}\`
- Target ID: ${targetId}
- Compose project name: ${projectName}

## Task

1. **Check Docker is running:** Run \`docker info\` to verify the Docker daemon is available.
2. **Find compose files:** Run \`find . -maxdepth 4 \\( -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' -o -name 'compose*.yml' -o -name 'compose*.yaml' \\) -not -path '*/node_modules/*'\` to locate Docker Compose files.
3. **Start services:** Run \`COMPOSE_PROJECT_NAME=${projectName} docker compose up --build -d\` from the directory containing the compose file. If multiple compose files exist, pick the one most likely to start the main application.
4. **Wait for health:** Run \`docker compose ps\` and check that services are running. If there are health checks, wait briefly and check again.
5. **Identify ports:** Run \`docker ps --format '{{.Ports}}'\` or inspect compose output to find published ports.

## Budget
You have 8 shell commands. Use them wisely — do not repeat commands unnecessarily.

## Environment variables
- You CANNOT write or edit files (the shell policy blocks file creation/mutation).
- If the compose file needs environment variables (e.g., API keys, database URLs), pass them
  inline on the docker compose command: \`KEY=value OTHER=value docker compose up -d\`
- For required secrets/keys, use dummy test values: \`MASTER_KEY=sk-test-1234\`,
  \`DATABASE_URL=postgresql://user:pass@db:5432/fixture-target\`, \`API_KEY=test-key\`, etc.
- Read the docker-compose file first to identify required env vars before starting.

## Rules
- Do NOT install packages on the host
- Do NOT edit files, create files, or mutate git state
- Do NOT run the application outside Docker
- If Docker is not available or compose fails, report failure honestly

## Output Format

Return a single JSON object (no markdown fences, no explanation outside the JSON):

{
  "success": true | false,
  "baseUrl": "http://localhost:<port>",
  "ports": ["<port1>", "<port2>"],
  "composeCwd": "relative/path/to/compose/dir",
  "composeFiles": ["docker-compose.yml"],
  "projectName": "${projectName}",
  "log": "brief description of what happened"
}
`;
}

export function buildPerCandidateRuntimePrompt(
  candidate: RuntimeCandidateInfo,
  repoRoot: string,
  targetId: string,
  serviceInfo: ServiceInfo,
): string {
  const sourceContext = candidate.sourceVerification
    ? buildSourceContext(candidate.sourceVerification)
    : '';

  const portsInfo = serviceInfo.ports.length > 0
    ? `Exposed ports: ${serviceInfo.ports.join(', ')}`
    : 'No ports detected';

  return `You are a runtime verification agent. Your job is to probe ONE specific security finding against a running instance of the target application.

## Target
- Repository: \`${repoRoot}\`
- Target ID: ${targetId}
- Service base URL: ${serviceInfo.baseUrl ?? 'unknown'}
- ${portsInfo}

## Candidate Finding
- **ID**: ${candidate.id}
- **Claim**: ${candidate.claim}

${sourceContext}
## Task

**CRITICAL: You MUST call http_request or shell_exec before producing your JSON verdict.
Do NOT generate a verdict without first making at least one real tool call to probe the
service. Any verdict produced without tool calls will be mechanically rejected.**

1. **Verify the service is reachable.** Call \`http_request\` with \`GET ${serviceInfo.baseUrl ?? 'http://localhost:4000'}/\`.
   This is mandatory — do it NOW as your first action. If it responds with HTTP 200, the service is up.
   If it fails, try \`shell_exec\` with \`curl -s -o /dev/null -w '%{http_code}' ${serviceInfo.baseUrl ?? 'http://localhost:4000'}/\`
   before reporting blocked.
2. **Identify the attack surface.** If source evidence is provided above, use the identified endpoints.
   If no source evidence is available, use read_file to find the relevant route or handler, then probe.
3. **Probe the finding.** Use \`http_request\` for HTTP endpoints. Use \`shell_exec\` with \`docker exec\`
   or local commands for non-HTTP reproducers. You MUST make at least one probe attempt.
4. **Capture evidence.** Record the exact commands, HTTP requests, and responses that demonstrate the
   vulnerability (or show it's not reproducible).
5. **Classify the result.**

## Budget
You have 5 shell commands and 5 HTTP requests. Source verification is complete — do NOT re-explore source code. Focus on runtime probing.

## Rules
- You MUST use at least one tool (http_request or shell_exec) before returning your verdict
- Do NOT read source files unless absolutely necessary to construct a probe (use read_file sparingly, budget: 3)
- Do NOT install packages, edit files, or mutate git state
- Do NOT probe external hosts — only probe the local Docker service
- If the service is not running or the endpoint doesn't exist, report it as blocked
- Set pvrReady to true ONLY if you have clear runtime evidence confirming a HIGH/CRITICAL severity issue with a distinct reproducer

## Evidence quality requirements
- **reproducerOutput** MUST contain the actual raw response body, headers, or error output from
  the server — NOT your summary or interpretation. Copy the exact text the server returned.
- **httpEvidence[].snippet** MUST be a verbatim excerpt from the HTTP response body, not your
  description of it.
- **Source cross-check:** If you name a specific control surface in your claim (header name,
  query parameter, config key, endpoint path), you MUST have confirmed that the target code
  actually reads/uses that input. If you have no source evidence, use read_file to verify
  the control exists before claiming it. Do NOT invent header names or parameters.
- A 4xx/5xx error code alone does NOT confirm a vulnerability. You must show the response
  body proves the server processed your malicious input (e.g., internal data leaked,
  connection to internal host attempted, error referencing the injected value).

## Output Format

Return a single JSON object (no markdown fences, no explanation outside the JSON):

{
  "candidateId": "${candidate.id}",
  "claim": "the original claim in your own words",
  "status": "confirmed" | "partially_confirmed" | "not_reproducible" | "blocked" | "refuted",
  "rootCause": "specific description of the confirmed root cause",
  "reproducerCommands": ["exact command 1", "exact command 2"],
  "reproducerOutput": "EXACT raw output from the server (copy-paste, not summary)",
  "httpEvidence": [
    { "url": "http://localhost:PORT/path", "method": "POST", "statusCode": 200, "snippet": "VERBATIM excerpt from response body" }
  ],
  "severity": "critical" | "high" | "medium" | "low" | "info",
  "pvrReady": false,
  "filingNotes": "why this should or should not be filed as a PVR",
  "suggestedFix": "brief description of how to fix",
  "regressionTest": "brief description of a test that would catch this",
  "blocker": "if status is blocked, what prevented reproduction",
  "confidence": 0.0 to 1.0
}
`;
}

function buildSourceContext(sv: SourceVerificationResult): string {
  const parts = [
    '### Source Verification Evidence (pre-verified)',
    `- **Status**: ${sv.status} (confidence: ${sv.confidence})`,
    `- **Root cause**: ${sv.rootCause}`,
  ];

  if (sv.sourceRefs.length > 0) {
    parts.push('- **Source references**:');
    for (const ref of sv.sourceRefs) {
      const loc = ref.line ? `${ref.file}:${ref.line}` : ref.file;
      parts.push(`  - \`${loc}\`: ${ref.snippet}`);
    }
  }

  if (sv.exploitPath) {
    parts.push(`- **Exploit path**: ${sv.exploitPath}`);
  }

  if (sv.runtimePlan) {
    parts.push(`- **Suggested runtime test**: ${sv.runtimePlan}`);
  }

  if (sv.preconditions.length > 0) {
    parts.push(`- **Preconditions**: ${sv.preconditions.join('; ')}`);
  }

  parts.push('');
  return parts.join('\n');
}
