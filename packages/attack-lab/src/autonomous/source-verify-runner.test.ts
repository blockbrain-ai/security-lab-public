import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  extractCandidatesFromReport,
  extractCandidatesFromCampaign,
  extractCandidatesFromAssessmentObject,
  extractCandidatesFromEmbeddedAssessment,
  extractCandidatesFromPacket,
  extractCandidatesFromEvents,
  CandidateAccumulator,
  resolveDefendedFindingStatus,
  resolveDefenseCriticOverride,
} from './source-verify-runner.js';
import {
  SourceVerificationResultSchema,
  DefenseCriticResultSchema,
  validateSupportedRefs,
} from './source-verify-schemas.js';
import {
  buildPerCandidateSourcePrompt,
  buildBugClassAuditPrompt,
  buildDefenseCriticPrompt,
} from './source-verify-prompts.js';

// ---------------------------------------------------------------------------
// Candidate extraction from report markdown
// ---------------------------------------------------------------------------

test('extractCandidatesFromReport extracts evidence leads', () => {
  const report = `# Security Lab Investigation Report

## Evidence Leads (Top 20 — not final verdicts)

- **[ws-1-11]** (code, conf=0.90, active) No SSRF protection patterns found in pass-through endpoints. | assets=fixture-target/proxy/pass_through_endpoints/
- **[ws-3-17]** (code, conf=0.85, active) JWT admin scope check allows bypassing standard key-based auth. | assets=fixture-target/proxy/auth/handle_jwt.py
- **[ws-0-1]** (code, conf=0.70, promoted) MCP management endpoints allow creation of external MCP servers. | assets=fixture-target/proxy/management_endpoints/mcp_management_endpoints.py

---

## What Was Tried And Failed
`;

  const candidates = extractCandidatesFromReport(report);
  assert.equal(candidates.length, 3);
  assert.equal(candidates[0]!.id, 'ws-1-11');
  assert.match(candidates[0]!.claim, /SSRF/);
  assert.match(candidates[0]!.context, /pass_through_endpoints/);
  assert.equal(candidates[1]!.id, 'ws-3-17');
  assert.equal(candidates[2]!.id, 'ws-0-1');
});

test('extractCandidatesFromReport returns empty for report with no leads', () => {
  const report = `# Security Lab Investigation Report

## Evidence Leads (Top 20 — not final verdicts)

(none)

---

## What Was Tried And Failed
`;

  const candidates = extractCandidatesFromReport(report);
  assert.equal(candidates.length, 0);
});

test('extractCandidatesFromReport handles leads without assets', () => {
  const report = `## Evidence Leads (Top 20)

- **[sig-1]** (code, conf=0.60, active) Some finding without asset references.

---
`;

  const candidates = extractCandidatesFromReport(report);
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0]!.id, 'sig-1');
  assert.equal(candidates[0]!.context, '');
});

// ---------------------------------------------------------------------------
// Per-candidate prompt construction
// ---------------------------------------------------------------------------

test('buildPerCandidateSourcePrompt includes candidate info and repo root', () => {
  const prompt = buildPerCandidateSourcePrompt(
    { id: 'ws-1-11', claim: 'SSRF via pass-through', context: 'assets=foo.py' },
    '/repo/fixture-target',
    'fixture-target-proxy',
  );

  assert.match(prompt, /ws-1-11/);
  assert.match(prompt, /SSRF via pass-through/);
  assert.match(prompt, /\/repo\/fixture-target/);
  assert.match(prompt, /fixture-target-proxy/);
  assert.match(prompt, /candidateId/);
  assert.match(prompt, /sourceRefs/);
});

test('buildPerCandidateSourcePrompt does not contain target-specific patterns', () => {
  const prompt = buildPerCandidateSourcePrompt(
    { id: 'test-1', claim: 'test claim', context: '' },
    '/repo/target',
    'generic-target',
  );

  assert.doesNotMatch(prompt, /fixture-target/i);
  assert.doesNotMatch(prompt, /ACME_INTERNAL_TARGET/i);
  assert.doesNotMatch(prompt, /ACME_INTERNAL_TARGET/i);
});

test('buildPerCandidateSourcePrompt prohibits runtime verification', () => {
  const prompt = buildPerCandidateSourcePrompt(
    { id: 'test-1', claim: 'test claim', context: '' },
    '/repo/target',
    'generic-target',
  );

  // The prompt should tell the model NOT to do runtime verification
  assert.match(prompt, /Do NOT attempt runtime verification/);
  assert.match(prompt, /Do NOT make filing decisions/);
});

// ---------------------------------------------------------------------------
// Bug-class audit prompt construction
// ---------------------------------------------------------------------------

test('buildBugClassAuditPrompt excludes existing candidate IDs', () => {
  const prompt = buildBugClassAuditPrompt(
    '/repo/target',
    'test-target',
    ['ws-1-11', 'ws-3-17'],
  );

  assert.match(prompt, /ws-1-11/);
  assert.match(prompt, /ws-3-17/);
  assert.match(prompt, /Do NOT duplicate/);
  assert.match(prompt, /Config\/default fail-open/);
  assert.match(prompt, /Route\/auth inconsistency/);
});

test('buildBugClassAuditPrompt does not contain target-specific patterns', () => {
  const prompt = buildBugClassAuditPrompt('/repo/target', 'test-target', []);

  // Generic header names like X-Forwarded-For are part of the bug-class
  // description (the class itself), not target-specific patterns.
  assert.doesNotMatch(prompt, /fixture-target/i);
  assert.doesNotMatch(prompt, /master_key/i);
  assert.doesNotMatch(prompt, /user_api_key_auth/i);
});

// ---------------------------------------------------------------------------
// Schema validation
// ---------------------------------------------------------------------------

test('SourceVerificationResultSchema parses valid supported result', () => {
  const input = {
    candidateId: 'ws-1-11',
    claim: 'SSRF via pass-through',
    status: 'supported',
    evidenceClass: 'multi_site_flow',
    rootCause: 'No URL validation in pass_through_request()',
    sourceRefs: [
      { file: 'fixture-target/proxy/pass_through.py', line: 42, snippet: 'httpx.request(url)' },
      { file: 'fixture-target/proxy/config.py', line: 10, snippet: 'base_target_url = ""' },
    ],
    preconditions: ['Attacker controls base_target_url'],
    confidence: 0.85,
  };

  const result = SourceVerificationResultSchema.parse(input);
  assert.equal(result.status, 'supported');
  assert.equal(result.sourceRefs.length, 2);
});

test('SourceVerificationResultSchema parses needs_runtime with error', () => {
  const input = {
    candidateId: 'ws-3-17',
    claim: 'JWT bypass',
    status: 'needs_runtime',
    rootCause: 'Could not determine from source',
    sourceRefs: [],
    preconditions: [],
    error: 'structured_parse_failure',
    confidence: 0,
  };

  const result = SourceVerificationResultSchema.parse(input);
  assert.equal(result.status, 'needs_runtime');
  assert.equal(result.error, 'structured_parse_failure');
});

test('SourceVerificationResultSchema defaults sourceRefs to empty array', () => {
  const input = {
    candidateId: 'test',
    claim: 'test',
    status: 'refuted',
    rootCause: 'not real',
    preconditions: [],
    confidence: 0.1,
  };

  const result = SourceVerificationResultSchema.parse(input);
  assert.deepEqual(result.sourceRefs, []);
});

// ---------------------------------------------------------------------------
// Validation rules
// ---------------------------------------------------------------------------

test('validateSupportedRefs requires 2 refs for multi-site supported', () => {
  const result = {
    candidateId: 'test',
    claim: 'test',
    status: 'supported' as const,
    evidenceClass: 'multi_site_flow' as const,
    rootCause: 'test',
    sourceRefs: [{ file: 'a.py', snippet: 'x' }],
    preconditions: [],
    defenseMechanismsObserved: [],
    confidence: 0.8,
  };

  const warning = validateSupportedRefs(result);
  assert.ok(warning);
  assert.match(warning, /at least 2/);
});

test('validateSupportedRefs accepts 1 ref for single_site_default', () => {
  const result = {
    candidateId: 'test',
    claim: 'test',
    status: 'supported' as const,
    evidenceClass: 'single_site_default' as const,
    rootCause: 'test',
    sourceRefs: [{ file: 'a.py', snippet: 'x' }],
    preconditions: [],
    defenseMechanismsObserved: [],
    confidence: 0.8,
  };

  const warning = validateSupportedRefs(result);
  assert.equal(warning, null);
});

test('validateSupportedRefs skips non-supported statuses', () => {
  const result = {
    candidateId: 'test',
    claim: 'test',
    status: 'refuted' as const,
    rootCause: 'test',
    sourceRefs: [],
    preconditions: [],
    defenseMechanismsObserved: [],
    confidence: 0.1,
  };

  const warning = validateSupportedRefs(result);
  assert.equal(warning, null);
});

// ---------------------------------------------------------------------------
// Phase 5a — Candidate rescue: CandidateAccumulator dedup
// ---------------------------------------------------------------------------

test('CandidateAccumulator deduplicates by exact ID', () => {
  const acc = new CandidateAccumulator();
  acc.add({ id: 'a', claim: 'SSRF in proxy', context: '' });
  acc.add({ id: 'a', claim: 'SSRF in proxy endpoint', context: 'more context' });
  assert.equal(acc.size, 1);
  assert.equal(acc.getAll()[0]!.claim, 'SSRF in proxy');
});

test('CandidateAccumulator deduplicates by normalized description substring', () => {
  const acc = new CandidateAccumulator();
  acc.add({ id: 'a', claim: 'SSRF via proxy', context: '' });
  acc.add({ id: 'b', claim: 'SSRF via proxy endpoint allows internal requests', context: '' });
  assert.equal(acc.size, 1);
  // Keeps the longer one
  assert.equal(acc.getAll()[0]!.id, 'b');
});

test('CandidateAccumulator keeps distinct claims', () => {
  const acc = new CandidateAccumulator();
  acc.add({ id: 'a', claim: 'SSRF in proxy', context: '' });
  acc.add({ id: 'b', claim: 'XSS in template rendering', context: '' });
  assert.equal(acc.size, 2);
});

// ---------------------------------------------------------------------------
// Phase 5a — extractCandidatesFromAssessmentObject
// ---------------------------------------------------------------------------

test('extractCandidatesFromAssessmentObject extracts from all 4 categories', () => {
  const acc = new CandidateAccumulator();
  const assessment = {
    confirmedVulnerabilities: [{ title: 'SSRF confirmed', severity: 'critical', description: 'SSRF in proxy' }],
    validatedRisks: [{ title: 'Weak auth', severity: 'high', description: 'Weak auth check' }],
    configurationRisks: [{ title: 'Debug mode', severity: 'medium', description: 'Debug enabled by default' }],
    unconfirmedLeads: [{ title: 'Possible XSS', severity: 'low', description: 'Possible XSS in template' }],
  };
  extractCandidatesFromAssessmentObject(assessment, 'test', acc);
  assert.equal(acc.size, 4);
  const ids = acc.getAll().map(c => c.id);
  assert.ok(ids.some(id => id.includes('confirmedVulnerabilities')));
  assert.ok(ids.some(id => id.includes('unconfirmedLeads')));
});

test('extractCandidatesFromAssessmentObject preserves severity metadata', () => {
  const acc = new CandidateAccumulator();
  extractCandidatesFromAssessmentObject(
    { confirmedVulnerabilities: [{ title: 'SSRF', severity: 'critical', description: 'SSRF desc' }] },
    'test', acc,
  );
  assert.equal(acc.getAll()[0]!.severity, 'critical');
});

// ---------------------------------------------------------------------------
// Phase 5a — extractCandidatesFromEmbeddedAssessment
// ---------------------------------------------------------------------------

test('extractCandidatesFromEmbeddedAssessment extracts from JSON-in-string summary', () => {
  const acc = new CandidateAccumulator();
  const assessment = {
    summary: JSON.stringify({
      configurationRisks: [{ title: 'CORS misconfiguration', severity: 'high', description: 'CORS allows *' }],
    }),
  };
  extractCandidatesFromEmbeddedAssessment(assessment, acc);
  assert.equal(acc.size, 1);
  assert.match(acc.getAll()[0]!.claim, /CORS/);
  assert.ok(acc.getAll()[0]!.source?.startsWith('embedded_summary'));
});

test('extractCandidatesFromEmbeddedAssessment extracts from JSON-in-string executiveSummary', () => {
  const acc = new CandidateAccumulator();
  const assessment = {
    executiveSummary: JSON.stringify({
      unconfirmedLeads: [{ title: 'Deserialization risk', description: 'Pickle loads from user input' }],
    }),
  };
  extractCandidatesFromEmbeddedAssessment(assessment, acc);
  assert.equal(acc.size, 1);
  assert.match(acc.getAll()[0]!.claim, /Deserialization/);
});

test('extractCandidatesFromEmbeddedAssessment ignores non-JSON strings', () => {
  const acc = new CandidateAccumulator();
  extractCandidatesFromEmbeddedAssessment({ summary: 'just a plain text summary' }, acc);
  assert.equal(acc.size, 0);
});

// ---------------------------------------------------------------------------
// Phase 5a — extractCandidatesFromPacket
// ---------------------------------------------------------------------------

test('extractCandidatesFromPacket extracts hypotheses, findings, and signals', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'sv-packet-'));
  try {
    const packet = {
      campaignId: 'test',
      targetId: 'target',
      targetLabel: 'Target',
      targetKind: 'webapp',
      environment: 'test',
      mode: 'declared',
      iterations: 1,
      totalCostUsd: 0,
      evidenceDigest: '',
      confirmedFindings: [
        { id: 'f1', severity: 'critical', description: 'SSRF confirmed', reproductionSteps: ['curl...'], remediationSuggestion: 'fix', involvedDormantReactivation: false, confirmedAt: '' },
      ],
      testedHypotheses: [
        { id: 'h1', severity: 'high', status: 'testing', description: 'Bash tool injection', signalIds: ['s1'], relatedAssets: ['tool.py'] },
      ],
      topSignals: [
        { id: 's1', surface: 'code', confidence: 0.85, status: 'active', description: 'Command injection pattern', relatedAssets: ['exec.py'] },
        { id: 's2', surface: 'code', confidence: 0.3, status: 'active', description: 'Low confidence signal', relatedAssets: [] },
        { id: 's3', surface: 'code', confidence: 0.7, status: 'refuted', description: 'Refuted signal', relatedAssets: [] },
      ],
      modelActivity: [],
    };
    await writeFile(join(dir, 'campaign-assessment.packet.json'), JSON.stringify(packet), 'utf8');
    const acc = new CandidateAccumulator();
    await extractCandidatesFromPacket(dir, acc);
    const all = acc.getAll();
    assert.ok(all.some(c => c.source === 'packet_finding'), 'should have packet finding');
    assert.ok(all.some(c => c.source === 'packet_hypothesis'), 'should have packet hypothesis');
    assert.ok(all.some(c => c.source === 'packet_signal'), 'should have packet signal');
    // Low-confidence and refuted signals should be excluded
    assert.ok(!all.some(c => c.claim.includes('Low confidence')), 'should skip low-confidence signals');
    assert.ok(!all.some(c => c.claim.includes('Refuted signal')), 'should skip refuted signals');
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('extractCandidatesFromPacket returns gracefully when file is missing', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'sv-no-packet-'));
  try {
    const acc = new CandidateAccumulator();
    await extractCandidatesFromPacket(dir, acc);
    assert.equal(acc.size, 0);
  } finally {
    await rm(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// Phase 5a — extractCandidatesFromEvents
// ---------------------------------------------------------------------------

test('extractCandidatesFromEvents extracts planner_hypothesis_grounded events', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'sv-events-'));
  try {
    const events = [
      JSON.stringify({ stage: 'planner_hypothesis_grounded', payload: { description: 'Deserialization via pickle', groundedSignalIds: ['s1', 's2'], iteration: 3 } }),
      JSON.stringify({ stage: 'planner_output', payload: { description: 'ignored' } }),
      JSON.stringify({ stage: 'planner_hypothesis_grounded', payload: { description: 'CORS bypass', groundedSignalIds: [], iteration: 5 } }),
    ];
    await writeFile(join(dir, 'events.jsonl'), events.join('\n'), 'utf8');
    const acc = new CandidateAccumulator();
    await extractCandidatesFromEvents(dir, acc);
    assert.equal(acc.size, 2);
    assert.ok(acc.getAll().some(c => c.claim.includes('Deserialization')));
    assert.ok(acc.getAll().some(c => c.claim.includes('CORS')));
    assert.equal(acc.getAll()[0]!.source, 'event_grounded');
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('extractCandidatesFromEvents returns gracefully when file is missing', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'sv-no-events-'));
  try {
    const acc = new CandidateAccumulator();
    await extractCandidatesFromEvents(dir, acc);
    assert.equal(acc.size, 0);
  } finally {
    await rm(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// Phase 5a — extractCandidatesFromCampaign (cumulative)
// ---------------------------------------------------------------------------

test('extractCandidatesFromCampaign combines all sources with dedup', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'sv-campaign-'));
  try {
    // Assessment JSON with empty arrays but embedded JSON in summary
    const assessment = {
      overallVerdict: 'high_priority_unconfirmed_leads',
      summary: JSON.stringify({
        configurationRisks: [{ title: 'CORS misconfiguration', severity: 'high', description: 'CORS allows wildcard' }],
      }),
      confirmedVulnerabilities: [],
      validatedRisks: [],
      configurationRisks: [],
      unconfirmedLeads: [],
    };
    await writeFile(join(dir, 'campaign-assessment.json'), JSON.stringify(assessment), 'utf8');

    // Packet with hypothesis
    const packet = {
      campaignId: 'test', targetId: 't', targetLabel: 'T', targetKind: 'webapp',
      environment: 'test', mode: 'declared', iterations: 1, totalCostUsd: 0,
      evidenceDigest: '', confirmedFindings: [],
      testedHypotheses: [{ id: 'h1', severity: 'critical', status: 'testing', description: 'Bash tool injection', signalIds: [], relatedAssets: [] }],
      topSignals: [], modelActivity: [],
    };
    await writeFile(join(dir, 'campaign-assessment.packet.json'), JSON.stringify(packet), 'utf8');

    // Events with grounded hypothesis
    const events = [
      JSON.stringify({ stage: 'planner_hypothesis_grounded', payload: { description: 'SSRF in proxy', groundedSignalIds: ['s1'], iteration: 1 } }),
    ];
    await writeFile(join(dir, 'events.jsonl'), events.join('\n'), 'utf8');

    const report = `## Evidence Leads (Top 20)

- **[ws-1]** (code, conf=0.90, active) SSRF in proxy endpoint | assets=proxy.py

---
`;
    const candidates = await extractCandidatesFromCampaign(dir, report);
    // Should have: CORS (embedded), Bash tool (packet hypothesis), SSRF (events), ws-1 (report — deduped with event SSRF)
    assert.ok(candidates.length >= 3, `expected >= 3 candidates, got ${candidates.length}`);
    assert.ok(candidates.some(c => c.claim.includes('CORS')), 'should include embedded CORS finding');
    assert.ok(candidates.some(c => c.claim.includes('Bash tool')), 'should include packet hypothesis');
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('extractCandidatesFromCampaign falls back to report when no artifacts exist', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'sv-empty-'));
  try {
    const report = `## Evidence Leads (Top 20)

- **[ws-1]** (code, conf=0.90, active) SSRF finding | assets=proxy.py

---
`;
    const candidates = await extractCandidatesFromCampaign(dir, report);
    assert.equal(candidates.length, 1);
    assert.equal(candidates[0]!.id, 'ws-1');
  } finally {
    await rm(dir, { recursive: true });
  }
});

test('extractCandidatesFromCampaign applies candidateLimit after dedup (via runner)', async () => {
  // CandidateAccumulator dedup + limit is tested directly here
  const acc = new CandidateAccumulator();
  for (let i = 0; i < 10; i++) {
    acc.add({ id: `c-${i}`, claim: `Unique finding ${i}`, context: '' });
  }
  assert.equal(acc.size, 10);
  const limited = acc.getAll().slice(0, 3);
  assert.equal(limited.length, 3);
});

// ---------------------------------------------------------------------------
// Phase 5b — Defense-bypass critic schemas
// ---------------------------------------------------------------------------

test('SourceVerificationResultSchema accepts defenseMechanismsObserved', () => {
  const input = {
    candidateId: 'test',
    claim: 'XSS in template',
    status: 'refuted',
    rootCause: 'html.escape covers it',
    sourceRefs: [{ file: 'views.py', line: 42, snippet: 'html.escape(user_input)' }],
    preconditions: [],
    defenseMechanismsObserved: ['html.escape() at views.py:42'],
    confidence: 0.7,
  };
  const result = SourceVerificationResultSchema.parse(input);
  assert.deepEqual(result.defenseMechanismsObserved, ['html.escape() at views.py:42']);
});

test('SourceVerificationResultSchema defaults defenseMechanismsObserved to empty array', () => {
  const input = {
    candidateId: 'test',
    claim: 'test',
    status: 'supported',
    rootCause: 'test',
    preconditions: [],
    confidence: 0.5,
  };
  const result = SourceVerificationResultSchema.parse(input);
  assert.deepEqual(result.defenseMechanismsObserved, []);
  assert.deepEqual(result.assumptions, []);
  assert.deepEqual(result.validationNotes, []);
});

test('DefenseCriticResultSchema parses valid critic output', () => {
  const input = {
    defenseValid: false,
    reasoning: 'html.escape does not cover JavaScript context in onclick handler',
    sinkRef: { file: 'views.py', line: 88, snippet: 'onclick="' },
    bypassPath: 'user input reaches onclick after html.escape',
    proofPayload: '" onmouseover="alert(1)',
    postDefenseSnippet: 'onclick="" onmouseover="alert(1)"',
    overrideStatus: 'needs_runtime',
  };
  const result = DefenseCriticResultSchema.parse(input);
  assert.equal(result.defenseValid, false);
  assert.equal(result.overrideStatus, 'needs_runtime');
  assert.equal(result.assumptions.length, 0);
});

test('DefenseCriticResultSchema cannot produce supported status', () => {
  assert.throws(() => {
    DefenseCriticResultSchema.parse({
      defenseValid: false,
      reasoning: 'test',
      overrideStatus: 'supported',
    });
  });
});

test('DefenseCriticResultSchema allows omitting overrideStatus when defense is valid', () => {
  const result = DefenseCriticResultSchema.parse({
    defenseValid: true,
    reasoning: 'The defense covers all attack vectors in this context',
  });
  assert.equal(result.defenseValid, true);
  assert.equal(result.overrideStatus, undefined);
  assert.deepEqual(result.assumptions, []);
});

// ---------------------------------------------------------------------------
// Phase 5b — buildDefenseCriticPrompt
// ---------------------------------------------------------------------------

test('buildDefenseCriticPrompt includes defenses, source refs, and bypass categories', () => {
  const prompt = buildDefenseCriticPrompt(
    { id: 'xss-1', claim: 'XSS in template rendering', context: '' },
    {
      status: 'refuted',
      rootCause: 'html.escape applied to all user input',
      sourceRefs: [{ file: 'views.py', line: 45, snippet: 'html.escape(user_input)' }],
      exploitPath: 'Inject via comment field',
      defenseMechanismsObserved: ['html.escape() at views.py:45', 'CSP header in middleware.py:12'],
    },
    '/repo/target',
  );
  assert.match(prompt, /html\.escape\(\) at views\.py:45/);
  assert.match(prompt, /CSP header/);
  assert.match(prompt, /views\.py:45/);
  assert.match(prompt, /Context-breaking payloads/);
  assert.match(prompt, /Wrong-layer escaping/);
  assert.match(prompt, /Encoding gaps/);
  assert.match(prompt, /Parser differentials/);
  assert.match(prompt, /Conditional defenses/);
  assert.match(prompt, /Feature-gated controls/);
  assert.match(prompt, /proof obligation/i);
  assert.match(prompt, /postDefenseSnippet/);
  assert.match(prompt, /assumptions/);
  assert.match(prompt, /needs_runtime", not "weakened"/);
});

test('buildDefenseCriticPrompt contains no target-specific strings', () => {
  const prompt = buildDefenseCriticPrompt(
    { id: 'test-1', claim: 'test', context: '' },
    {
      status: 'refuted',
      rootCause: 'defense exists',
      sourceRefs: [],
      defenseMechanismsObserved: ['some_defense()'],
    },
    '/repo/generic',
  );
  assert.doesNotMatch(prompt, /fixture-target/i);
  assert.doesNotMatch(prompt, /ACME_INTERNAL_TARGET/i);
  assert.doesNotMatch(prompt, /ACME_INTERNAL_TARGET/i);
  assert.doesNotMatch(prompt, /fixture-app/i);
});

test('resolveDefenseCriticOverride keeps weakened only when proof obligations are satisfied', () => {
  const decision = resolveDefenseCriticOverride(DefenseCriticResultSchema.parse({
    defenseValid: false,
    reasoning: 'The sink still receives executable content after the defense.',
    sinkRef: { file: 'views.py', line: 120, snippet: 'dangerouslySetInnerHTML = html' },
    bypassPath: 'user input is escaped for HTML text, then reinserted into a raw script template',
    proofPayload: '</script><script>alert(1)</script>',
    postDefenseSnippet: '</script><script>alert(1)</script>',
    assumptions: [],
    overrideStatus: 'weakened',
  }));

  assert.deepEqual(decision, {
    status: 'weakened',
    notes: 'The sink still receives executable content after the defense.',
  });
});

test('resolveDefenseCriticOverride downgrades weakened to needs_runtime when proof is incomplete', () => {
  const decision = resolveDefenseCriticOverride(DefenseCriticResultSchema.parse({
    defenseValid: false,
    reasoning: 'The defense may be bypassed, but the exact post-defense output was not proven.',
    sinkRef: { file: 'views.py', line: 120, snippet: 'dangerouslySetInnerHTML = html' },
    bypassPath: 'user input may still control the sink',
    assumptions: [],
    overrideStatus: 'weakened',
  }));

  assert.equal(decision?.status, 'needs_runtime');
  assert.match(decision?.notes ?? '', /downgraded override to needs_runtime/i);
});

test('resolveDefenseCriticOverride downgrades weakened to needs_runtime when assumptions remain', () => {
  const decision = resolveDefenseCriticOverride(DefenseCriticResultSchema.parse({
    defenseValid: false,
    reasoning: 'The bypass depends on browser parsing behavior that was not proven from source.',
    sinkRef: { file: 'views.py', line: 120, snippet: 'innerHTML = html' },
    bypassPath: 'escaped content may be reparsed by the browser',
    proofPayload: '<svg/onload=alert(1)>',
    postDefenseSnippet: '&lt;svg/onload=alert(1)&gt;',
    assumptions: ['browser reparses this fragment into executable markup'],
    overrideStatus: 'weakened',
  }));

  assert.equal(decision?.status, 'needs_runtime');
  assert.match(decision?.notes ?? '', /Assumptions:/);
});

test('resolveDefenseCriticOverride keeps refuted when critic lacks a concrete sink reference', () => {
  const decision = resolveDefenseCriticOverride(DefenseCriticResultSchema.parse({
    defenseValid: false,
    reasoning: 'The defense might not apply everywhere.',
    bypassPath: 'unclear',
    overrideStatus: 'needs_runtime',
  }));

  assert.equal(decision, null);
});

// ---------------------------------------------------------------------------
// Phase 5c — Bug-class audit prompt
// ---------------------------------------------------------------------------

test('buildBugClassAuditPrompt includes all 11 bug classes', () => {
  const prompt = buildBugClassAuditPrompt('/repo', 'target', []);
  assert.match(prompt, /Config\/default fail-open/);
  assert.match(prompt, /Auth\/session\/state fixation/);
  assert.match(prompt, /Trusted proxy/);
  assert.match(prompt, /Route\/auth inconsistency/);
  assert.match(prompt, /Python sandbox escape/);
  assert.match(prompt, /Deserialization/);
  assert.match(prompt, /SSRF/);
  assert.match(prompt, /XSS context-sensitive/);
  assert.match(prompt, /Command execution tool boundaries/);
  assert.match(prompt, /CORS credential exposure/);
  assert.match(prompt, /Rate-limit/);
});

test('buildBugClassAuditPrompt new bug classes contain no target-specific strings', () => {
  const prompt = buildBugClassAuditPrompt('/repo', 'target', []);
  assert.doesNotMatch(prompt, /fixture-target/i);
  assert.doesNotMatch(prompt, /fixture-app/i);
  assert.doesNotMatch(prompt, /adk.python/i);
  assert.doesNotMatch(prompt, /fixture-app/i);
  assert.doesNotMatch(prompt, /ucp.proxy/i);
});

test('buildBugClassAuditPrompt output includes defenseMechanismsObserved', () => {
  const prompt = buildBugClassAuditPrompt('/repo', 'target', []);
  assert.match(prompt, /defenseMechanismsObserved/);
  assert.match(prompt, /residualSinkRef/);
  assert.match(prompt, /proofPayload/);
});

test('buildPerCandidateSourcePrompt includes defense mechanism listing step', () => {
  const prompt = buildPerCandidateSourcePrompt(
    { id: 'test-1', claim: 'test', context: '' },
    '/repo', 'target',
  );
  assert.match(prompt, /defense mechanisms/i);
  assert.match(prompt, /defenseMechanismsObserved/);
  assert.match(prompt, /sanitization, escaping, validation/);
  assert.match(prompt, /Proof obligation for defended positive findings/);
  assert.match(prompt, /residualSinkRef/);
  assert.match(prompt, /postDefenseSnippet/);
});

test('resolveDefendedFindingStatus downgrades false weakening with incomplete defense bypass proof', () => {
  const decision = resolveDefendedFindingStatus(SourceVerificationResultSchema.parse({
    candidateId: 'xss-1',
    claim: 'Potential XSS in HTML visualization',
    status: 'weakened',
    evidenceClass: 'multi_site_flow',
    rootCause: 'innerHTML may render attacker HTML after json.dumps',
    sourceRefs: [
      { file: 'fixture-app/visualization.py', line: 449, snippet: 'js_data = json.dumps(extraction_data)' },
      { file: 'fixture-app/visualization.py', line: 499, snippet: "innerHTML = extraction.attributesHtml" },
    ],
    exploitPath: 'Attacker controls HTML that later reaches innerHTML.',
    preconditions: ['Browser renders the visualization.'],
    defenseMechanismsObserved: ['json.dumps at visualization.py:449'],
    confidence: 0.85,
  }));

  assert.equal(decision?.status, 'needs_runtime');
  assert.match((decision?.notes ?? []).join(' '), /residual-risk proof obligations/i);
  assert.match((decision?.notes ?? []).join(' '), /Missing residualSinkRef/);
});

test('resolveDefendedFindingStatus preserves plugin-chain weakening with concrete residual proof', () => {
  const decision = resolveDefendedFindingStatus(SourceVerificationResultSchema.parse({
    candidateId: 'plugin-1',
    claim: 'Dynamic provider entry points can load malicious plugin code',
    status: 'weakened',
    evidenceClass: 'multi_site_flow',
    rootCause: 'Plugins are enabled by default but can be disabled via env var.',
    sourceRefs: [
      { file: 'fixture-app/providers/router.py', line: 83, snippet: 'importlib.import_module(module_path)' },
      { file: 'fixture-app/providers/__init__.py', line: 44, snippet: 'for entry_point in metadata.entry_points()' },
    ],
    exploitPath: 'A malicious installed provider package is discovered and imported.',
    preconditions: ['Attacker can influence installed packages.', 'LANGEXTRACT_DISABLE_PLUGINS is unset.'],
    defenseMechanismsObserved: ['LANGEXTRACT_DISABLE_PLUGINS opt-out at providers/__init__.py:22'],
    residualSinkRef: { file: 'fixture-app/providers/router.py', line: 83, snippet: 'module = importlib.import_module(module_path)' },
    residualBypassPath: 'Default startup loads provider entry points, then register_lazy imports attacker-controlled module_path.',
    proofPayload: 'malicious-provider = "attacker_pkg.provider:BackdoorProvider"',
    postDefenseSnippet: 'if not disable_plugins: entry_point.load() -> importlib.import_module(module_path)',
    assumptions: [],
    confidence: 0.6,
  }));

  assert.deepEqual(decision, {
    status: 'weakened',
    notes: [],
  });
});

test('resolveDefendedFindingStatus leaves undefended SSRF findings unchanged', () => {
  const decision = resolveDefendedFindingStatus(SourceVerificationResultSchema.parse({
    candidateId: 'ssrf-1',
    claim: 'requests.get() without SSRF protections',
    status: 'supported',
    evidenceClass: 'multi_site_flow',
    rootCause: 'download_text_from_url calls requests.get(url) without host validation.',
    sourceRefs: [
      { file: 'fixture-app/io.py', line: 262, snippet: 'response = requests.get(url)' },
      { file: 'fixture-app/extraction.py', line: 224, snippet: 'text_or_documents = io.download_text_from_url(text_or_documents)' },
    ],
    preconditions: ['Attacker controls URL input.'],
    defenseMechanismsObserved: [],
    confidence: 0.95,
  }));

  assert.equal(decision, null);
});

test('resolveDefenseCriticOverride downgrades N/A placeholders to needs_runtime', () => {
  const decision = resolveDefenseCriticOverride(DefenseCriticResultSchema.parse({
    defenseValid: false,
    reasoning: 'The cited defense does not exist in the file.',
    sinkRef: { file: 'visualization.py', line: 1, snippet: '# Copyright 2025 Google LLC' },
    bypassPath: 'The cited defense is absent.',
    proofPayload: 'N/A',
    postDefenseSnippet: 'N/A',
    assumptions: [],
    overrideStatus: 'weakened',
  }));

  assert.equal(decision?.status, 'needs_runtime');
  assert.match(decision?.notes ?? '', /Missing proofPayload/);
});

test('resolveDefendedFindingStatus rejects placeholder proof values', () => {
  const decision = resolveDefendedFindingStatus(SourceVerificationResultSchema.parse({
    candidateId: 'test-placeholder',
    claim: 'XSS in visualization',
    status: 'weakened',
    rootCause: 'Some root cause',
    sourceRefs: [{ file: 'a.py', line: 1, snippet: 'code' }],
    preconditions: [],
    defenseMechanismsObserved: ['html.escape() at views.py:45'],
    residualSinkRef: { file: 'views.py', line: 99, snippet: 'innerHTML = data' },
    residualBypassPath: 'data flow bypasses defense',
    proofPayload: 'none',
    postDefenseSnippet: 'N/A',
    confidence: 0.9,
  }));

  assert.equal(decision?.status, 'needs_runtime');
  assert.ok(decision?.notes.some(n => n.includes('proofPayload/postDefenseSnippet')));
});
