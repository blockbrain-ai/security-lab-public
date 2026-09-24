import test from 'node:test';
import assert from 'node:assert/strict';
import type { InvokeOptions, ModelAdapter, ModelResponse } from '../providers/contracts.js';
import {
  buildDeterministicCampaignAssessment,
  reviewCampaignAssessment,
  runCampaignAssessmentPanel,
  synthesizeCampaignAssessment,
  toCampaignAssessmentArtifact,
  type CampaignAssessmentPacket,
} from './campaign-assessment.js';

class StaticAdapter implements ModelAdapter {
  readonly provider = 'test';
  readonly model = 'static-assessor';

  constructor(private readonly content: string) {}

  async invoke<T = unknown>(_options: InvokeOptions<T>): Promise<ModelResponse<T>> {
    return {
      content: this.content,
      usage: {
        inputTokens: 100,
        outputTokens: 200,
        costUsd: 0.02,
      },
      durationMs: 1,
      provider: this.provider,
      model: this.model,
    };
  }
}

function createPacket(): CampaignAssessmentPacket {
  return {
    campaignId: 'campaign-1',
    targetId: 'fixture-static',
    targetLabel: 'Fixture Static',
    targetKind: 'code',
    environment: 'sandbox',
    mode: 'declared',
    iterations: 5,
    totalCostUsd: 1.23,
    evidenceDigest: 'Static code investigation. Signals are leads, not final findings.',
    liveConfirmation: {
      enabled: false,
      status: 'not_run',
      targetId: null,
      confirmedFindings: 0,
    },
    confirmedFindings: [],
    topSignals: [
      {
        id: 'ws-1',
        surface: 'code',
        confidence: 0.8,
        status: 'active',
        description: 'Auth appears optional when BOS_JWT_SECRET is unset.',
        relatedAssets: ['src/api/server.ts'],
      },
    ],
    testedHypotheses: [
      {
        id: 'ph-1',
        severity: 'high',
        status: 'refuted',
        description: 'Optional JWT plus tenant header flow may enable cross-tenant action execution.',
        signalIds: ['ws-1'],
        relatedAssets: ['src/api/server.ts'],
        latestVerdict: 'dead_end',
        decisionSource: 'single_judge',
        involvedDormantReactivation: false,
      },
    ],
    modelActivity: [
      {
        role: 'plan',
        provider: 'anthropic',
        model: 'claude-sonnet-4-6',
        calls: 3,
        costUsd: 0.45,
      },
    ],
  };
}

test('buildDeterministicCampaignAssessment classifies conditional static leads conservatively', () => {
  const assessment = buildDeterministicCampaignAssessment(createPacket());

  assert.equal(assessment.overallVerdict, 'validated_architectural_risks_only');
  assert.equal(assessment.confirmedVulnerabilities.length, 0);
  assert.equal(assessment.configurationRisks.length, 1);
  assert.match(assessment.configurationRisks[0]!.description, /BOS_JWT_SECRET/i);
  assert.ok(
    assessment.nextActions.some((action) => /live-confirmation/i.test(action)),
  );
});

test('reviewCampaignAssessment downgrades unsupported confirmed claims to unconfirmed leads', async () => {
  const adapter = new StaticAdapter(JSON.stringify({
    overallVerdict: 'confirmed_vulnerabilities_present',
    summary: 'This is definitely exploitable.',
    confidence: 0.92,
    confirmedVulnerabilities: [
      {
        title: 'Header-only tenant impersonation',
        severity: 'critical',
        description: 'The header can be spoofed to impersonate another tenant.',
        evidenceRefs: ['ws-1'],
        requiredConditions: [],
      },
    ],
    validatedRisks: [],
    configurationRisks: [],
    unconfirmedLeads: [],
    suppressedClaims: [],
    nextActions: [],
  }));

  const invocation = await reviewCampaignAssessment(adapter, createPacket());

  assert.equal(invocation.output.confirmedVulnerabilities.length, 0);
  assert.equal(invocation.output.unconfirmedLeads.length, 1);
  assert.equal(invocation.output.overallVerdict, 'high_priority_unconfirmed_leads');
  assert.match(invocation.output.unconfirmedLeads[0]!.description, /Downgraded from confirmed claim/i);
});

test('reviewCampaignAssessment repairs snake_case reviewer output and preserves structured risks', async () => {
  const adapter = new StaticAdapter(`\`\`\`json
{
  "verdict": "validated_architectural_risks_only",
  "confidence": 0.88,
  "summary": "Static evidence validates architectural risks but not confirmed exploits.",
  "validated_risks": [
    {
      "id": "RISK-001",
      "title": "Optional auth mode",
      "severity": "medium",
      "description": "Auth becomes conditional when a secret is unset.",
      "evidence": "See ws-1 in server.ts"
    }
  ],
  "configuration_risks": [
    {
      "id": "CONFIG-001",
      "title": "Header-based fallback",
      "severity": "low",
      "description": "Header propagation is trusted when fallback auth is enabled."
    }
  ],
  "unconfirmed_leads": [
    {
      "id": "LEAD-001",
      "title": "Tenant impersonation chain",
      "severity": "high",
      "description": "The chain needs runtime confirmation.",
      "evidence": "ph-1 and ws-1"
    }
  ],
  "suppressed_claims": [
    {
      "original_claim": "Confirmed tenant impersonation",
      "suppression_reason": "Static evidence is insufficient."
    }
  ],
  "next_actions": ["Run live confirmation."]
}
\`\`\``);

  const invocation = await reviewCampaignAssessment(adapter, createPacket());

  assert.equal(invocation.parseSuccess, true);
  assert.equal(invocation.output.overallVerdict, 'validated_architectural_risks_only');
  assert.equal(invocation.output.validatedRisks.length, 1);
  assert.equal(invocation.output.configurationRisks.length, 1);
  assert.equal(invocation.output.unconfirmedLeads.length, 1);
  assert.equal(invocation.output.suppressedClaims.length, 1);
  assert.deepEqual(invocation.output.nextActions, ['Run live confirmation.']);
});

test('reviewCampaignAssessment recursively extracts structured JSON embedded inside summary text', async () => {
  const nested = {
    overallVerdict: 'validated_architectural_risks_only',
    summary: 'Nested assessment payload recovered.',
    confidence: 0.84,
    confirmedVulnerabilities: [],
    validatedRisks: [
      {
        title: 'Buyer room guard requires confirmation',
        severity: 'medium',
        description: 'A referenced guard file still needs direct review.',
        evidenceRefs: ['ws-1'],
        requiredConditions: ['Read the referenced guard implementation.'],
      },
    ],
    configurationRisks: [],
    unconfirmedLeads: [],
    suppressedClaims: [],
    nextActions: ['Read buyer-room-access.ts directly.'],
  };

  const adapter = new StaticAdapter(JSON.stringify({
    overallVerdict: 'no_material_findings',
    confidence: 0.4,
    summary: `Reviewer wrapper text.\n\`\`\`json\n${JSON.stringify(nested, null, 2)}\n\`\`\``,
    confirmedVulnerabilities: [],
    validatedRisks: [],
    configurationRisks: [],
    unconfirmedLeads: [],
    suppressedClaims: [],
    nextActions: [],
  }));

  const invocation = await reviewCampaignAssessment(adapter, createPacket());

  assert.equal(invocation.parseSuccess, true);
  assert.match(invocation.parseStatus, /nested_summary/);
  assert.equal(invocation.output.overallVerdict, 'validated_architectural_risks_only');
  assert.equal(invocation.output.validatedRisks.length, 1);
  assert.deepEqual(invocation.output.nextActions, ['Read buyer-room-access.ts directly.']);
});

test('runCampaignAssessmentPanel computes disagreement metadata across reviewers', async () => {
  const packet = {
    ...createPacket(),
    testedHypotheses: [
      {
        id: 'ph-2',
        severity: 'critical',
        status: 'needs_more_data',
        description: 'Optional JWT plus header-only tenant flow may cross a trust boundary.',
        signalIds: ['ws-1'],
        relatedAssets: ['src/api/server.ts', 'src/api/app.ts'],
        latestVerdict: 'partial',
        decisionSource: 'judge_panel',
        involvedDormantReactivation: true,
        boundaryCrossing: {
          from: 'unauthenticated request',
          to: 'tenant-scoped action runtime',
          mechanism: 'header propagation',
        },
      },
    ],
  };
  const conservative = new StaticAdapter(JSON.stringify({
    overallVerdict: 'validated_architectural_risks_only',
    summary: 'Configuration-sensitive architectural risk.',
    confidence: 0.81,
    confirmedVulnerabilities: [],
    validatedRisks: [
      {
        title: 'Optional JWT architecture',
        severity: 'high',
        description: 'Auth becomes opt-in when BOS_JWT_SECRET is unset.',
        evidenceRefs: ['ws-1'],
        requiredConditions: ['Requires BOS_JWT_SECRET to be unset.'],
      },
    ],
    configurationRisks: [],
    unconfirmedLeads: [],
    suppressedClaims: [],
    nextActions: ['Run live confirmation.'],
  }));
  const aggressive = new StaticAdapter(JSON.stringify({
    overallVerdict: 'high_priority_unconfirmed_leads',
    summary: 'The chain is serious but still needs proof.',
    confidence: 0.72,
    confirmedVulnerabilities: [],
    validatedRisks: [],
    configurationRisks: [],
    unconfirmedLeads: [
      {
        title: 'Tenant impersonation chain',
        severity: 'critical',
        description: 'The chain may permit tenant impersonation.',
        evidenceRefs: ['ph-2', 'ws-1'],
        requiredConditions: ['Needs runtime confirmation.'],
      },
    ],
    suppressedClaims: [],
    nextActions: ['Keep the lead open.'],
  }));

  const panel = await runCampaignAssessmentPanel([
    { label: 'conservative', adapter: conservative },
    { label: 'aggressive', adapter: aggressive },
  ], packet);

  assert.equal(panel.unanimous, false);
  assert.equal(panel.distinctVerdicts, 2);
  assert.deepEqual(panel.verdictSplit, {
    validated_architectural_risks_only: 1,
    high_priority_unconfirmed_leads: 1,
  });
  assert.equal(panel.dissenters.length, 1);
});

test('synthesizeCampaignAssessment preserves reviewer identities and allows live-confirmed promotion', async () => {
  const packet = {
    ...createPacket(),
    liveConfirmation: {
      enabled: true,
      status: 'completed',
      targetId: 'fixture-local',
      confirmedFindings: 1,
    },
  };
  const panel = await runCampaignAssessmentPanel([
    {
      label: 'judge-a',
      adapter: new StaticAdapter(JSON.stringify({
        overallVerdict: 'confirmed_vulnerabilities_present',
        summary: 'Live confirmation supports a confirmed vulnerability.',
        confidence: 0.91,
        confirmedVulnerabilities: [
          {
            title: 'Confirmed fixture auth gap',
            severity: 'critical',
            description: 'The local target reproduced the gap.',
            evidenceRefs: ['ws-1'],
            requiredConditions: ['Confirmed in live mode.'],
          },
        ],
        validatedRisks: [],
        configurationRisks: [],
        unconfirmedLeads: [],
        suppressedClaims: [],
        nextActions: ['Patch immediately.'],
      })),
    },
    {
      label: 'judge-b',
      adapter: new StaticAdapter(JSON.stringify({
        overallVerdict: 'validated_architectural_risks_only',
        summary: 'Architectural risk is certain; exploit confirmation depends on live context.',
        confidence: 0.74,
        confirmedVulnerabilities: [],
        validatedRisks: [
          {
            title: 'Auth degradation architecture',
            severity: 'high',
            description: 'The architecture becomes risky in degraded mode.',
            evidenceRefs: ['ws-1'],
            requiredConditions: ['JWT secret unset.'],
          },
        ],
        configurationRisks: [],
        unconfirmedLeads: [],
        suppressedClaims: [],
        nextActions: ['Retest with live confirmation.'],
      })),
    },
  ], packet);

  const synthesis = await synthesizeCampaignAssessment(new StaticAdapter(JSON.stringify({
    overallVerdict: 'confirmed_vulnerabilities_present',
    summary: 'The live-confirmed evidence is strong enough to uphold a confirmed vulnerability.',
    confidence: 0.93,
    confirmedVulnerabilities: [
      {
        title: 'Confirmed fixture auth gap',
        severity: 'critical',
        description: 'Live confirmation and reviewer evidence uphold the finding.',
        evidenceRefs: ['ws-1'],
        requiredConditions: ['Confirmed in live mode.'],
      },
    ],
    validatedRisks: [],
    configurationRisks: [],
    unconfirmedLeads: [],
    suppressedClaims: [],
    nextActions: ['Ship a fix and rerun regression.'],
  })), packet, panel);

  assert.equal(synthesis.output.source, 'synthesized');
  assert.equal(synthesis.output.confirmedVulnerabilities.length, 1);
  assert.equal(synthesis.output.overallVerdict, 'confirmed_vulnerabilities_present');
  assert.deepEqual(synthesis.output.reviewerModels, ['test/static-assessor', 'test/static-assessor']);
  assert.equal(synthesis.output.synthesizerModel, 'test/static-assessor');
});

test('buildDeterministicCampaignAssessment returns no-material-findings for empty evidence', () => {
  const packet = createPacket();
  packet.topSignals = [];
  packet.testedHypotheses = [];

  const assessment = buildDeterministicCampaignAssessment(packet);

  assert.equal(assessment.overallVerdict, 'no_material_findings');
  assert.equal(assessment.nextActions.length, 1);
});

test('toCampaignAssessmentArtifact adds compatibility aliases', () => {
  const packet = createPacket();
  const assessment = buildDeterministicCampaignAssessment(packet);

  const artifact = toCampaignAssessmentArtifact(assessment) as {
    overallVerdict?: string;
    verdict?: string;
    summary?: string;
    executiveSummary?: string;
  };

  assert.equal(artifact.overallVerdict, assessment.overallVerdict);
  assert.equal(artifact.verdict, assessment.overallVerdict);
  assert.equal(artifact.summary, assessment.summary);
  assert.equal(artifact.executiveSummary, assessment.summary);
});

test('a campaign-level live flag cannot promote an ungrounded confirmed claim', async () => {
  // The flag says "something in this campaign was confirmed live"; it is not
  // evidence for an item that cites nothing.
  const packet = {
    ...createPacket(),
    liveConfirmation: {
      enabled: true,
      status: 'completed',
      targetId: 'fixture-local',
      confirmedFindings: 2,
    },
  };

  const panel = await runCampaignAssessmentPanel([
    {
      label: 'judge-a',
      adapter: new StaticAdapter(JSON.stringify({
        overallVerdict: 'confirmed_vulnerabilities_present',
        summary: 'Two items claimed as confirmed.',
        confidence: 0.9,
        confirmedVulnerabilities: [
          {
            title: 'Ungrounded claim',
            severity: 'critical',
            description: 'No reference backs this claim.',
            evidenceRefs: [],
            requiredConditions: [],
          },
          {
            title: 'Grounded claim',
            severity: 'high',
            description: 'Cites a known signal.',
            evidenceRefs: ['ws-1'],
            requiredConditions: [],
          },
        ],
        validatedRisks: [],
        configurationRisks: [],
        unconfirmedLeads: [],
        suppressedClaims: [],
        nextActions: [],
      })),
    },
  ], packet);

  const synthesis = await synthesizeCampaignAssessment(new StaticAdapter(JSON.stringify({
    overallVerdict: 'confirmed_vulnerabilities_present',
    summary: 'Two items claimed as confirmed.',
    confidence: 0.9,
    confirmedVulnerabilities: [
      {
        title: 'Ungrounded claim',
        severity: 'critical',
        description: 'No reference backs this claim.',
        evidenceRefs: [],
        requiredConditions: [],
      },
      {
        title: 'Grounded claim',
        severity: 'high',
        description: 'Cites a known signal.',
        evidenceRefs: ['ws-1'],
        requiredConditions: [],
      },
    ],
    validatedRisks: [],
    configurationRisks: [],
    unconfirmedLeads: [],
    suppressedClaims: [],
    nextActions: [],
  })), packet, panel);

  const confirmedTitles = synthesis.output.confirmedVulnerabilities.map((item) => item.title);
  assert.deepEqual(confirmedTitles, ['Grounded claim'], 'only the grounded item may stay confirmed');
  assert.ok(
    synthesis.output.unconfirmedLeads.some((lead) => lead.title === 'Ungrounded claim'),
    'the ungrounded claim must be downgraded to a lead',
  );
});
