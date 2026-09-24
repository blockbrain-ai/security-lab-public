import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyBugFamily,
  resolveReviewPolicy,
  type BugFamily,
} from './review-policy.js';

// ---------------------------------------------------------------------------
// classifyBugFamily
// ---------------------------------------------------------------------------

describe('classifyBugFamily', () => {
  const cases: Array<{ claim: string; candidateId: string; rootCause?: string; expected: BugFamily }> = [
    { claim: 'SSRF via URL fetch', candidateId: 'c-1', expected: 'ssrf' },
    { claim: 'Server-side request forgery in webhook handler', candidateId: 'c-2', expected: 'ssrf' },
    { claim: 'Private IP filtering bypass', candidateId: 'c-3', expected: 'ssrf' },
    { claim: 'DNS rebinding attack on internal service', candidateId: 'c-4', expected: 'ssrf' },
    { claim: 'Authentication bypass on admin endpoint', candidateId: 'c-5', expected: 'auth_bypass' },
    { claim: 'Unauthenticated access to user data', candidateId: 'c-6', expected: 'auth_bypass' },
    { claim: 'Route missing auth middleware', candidateId: 'c-7', expected: 'auth_bypass' },
    { claim: 'Session fixation via cookie', candidateId: 'c-8', expected: 'auth_bypass' },
    { claim: 'Remote code execution via eval', candidateId: 'c-9', expected: 'rce' },
    { claim: 'Command injection in shell handler', candidateId: 'c-10', expected: 'rce' },
    { claim: 'os.system with user input', candidateId: 'c-11', rootCause: 'os.system called with untrusted data', expected: 'rce' },
    { claim: 'Sandbox escape via __subclasses__', candidateId: 'c-12', expected: 'sandbox_escape' },
    { claim: 'Python sandbox bypass via __globals__', candidateId: 'c-13', expected: 'sandbox_escape' },
    { claim: 'Unsafe deserialization of user data', candidateId: 'c-14', expected: 'deserialization' },
    { claim: 'Pickle load on untrusted input', candidateId: 'c-15', expected: 'deserialization' },
    { claim: 'XSS via dangerouslySetInnerHTML', candidateId: 'c-16', expected: 'xss' },
    { claim: 'Cross-site scripting in comment field', candidateId: 'c-17', expected: 'xss' },
    { claim: 'CORS credential exposure with reflected origin', candidateId: 'c-18', expected: 'cors' },
    { claim: 'Supply chain dependency confusion', candidateId: 'c-19', expected: 'supply_chain' },
    { claim: 'Tenant boundary violation via IDOR', candidateId: 'c-20', expected: 'tenant_boundary' },
    { claim: 'Cross-tenant data leak', candidateId: 'c-21', expected: 'tenant_boundary' },
    { claim: 'Prompt injection in chat handler', candidateId: 'c-22', expected: 'prompt_injection' },
    { claim: 'LLM jailbreak via system prompt override', candidateId: 'c-23', expected: 'prompt_injection' },
    { claim: 'Rate limit bypass on login endpoint', candidateId: 'c-24', expected: 'rate_limit_dos' },
    { claim: 'ReDoS in email validation regex', candidateId: 'c-25', expected: 'rate_limit_dos' },
    { claim: 'Hardcoded secret key in config module', candidateId: 'c-26', expected: 'credential_exposure' },
    { claim: 'API key leaked via error log', candidateId: 'c-27', expected: 'credential_exposure' },
    { claim: 'Some vague architectural concern', candidateId: 'c-28', expected: 'unknown' },
  ];

  for (const { claim, candidateId, rootCause, expected } of cases) {
    it(`classifies "${claim.slice(0, 50)}..." as ${expected}`, () => {
      assert.equal(classifyBugFamily(claim, candidateId, rootCause), expected);
    });
  }

  it('uses rootCause text for classification', () => {
    assert.equal(
      classifyBugFamily('Something weird', 'c-x', 'pickle.loads on user-supplied bytes'),
      'deserialization',
    );
  });

  it('uses candidateId for classification', () => {
    assert.equal(
      classifyBugFamily('some issue', 'audit-ssrf-webhook', undefined),
      'ssrf',
    );
  });
});

// ---------------------------------------------------------------------------
// resolveReviewPolicy — tier mapping
// ---------------------------------------------------------------------------

describe('resolveReviewPolicy', () => {
  describe('critical tier', () => {
    it('ssrf supported high confidence → critical always', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'ssrf',
        severity: 'high',
        sourceStatus: 'supported',
        confidence: 0.9,
      });
      assert.equal(policy.riskTier, 'critical');
      assert.equal(policy.reviewMode, 'always');
      assert.equal(policy.hardFailOnMiss, true);
      assert.equal(policy.requireRuntime, true);
      assert.equal(policy.observational, true);
    });

    it('rce critical severity → critical', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'rce',
        severity: 'critical',
        sourceStatus: 'supported',
        confidence: 0.8,
      });
      assert.equal(policy.riskTier, 'critical');
    });

    it('auth_bypass high severity high confidence → critical', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'auth_bypass',
        severity: 'high',
        sourceStatus: 'needs_runtime',
        confidence: 0.8,
      });
      assert.equal(policy.riskTier, 'critical');
    });

    it('deserialization supported → critical', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'deserialization',
        severity: 'high',
        sourceStatus: 'supported',
        confidence: 0.85,
      });
      assert.equal(policy.riskTier, 'critical');
    });

    it('sandbox_escape supported → critical', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'sandbox_escape',
        severity: 'high',
        sourceStatus: 'supported',
        confidence: 0.9,
      });
      assert.equal(policy.riskTier, 'critical');
    });
  });

  describe('critical family downgrades to intermediate', () => {
    it('ssrf medium severity → intermediate', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'ssrf',
        severity: 'medium',
        sourceStatus: 'supported',
        confidence: 0.8,
      });
      assert.equal(policy.riskTier, 'intermediate');
    });

    it('rce low confidence low severity → intermediate', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'rce',
        severity: 'low',
        sourceStatus: 'weakened',
        confidence: 0.5,
      });
      assert.equal(policy.riskTier, 'intermediate');
    });

    it('credential_exposure medium severity not supported → intermediate', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'credential_exposure',
        severity: 'medium',
        sourceStatus: 'weakened',
        confidence: 0.6,
      });
      assert.equal(policy.riskTier, 'intermediate');
    });
  });

  describe('intermediate tier', () => {
    it('xss → intermediate', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'xss',
        severity: 'high',
        sourceStatus: 'supported',
        confidence: 0.9,
      });
      assert.equal(policy.riskTier, 'intermediate');
      assert.equal(policy.reviewMode, 'borderline');
      assert.equal(policy.hardFailOnMiss, false);
    });

    it('cors → intermediate', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'cors',
        severity: 'medium',
        sourceStatus: 'weakened',
        confidence: 0.6,
      });
      assert.equal(policy.riskTier, 'intermediate');
    });

    it('supply_chain → intermediate', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'supply_chain',
        severity: 'high',
        sourceStatus: 'supported',
        confidence: 0.8,
      });
      assert.equal(policy.riskTier, 'intermediate');
    });

    it('tenant_boundary → intermediate', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'tenant_boundary',
        severity: 'high',
        sourceStatus: 'supported',
        confidence: 0.9,
      });
      assert.equal(policy.riskTier, 'intermediate');
    });

    it('intermediate supported → requireRuntime true', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'xss',
        severity: 'high',
        sourceStatus: 'supported',
        confidence: 0.9,
      });
      assert.equal(policy.requireRuntime, true);
    });

    it('intermediate weakened high confidence → requireRuntime true', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'xss',
        severity: 'high',
        sourceStatus: 'weakened',
        confidence: 0.8,
      });
      assert.equal(policy.requireRuntime, true);
    });

    it('intermediate weakened low confidence → requireRuntime false', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'xss',
        severity: 'high',
        sourceStatus: 'weakened',
        confidence: 0.5,
      });
      assert.equal(policy.requireRuntime, false);
    });

    it('intermediate refuted → requireRuntime false', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'xss',
        severity: 'high',
        sourceStatus: 'refuted',
        confidence: 0.3,
      });
      assert.equal(policy.requireRuntime, false);
    });

    it('intermediate needs_runtime → requireRuntime true', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'cors',
        severity: 'medium',
        sourceStatus: 'needs_runtime',
        confidence: 0.6,
      });
      assert.equal(policy.requireRuntime, true);
    });
  });

  describe('low tier', () => {
    it('prompt_injection → low', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'prompt_injection',
        severity: 'medium',
        sourceStatus: 'supported',
        confidence: 0.8,
      });
      assert.equal(policy.riskTier, 'low');
      assert.equal(policy.reviewMode, 'none');
      assert.equal(policy.hardFailOnMiss, false);
      assert.equal(policy.requireRuntime, false);
    });

    it('rate_limit_dos → low', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'rate_limit_dos',
        severity: 'medium',
        sourceStatus: 'supported',
        confidence: 0.7,
      });
      assert.equal(policy.riskTier, 'low');
    });

    it('unknown low severity → low', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'unknown',
        severity: 'low',
        sourceStatus: 'weakened',
        confidence: 0.5,
      });
      assert.equal(policy.riskTier, 'low');
    });

    it('unknown info severity → low', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'unknown',
        severity: 'info',
        sourceStatus: 'supported',
        confidence: 0.6,
      });
      assert.equal(policy.riskTier, 'low');
    });

    it('unknown very low confidence → low', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'unknown',
        severity: 'medium',
        sourceStatus: 'weakened',
        confidence: 0.3,
      });
      assert.equal(policy.riskTier, 'low');
    });
  });

  describe('unknown family at medium+ → intermediate', () => {
    it('unknown medium severity decent confidence → intermediate', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'unknown',
        severity: 'medium',
        sourceStatus: 'supported',
        confidence: 0.6,
      });
      assert.equal(policy.riskTier, 'intermediate');
    });

    it('unknown high severity → intermediate', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'unknown',
        severity: 'high',
        sourceStatus: 'supported',
        confidence: 0.8,
      });
      assert.equal(policy.riskTier, 'intermediate');
    });
  });

  describe('observational flag', () => {
    it('defaults to observational (true)', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'ssrf',
        severity: 'high',
        sourceStatus: 'supported',
        confidence: 0.9,
      });
      assert.equal(policy.observational, true);
    });

    it('respects enforcing=true', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'ssrf',
        severity: 'high',
        sourceStatus: 'supported',
        confidence: 0.9,
        enforcing: true,
      });
      assert.equal(policy.observational, false);
    });
  });

  describe('bugFamily preserved in policy', () => {
    it('stamps the correct bugFamily', () => {
      const policy = resolveReviewPolicy({
        bugFamily: 'xss',
        severity: 'high',
        sourceStatus: 'supported',
        confidence: 0.8,
      });
      assert.equal(policy.bugFamily, 'xss');
    });
  });
});

// ---------------------------------------------------------------------------
// Comprehensive tier boundary snapshot
// ---------------------------------------------------------------------------

describe('tier boundary snapshot', () => {
  const criticalFamilies: BugFamily[] = ['ssrf', 'auth_bypass', 'rce', 'deserialization', 'sandbox_escape', 'credential_exposure'];
  const intermediateFamilies: BugFamily[] = ['xss', 'cors', 'supply_chain', 'tenant_boundary'];
  const lowFamilies: BugFamily[] = ['prompt_injection', 'rate_limit_dos'];

  it('all critical families at high severity high confidence → critical', () => {
    for (const family of criticalFamilies) {
      const policy = resolveReviewPolicy({
        bugFamily: family,
        severity: 'high',
        sourceStatus: 'supported',
        confidence: 0.9,
      });
      assert.equal(policy.riskTier, 'critical', `expected ${family} → critical`);
    }
  });

  it('all intermediate families → intermediate regardless of severity/confidence', () => {
    for (const family of intermediateFamilies) {
      const policy = resolveReviewPolicy({
        bugFamily: family,
        severity: 'critical',
        sourceStatus: 'supported',
        confidence: 1.0,
      });
      assert.equal(policy.riskTier, 'intermediate', `expected ${family} → intermediate`);
    }
  });

  it('all low families → low regardless of severity/confidence', () => {
    for (const family of lowFamilies) {
      const policy = resolveReviewPolicy({
        bugFamily: family,
        severity: 'critical',
        sourceStatus: 'supported',
        confidence: 1.0,
      });
      assert.equal(policy.riskTier, 'low', `expected ${family} → low`);
    }
  });
});
