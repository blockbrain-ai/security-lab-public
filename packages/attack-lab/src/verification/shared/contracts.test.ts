import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  emptyVerificationStatus,
  classifyFromVerification,
  createExperimentId,
} from './contracts.js';

describe('shared verification contracts', () => {
  it('emptyVerificationStatus produces an unconfirmed lead', () => {
    const status = emptyVerificationStatus('finding-1');
    assert.equal(status.findingId, 'finding-1');
    assert.equal(status.finalClassification, 'unconfirmed_lead');
    assert.equal(status.confidence, 0);
    assert.equal(status.testSynthesis.attempted, false);
    assert.equal(status.localLive.attempted, false);
  });

  it('classifyFromVerification promotes hosted confirmation above all', () => {
    const status = emptyVerificationStatus('f');
    status.hosted.attempted = true;
    status.hosted.verdict = 'confirmed';
    status.localLive.attempted = true;
    status.localLive.verdict = 'confirmed';
    assert.equal(classifyFromVerification(status), 'confirmed_exploitable_hosted');
  });

  it('classifyFromVerification falls back to local-live confirmation', () => {
    const status = emptyVerificationStatus('f');
    status.localLive.attempted = true;
    status.localLive.verdict = 'confirmed';
    assert.equal(classifyFromVerification(status), 'confirmed_exploitable_local');
  });

  it('classifyFromVerification surfaces supply chain risk', () => {
    const status = emptyVerificationStatus('f');
    status.supplyChain.attempted = true;
    status.supplyChain.verdict = 'confirmed_risk';
    assert.equal(classifyFromVerification(status), 'confirmed_supply_chain_risk');
  });

  it('classifyFromVerification refutes when all attempted lanes refuted', () => {
    const status = emptyVerificationStatus('f');
    status.testSynthesis.attempted = true;
    status.testSynthesis.verdict = 'refuted';
    status.localLive.attempted = true;
    status.localLive.verdict = 'refuted';
    assert.equal(classifyFromVerification(status), 'refuted');
  });

  it('createExperimentId is unique per call', () => {
    const a = createExperimentId('local_live', 'f');
    const b = createExperimentId('local_live', 'f');
    assert.notEqual(a, b);
    assert.match(a, /^exp-local_live-f-/);
  });
});
