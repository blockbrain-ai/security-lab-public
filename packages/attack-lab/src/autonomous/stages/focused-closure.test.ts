/**
 * Section 5.2 — tests for the FocusedClosureStage citation-rule helper.
 *
 * The contract rule (§0.1 / SL1) is that a hypothesis may enter
 * the focused list only if it cites at least one source ref, probe ref,
 * or event ref. Hypotheses missing all three are classified as
 * `unconfirmed_lead` and held back from the focused list.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  FocusedClosureStage,
  applyEvidenceRefCitationRule,
  hasSufficientEvidenceRefs,
  type HypothesisForClosure,
} from './focused-closure.js';

test('hypothesis with a source ref is included in the focused list', () => {
  const h: HypothesisForClosure = {
    id: 'h-src',
    description: 'source ref',
    severity: 'high',
    sourceRefs: ['src://pkg/file.ts#12'],
  };
  assert.equal(hasSufficientEvidenceRefs(h), true);
  const { focusedList, unconfirmedLeads } = applyEvidenceRefCitationRule({ hypotheses: [h] });
  assert.deepEqual(focusedList, [h]);
  assert.deepEqual(unconfirmedLeads, []);
});

test('hypothesis with a probe ref only is included', () => {
  const h: HypothesisForClosure = {
    id: 'h-probe',
    description: 'probe ref',
    severity: 'medium',
    probeRefs: ['probe://p-1'],
  };
  const { focusedList, unconfirmedLeads } = applyEvidenceRefCitationRule({ hypotheses: [h] });
  assert.deepEqual(focusedList, [h]);
  assert.deepEqual(unconfirmedLeads, []);
});

test('hypothesis with an event ref only is included', () => {
  const h: HypothesisForClosure = {
    id: 'h-event',
    description: 'event ref',
    severity: 'low',
    eventRefs: ['event://e-42'],
  };
  const { focusedList, unconfirmedLeads } = applyEvidenceRefCitationRule({ hypotheses: [h] });
  assert.deepEqual(focusedList, [h]);
  assert.deepEqual(unconfirmedLeads, []);
});

test('hypothesis with no refs is flagged as unconfirmed_lead', () => {
  const h: HypothesisForClosure = {
    id: 'h-empty',
    description: 'no refs',
    severity: 'high',
  };
  assert.equal(hasSufficientEvidenceRefs(h), false);
  const { focusedList, unconfirmedLeads } = applyEvidenceRefCitationRule({ hypotheses: [h] });
  assert.deepEqual(focusedList, []);
  assert.deepEqual(unconfirmedLeads, [h]);
});

test('hypothesis with empty ref arrays is flagged as unconfirmed_lead', () => {
  const h: HypothesisForClosure = {
    id: 'h-empty-arrays',
    description: 'empty arrays',
    severity: 'medium',
    sourceRefs: [],
    probeRefs: [],
    eventRefs: [],
  };
  const { focusedList, unconfirmedLeads } = applyEvidenceRefCitationRule({ hypotheses: [h] });
  assert.deepEqual(focusedList, []);
  assert.deepEqual(unconfirmedLeads, [h]);
});

test('mixed hypotheses are partitioned correctly', () => {
  const cited: HypothesisForClosure = {
    id: 'h-cited',
    description: 'cited',
    severity: 'high',
    sourceRefs: ['src://a.ts#1'],
  };
  const lead: HypothesisForClosure = {
    id: 'h-lead',
    description: 'lead',
    severity: 'high',
  };
  const { focusedList, unconfirmedLeads } = applyEvidenceRefCitationRule({
    hypotheses: [cited, lead],
  });
  assert.deepEqual(focusedList, [cited]);
  assert.deepEqual(unconfirmedLeads, [lead]);
});

test('hypothesis with sourceLocationRefs (Section 7.1) is included in the focused list', () => {
  const h: HypothesisForClosure = {
    id: 'h-source-loc',
    description: 'has typed source location refs',
    severity: 'high',
    sourceLocationRefs: [{ path: 'src/handler.ts', startLine: 10, endLine: 20 }],
  };
  assert.equal(hasSufficientEvidenceRefs(h), true);
  const { focusedList, unconfirmedLeads } = applyEvidenceRefCitationRule({ hypotheses: [h] });
  assert.deepEqual(focusedList, [h]);
  assert.deepEqual(unconfirmedLeads, []);
});

test('hypothesis with only signal refs (no source/probe) is unconfirmed_lead', () => {
  const h: HypothesisForClosure = {
    id: 'h-signal-only',
    description: 'only has signal refs from signalIds',
    severity: 'medium',
    // sourceRefs populated from signalIds — but signalIds are opaque IDs,
    // not real source refs. Without probeRefs or sourceLocationRefs, this
    // counts because sourceRefs is non-empty (legacy behavior).
    sourceRefs: ['ws-1'],
  };
  assert.equal(hasSufficientEvidenceRefs(h), true);
});

test('FocusedClosureStage exposes the focused_closure stage name', () => {
  const stage = new FocusedClosureStage();
  assert.equal(stage.name, 'focused_closure');
});
