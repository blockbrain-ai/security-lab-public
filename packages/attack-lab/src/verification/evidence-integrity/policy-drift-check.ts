/**
 * Policy drift check — compares two policy snapshots and reports
 * what changed, with a severity score. Used to catch cases where the
 * "rules of the game" moved between when a finding was first reported
 * and when it was re-judged.
 */

import { createHash } from 'node:crypto';
import type { PolicyDrift, PolicySnapshot } from './contracts.js';

// ---------------------------------------------------------------------------
// Snapshot helper
// ---------------------------------------------------------------------------

export function snapshotPolicy(
  policyVersion: string,
  policyContent: unknown,
  rubricContent: unknown,
): PolicySnapshot {
  return {
    policyVersion,
    policyHash: createHash('sha256').update(JSON.stringify(policyContent)).digest('hex'),
    rubricHash: createHash('sha256').update(JSON.stringify(rubricContent)).digest('hex'),
    capturedAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Drift check
// ---------------------------------------------------------------------------

export class PolicyDriftCheck {
  compare(previous: PolicySnapshot, current: PolicySnapshot): PolicyDrift | null {
    const changedFields: string[] = [];
    if (previous.policyVersion !== current.policyVersion) changedFields.push('policyVersion');
    if (previous.policyHash !== current.policyHash) changedFields.push('policyHash');
    if (previous.rubricHash !== current.rubricHash) changedFields.push('rubricHash');

    if (changedFields.length === 0) return null;

    let severity: PolicyDrift['severity'] = 'info';
    let reason = `Changes detected: ${changedFields.join(', ')}`;

    if (changedFields.includes('rubricHash')) {
      severity = 'high';
      reason = 'Rubric content changed — interpretation of evidence may have shifted';
    } else if (changedFields.includes('policyHash')) {
      severity = 'medium';
      reason = 'Policy content changed without a version bump';
    }

    return { previous, current, changedFields, severity, reason };
  }
}
