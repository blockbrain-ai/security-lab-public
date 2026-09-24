/**
 * End-of-run evidence integrity check.
 *
 * The chain is only meaningful if somebody verifies it: `HashChain.verify()`
 * had no production caller, so a forked, truncated or tampered stream was
 * accepted silently. This runs once the event stream is final.
 *
 * Diagnostics are deliberately out-of-band (stderr plus a sidecar file): the
 * event stream may be exactly what is broken, so it must not be appended to.
 */

import { appendFile, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import type { EvidenceStore } from '../../../evidence-plane/src/store.js';

export interface CampaignIntegrityReport {
  valid: boolean;
  eventCount: number;
  headHash: string;
  errors: string[];
  /** Where the diagnostics were written when the chain was invalid. */
  diagnosticsPath?: string;
}

/** Verify the campaign's evidence chain; never throws. */
export async function verifyCampaignEvidence(
  evidenceStore: EvidenceStore,
  campaignDir: string,
  campaignId: string,
): Promise<CampaignIntegrityReport> {
  try {
    const verification = await evidenceStore.verifyChain();
    const report: CampaignIntegrityReport = {
      valid: verification.valid,
      eventCount: verification.eventCount,
      headHash: verification.headHash,
      errors: verification.errors,
    };

    if (!verification.valid) {
      process.stderr.write(
        `[security-lab] evidence chain verification FAILED for campaign ${campaignId} ` +
          `(${verification.eventCount} events, head ${verification.headHash || 'none'}): ` +
          `${verification.errors.slice(0, 10).join('; ')}\n`,
      );
      const diagnosticsPath = resolve(campaignDir, campaignId, 'integrity-errors.jsonl');
      report.diagnosticsPath = diagnosticsPath;
      try {
        await mkdir(dirname(diagnosticsPath), { recursive: true });
        await appendFile(
          diagnosticsPath,
          `${JSON.stringify({
            at: new Date().toISOString(),
            campaignId,
            eventCount: verification.eventCount,
            headHash: verification.headHash,
            errors: verification.errors,
          })}\n`,
          'utf8',
        );
      } catch {
        // A diagnostic that cannot be written must not fail the campaign.
      }
    }

    return report;
  } catch (error: unknown) {
    process.stderr.write(
      `[security-lab] evidence chain verification could not run for ${campaignId}: ` +
        `${error instanceof Error ? error.message : String(error)}\n`,
    );
    return {
      valid: false,
      eventCount: 0,
      headHash: '',
      errors: [error instanceof Error ? error.message : String(error)],
    };
  }
}
