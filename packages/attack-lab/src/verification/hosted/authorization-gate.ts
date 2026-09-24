/**
 * Authorization gate — explicit confirmation flow before any hosted
 * probe is allowed to fire. Requires the --authorize-hosted flag plus
 * an interactive typed confirmation, and produces a one-time token
 * stamped onto every audit entry for the campaign.
 */

import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { randomBytes } from 'node:crypto';
import type { AuthorizationContext } from './contracts.js';

const REQUIRED_CONFIRMATION = 'CONFIRM HOSTED PROBE';

/** Automated callers must opt in explicitly; the default is fail-closed. */
export function isTestMode(env: NodeJS.ProcessEnv = process.env): boolean {
  return env['SECURITY_LAB_TEST_MODE'] === '1';
}

// ---------------------------------------------------------------------------
// Authorization gate
// ---------------------------------------------------------------------------

export class AuthorizationGate {
  /**
   * Check the gate. Throws if the operator has not authorized this
   * hosted run. On success, returns the authorization token to embed
   * in the audit trail.
   */
  async check(context: AuthorizationContext, options: { skipPrompt?: boolean } = {}): Promise<string> {
    if (!context.authorizeFlagSet) {
      throw new Error(
        'Hosted probing requires the --authorize-hosted flag. ' +
          'No probes will be sent until explicit authorization is provided.',
      );
    }

    if (context.authorizationToken) {
      return context.authorizationToken;
    }

    if (options.skipPrompt) {
      // A skipped prompt is only legitimate in a test process. Without this
      // check, every headless run (CI, cron, agent-driven) would silently
      // downgrade the documented interactive confirmation to a self-minted
      // token — the control would exist only on a TTY.
      if (!isTestMode()) {
        throw new Error(
          'Hosted probing requires the interactive confirmation, but stdin is not a TTY. ' +
            'Run the campaign from a terminal, pass a pre-authorized token, or set ' +
            'SECURITY_LAB_TEST_MODE=1 when driving the gate from an automated test.',
        );
      }
      return `automated-${randomBytes(8).toString('hex')}`;
    }

    const rl = createInterface({ input: stdin, output: stdout });
    try {
      stdout.write(
        `\nHOSTED PROBE AUTHORIZATION REQUIRED\n` +
          `  Campaign: ${context.campaignId}\n` +
          `  Target:   ${context.hostedTargetId}\n` +
          `  Base URL: ${context.baseUrl}\n\n` +
          `Type "${REQUIRED_CONFIRMATION}" to authorize, or anything else to abort.\n> `,
      );
      const answer = await rl.question('');
      if (answer.trim() !== REQUIRED_CONFIRMATION) {
        throw new Error(
          `Hosted probe authorization aborted by operator (received "${answer.trim().slice(0, 32)}")`,
        );
      }
      const token = `auth-${Date.now()}-${randomBytes(8).toString('hex')}`;
      stdout.write(`Authorized. Token: ${token}\n\n`);
      return token;
    } finally {
      rl.close();
    }
  }
}
