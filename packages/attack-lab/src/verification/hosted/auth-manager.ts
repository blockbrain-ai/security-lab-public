/**
 * Auth manager — fetches and refreshes credentials for hosted probes.
 * Supports IAP service accounts, IAP user tokens via gcloud, session
 * cookies, and bearer tokens.
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { AuthSource } from './contracts.js';

const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------------------
// Resolved credentials
// ---------------------------------------------------------------------------

export interface ResolvedCredentials {
  headers: Record<string, string>;
  expiresAt?: number;
  source: AuthSource['source'];
}

// ---------------------------------------------------------------------------
// Auth manager
// ---------------------------------------------------------------------------

export class AuthManager {
  private cache: Map<string, ResolvedCredentials> = new Map();

  constructor(private readonly sources: Map<string, AuthSource>) {}

  /**
   * Resolve credentials for a given auth source ID. Returns null if
   * credentials cannot be obtained (so the probe is skipped, not run).
   */
  async resolve(sourceId: string): Promise<ResolvedCredentials | null> {
    const cached = this.cache.get(sourceId);
    if (cached && (!cached.expiresAt || cached.expiresAt > Date.now() + 60_000)) {
      return cached;
    }

    const source = this.sources.get(sourceId);
    if (!source) return null;

    const resolved = await this.fetch(source);
    if (resolved) {
      this.cache.set(sourceId, resolved);
    }
    return resolved;
  }

  private async fetch(source: AuthSource): Promise<ResolvedCredentials | null> {
    switch (source.source) {
      case 'anonymous': {
        return {
          source: source.source,
          headers: {},
        };
      }

      case 'iap_service_account': {
        // Use application-default credentials with an explicit credential file.
        try {
          const { stdout } = await execFileAsync(
            'gcloud',
            [
              'auth',
              'application-default',
              'print-identity-token',
              `--audiences=${source.audience}`,
            ],
            {
              env: {
                ...process.env,
                GOOGLE_APPLICATION_CREDENTIALS: source.serviceAccountPath,
              },
            },
          );
          const token = stdout.trim();
          if (!token) return null;
          this.rejectIfProductionUserToken(token);
          return {
            source: source.source,
            headers: { 'Proxy-Authorization': `Bearer ${token}` },
            expiresAt: Date.now() + 3_500_000,
          };
        } catch {
          return null;
        }
      }

      case 'iap_user_token': {
        try {
          const [cmd, ...args] = source.tokenCommand.split(/\s+/);
          if (!cmd) return null;
          const { stdout } = await execFileAsync(cmd, args);
          const token = stdout.trim();
          if (!token) return null;
          this.rejectIfProductionUserToken(token);
          return {
            source: source.source,
            headers: { 'Proxy-Authorization': `Bearer ${token}` },
            expiresAt: Date.now() + (source.refreshIntervalSeconds ?? 3_500) * 1_000,
          };
        } catch {
          return null;
        }
      }

      case 'session_cookie': {
        const value = process.env[source.cookieValueEnv];
        if (!value) return null;
        this.rejectIfProductionUserToken(value);
        return {
          source: source.source,
          headers: { Cookie: `${source.cookieName}=${value}` },
        };
      }

      case 'bearer_token': {
        const token = process.env[source.tokenEnv];
        if (!token) return null;
        this.rejectIfProductionUserToken(token);
        return {
          source: source.source,
          headers: { Authorization: `Bearer ${token}` },
        };
      }
    }
  }

  /**
   * Reject anything that looks like a real production credential.
   * The hosted lane is for canary identities only.
   */
  private rejectIfProductionUserToken(token: string): void {
    const productionMarkers = [
      'prod_',
      '_prod_',
      'PRODUCTION',
      'live_',
      'real_user_',
    ];
    for (const marker of productionMarkers) {
      if (token.includes(marker)) {
        throw new Error(
          `AuthManager refused to use credential containing production marker "${marker}". ` +
            'Hosted probing must use dedicated canary identities only.',
        );
      }
    }
  }

  /** Clear all cached credentials. */
  invalidate(): void {
    this.cache.clear();
  }
}
