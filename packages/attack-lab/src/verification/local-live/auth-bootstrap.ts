import { createHmac, randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { InvestigationTarget } from '../../autonomous/target-profile.js';
import type { IdentitySpec } from './contracts.js';

// ---------------------------------------------------------------------------
// Production-secret detection markers
// ---------------------------------------------------------------------------

const PRODUCTION_SECRET_MARKERS = ['prod_', 'live_', 'real_user_'];

// ---------------------------------------------------------------------------
// Rollback mode
// ---------------------------------------------------------------------------

export type AuthBootstrapRollbackMode = 'memory-only' | 'seed-teardown' | 'none';

// ---------------------------------------------------------------------------
// Bootstrap result
// ---------------------------------------------------------------------------

export interface LocalAuthBootstrapResult {
  envFilePath?: string;
  environment: Record<string, string>;
  identityEnv: Record<string, string>;
  issuedIdentities: string[];
  rollbackMode: AuthBootstrapRollbackMode;
  metadata: {
    type: string;
    issuer?: string;
    audience?: string;
    subjectPrefix?: string;
    secretHash: string;
  };
  /**
   * Teardown function — call at end of campaign to clean up minted credentials.
   * For 'memory-only' mode this is a no-op. For 'seed-teardown' mode this
   * calls the target's teardown API. Always safe to call multiple times.
   */
  teardown: () => Promise<void>;
}

// ---------------------------------------------------------------------------
// Bootstrap event callbacks
// ---------------------------------------------------------------------------

export interface AuthBootstrapCallbacks {
  onEvent?: (stage: string, payload: Record<string, unknown>) => void;
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

export async function prepareLocalAuthBootstrap(
  target: InvestigationTarget,
  campaignDir: string,
  callbacks?: AuthBootstrapCallbacks,
): Promise<LocalAuthBootstrapResult | null> {
  const config = (target.authBootstrap as Record<string, unknown> | undefined) ?? {};
  const type = typeof config['type'] === 'string' ? config['type'] : '';
  if (!type.endsWith('_local_jwt')) {
    return null;
  }

  const rollbackMode: AuthBootstrapRollbackMode =
    (stringValue(config['rollback']) as AuthBootstrapRollbackMode | undefined) ?? 'memory-only';

  const envPrefix = stringValue(config['envPrefix']) ?? type.replace(/_local_jwt$/, '').toUpperCase();

  // Resolve the issuer secret — either from config or from env
  const issuerSecretEnv = stringValue(config['issuerSecretEnv']) ?? `${envPrefix}_JWT_SECRET`;
  const secret = stringValue(config['secret'])
    ?? process.env[issuerSecretEnv]
    ?? randomBytes(24).toString('hex');

  // Section 3.1: refuse production issuer secrets
  if (containsProductionMarker(secret)) {
    callbacks?.onEvent?.('coverage_gap', {
      code: 'auth_bootstrap_refused_production_secret',
      reason: `Issuer secret from ${issuerSecretEnv} contains production markers — refusing to mint canary credentials`,
    });
    return null;
  }

  const issuer = stringValue(config['issuer']) ?? process.env[`${envPrefix}_JWT_ISSUER`] ?? `${envPrefix.toLowerCase()}-api`;
  const audience = stringValue(config['audience']) ?? process.env[`${envPrefix}_JWT_AUDIENCE`] ?? `${envPrefix.toLowerCase()}-public`;
  const channelEncryptionKey = process.env['CHANNEL_ENCRYPTION_KEY']
    ?? randomBytes(32).toString('hex');
  const subjectPrefix = stringValue(config['subjectPrefix']) ?? 'security-lab';
  const expirationSeconds = numberValue(config['expirationSeconds']) ?? 3600;

  const identityEnv: Record<string, string> = {};
  const issuedIdentities: string[] = [];
  let environment: Record<string, string>;
  let envFilePath: string;
  try {
    for (const identity of (target.identities ?? []) as unknown as IdentitySpec[]) {
      if (identity.kind !== 'bearer_token' || !identity.tokenEnv) {
        continue;
      }
      const token = mintLocalJwt(identity, {
        secret,
        issuer,
        audience,
        expirationSeconds,
        subjectPrefix,
      });
      identityEnv[identity.tokenEnv] = token;
      issuedIdentities.push(identity.id);
    }

    environment = {
      [issuerSecretEnv]: secret,
      [`${envPrefix}_JWT_ISSUER`]: issuer,
      [`${envPrefix}_JWT_AUDIENCE`]: audience,
      CHANNEL_ENCRYPTION_KEY: channelEncryptionKey,
    };

    envFilePath = resolve(campaignDir, 'bootstrap', `${target.id}.env`);
    await mkdir(resolve(envFilePath, '..'), { recursive: true });
    await writeFile(
      envFilePath,
      [
        ...Object.entries(environment).map(([key, value]) => `${key}=${shellEscapeEnv(value)}`),
        ...Object.entries(identityEnv).map(([key, value]) => `${key}=${shellEscapeEnv(value)}`),
      ].join('\n') + '\n',
      'utf8',
    );
  } catch (error) {
    // Section 3.1: any failure to mint or persist credentials (other than
    // the production-secret refusal above) degrades to a coverage gap so
    // the lane can continue and the gap is auditable.
    callbacks?.onEvent?.('coverage_gap', {
      code: 'auth_bootstrap_unavailable',
      reason: `Auth bootstrap failed: ${error instanceof Error ? error.message : String(error)}`,
      target: target.id,
    });
    return null;
  }

  // Build the teardown function
  let tornDown = false;
  const teardown = async (): Promise<void> => {
    if (tornDown) return;
    tornDown = true;
    if (rollbackMode === 'seed-teardown') {
      callbacks?.onEvent?.('auth_bootstrap_teardown', {
        target: target.id,
        issuedIdentities,
        mode: 'seed-teardown',
      });
      // Seed-teardown: the target profile should declare a teardown API.
      // For now we record the teardown event; actual API calls are target-specific.
      const teardownConfig = config['seedTeardown'] as Record<string, unknown> | undefined;
      if (teardownConfig && target.baseUrl) {
        const teardownPath = stringValue(teardownConfig['path']) ?? '/api/v1/test/teardown';
        try {
          await fetch(new URL(teardownPath, target.baseUrl).toString(), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ identities: issuedIdentities }),
            signal: AbortSignal.timeout(10_000),
          });
        } catch {
          // Best-effort teardown — the evidence stream records the attempt
        }
      }
    }
    callbacks?.onEvent?.('auth_bootstrap_teardown_complete', {
      target: target.id,
      mode: rollbackMode,
    });
  };

  const result: LocalAuthBootstrapResult = {
    envFilePath,
    environment,
    identityEnv,
    issuedIdentities,
    rollbackMode,
    metadata: {
      type,
      issuer,
      audience,
      subjectPrefix,
      secretHash: createHmac('sha256', 'security-lab')
        .update(secret)
        .digest('hex'),
    },
    teardown,
  };

  // For seed-teardown, wrap the teardown to remove exit handler
  if (rollbackMode === 'seed-teardown') {
    const exitHandler = () => {
      try {
        const journalPath = resolve(campaignDir, 'bootstrap', `${target.id}.teardown-journal.json`);
        writeFileSync(journalPath, JSON.stringify({
          target: target.id,
          issuedIdentities,
          rollbackMode,
          crashedAt: new Date().toISOString(),
        }), 'utf8');
      } catch {
        // Nothing we can do here
      }
    };
    process.on('exit', exitHandler);

    const baseTeardown = result.teardown;
    result.teardown = async (): Promise<void> => {
      process.removeListener('exit', exitHandler);
      await baseTeardown();
    };
  }

  return result;
}

// ---------------------------------------------------------------------------
// Production-secret check
// ---------------------------------------------------------------------------

export function containsProductionMarker(secret: string): boolean {
  const lower = secret.toLowerCase();
  return PRODUCTION_SECRET_MARKERS.some((marker) => lower.includes(marker));
}

// ---------------------------------------------------------------------------
// JWT minting
// ---------------------------------------------------------------------------

interface LocalJwtOptions {
  secret: string;
  issuer: string;
  audience: string;
  expirationSeconds: number;
  subjectPrefix: string;
}

function mintLocalJwt(identity: IdentitySpec, options: LocalJwtOptions): string {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    org: identity.organizationId ?? '00000000-0000-0000-0000-000000000001',
    kid: `${options.subjectPrefix}-${identity.id}`,
    scopes: deriveScopes(identity),
    tier: deriveTier(identity),
    financeRoles: [],
    iss: options.issuer,
    aud: options.audience,
    sub: `${options.subjectPrefix}-${identity.id}`,
    iat: now,
    exp: now + options.expirationSeconds,
    jti: `${options.subjectPrefix}-${identity.id}-${now}`,
  };

  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = createHmac('sha256', options.secret)
    .update(signingInput)
    .digest('base64url');

  return `${signingInput}.${signature}`;
}

function deriveScopes(identity: IdentitySpec): string[] {
  if (identity.expectedRole === 'admin') {
    return ['admin', 'write', 'read'];
  }
  if (identity.expectedRole === 'service') {
    return identity.expectedScope ? [identity.expectedScope] : ['service', 'read'];
  }
  return ['entities', 'decisions', 'read'];
}

function deriveTier(identity: IdentitySpec): string {
  if (identity.expectedRole === 'admin' || identity.expectedRole === 'service') {
    return 'internal';
  }
  return 'standard';
}

function base64url(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64url');
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function numberValue(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function shellEscapeEnv(value: string): string {
  return JSON.stringify(value);
}
