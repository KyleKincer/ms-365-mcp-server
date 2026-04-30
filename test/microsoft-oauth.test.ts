import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  ensureMicrosoftClaimsCapability,
  ensureMicrosoftOAuthScopes,
  exchangeCodeForToken,
  getMicrosoftOAuthPrompt,
  OAuthTokenExchangeError,
} from '../src/lib/microsoft-auth.js';

describe('Microsoft OAuth compatibility helpers', () => {
  const originalFetch = global.fetch;
  type FetchOptionsWithBody = { body?: { toString(): string } };

  beforeEach(() => {
    vi.unstubAllEnvs();
  });

  afterEach(() => {
    global.fetch = originalFetch;
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it('adds offline_access to requested scopes so refresh tokens can be issued', () => {
    expect(ensureMicrosoftOAuthScopes('User.Read Mail.Read')).toBe(
      'User.Read Mail.Read offline_access'
    );
  });

  it('does not duplicate offline_access when the client already requested it', () => {
    expect(ensureMicrosoftOAuthScopes('User.Read offline_access Mail.Read')).toBe(
      'User.Read offline_access Mail.Read'
    );
  });

  it('adds Microsoft claims challenge client capability when no claims are present', () => {
    const claims = JSON.parse(ensureMicrosoftClaimsCapability(undefined));
    expect(claims).toEqual({
      access_token: {
        xms_cc: {
          values: ['cp1'],
        },
      },
    });
  });

  it('preserves existing claims while adding cp1 client capability', () => {
    const originalClaims = JSON.stringify({
      access_token: {
        acrs: {
          essential: true,
          value: 'c1',
        },
      },
    });

    const claims = JSON.parse(ensureMicrosoftClaimsCapability(originalClaims));
    expect(claims.access_token.acrs).toEqual({ essential: true, value: 'c1' });
    expect(claims.access_token.xms_cc.values).toContain('cp1');
  });

  it('defaults to select_account prompt but allows disabling or overriding it', () => {
    expect(getMicrosoftOAuthPrompt(undefined)).toBe('select_account');
    expect(getMicrosoftOAuthPrompt('login')).toBe('login');

    vi.stubEnv('MS365_MCP_OAUTH_PROMPT', 'disabled');
    expect(getMicrosoftOAuthPrompt(undefined)).toBeNull();

    vi.stubEnv('MS365_MCP_OAUTH_PROMPT', 'login');
    expect(getMicrosoftOAuthPrompt(undefined)).toBe('login');
  });

  it('forwards claims to Microsoft token exchange when provided', async () => {
    let requestBody = '';
    global.fetch = vi
      .fn()
      .mockImplementation(async (_url: string, options: FetchOptionsWithBody) => {
        requestBody = options.body?.toString() ?? '';
        return {
          ok: true,
          json: async () => ({
            access_token: 'access-token',
            token_type: 'Bearer',
            scope: 'User.Read offline_access',
            expires_in: 3600,
            refresh_token: 'refresh-token',
          }),
        } as Response;
      });

    await exchangeCodeForToken(
      'code',
      'https://echo.sweetwater.com/api/mcp/m365/oauth/callback',
      'client-id',
      undefined,
      'tenant-id',
      'verifier',
      'global',
      '{"access_token":{"xms_cc":{"values":["cp1"]}}}'
    );

    const params = new URLSearchParams(requestBody);
    expect(params.get('claims')).toBe('{"access_token":{"xms_cc":{"values":["cp1"]}}}');
  });

  it('preserves Microsoft claims challenges from token exchange errors', () => {
    const claims = '{"access_token":{"acrs":{"essential":true,"value":"c1"}}}';
    const error = new OAuthTokenExchangeError(
      'Authorization code exchange',
      400,
      JSON.stringify({
        error: 'invalid_grant',
        error_description: 'AADSTS50076: MFA required.',
        claims,
      })
    );

    expect(error.oauthError).toBe('invalid_grant');
    expect(error.oauthErrorDescription).toBe('AADSTS50076: MFA required.');
    expect(error.oauthClaims).toBe(claims);
  });
});
