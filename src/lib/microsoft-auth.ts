import { Request, Response, NextFunction } from 'express';
import logger from '../logger.js';
import { getCloudEndpoints, type CloudType } from '../cloud-config.js';

type OAuthErrorBody = {
  error?: string;
  error_description?: string;
};

const MICROSOFT_REFRESH_SCOPE = 'offline_access';
const MICROSOFT_CLIENT_CAPABILITY_CLAIMS = {
  access_token: {
    xms_cc: {
      values: ['cp1'],
    },
  },
};

type ClaimsRequest = {
  access_token?: {
    xms_cc?: {
      values?: string[];
    };
    [key: string]: unknown;
  };
  [key: string]: unknown;
};

export function ensureMicrosoftOAuthScopes(scope: string | null | undefined): string {
  const scopes = new Set(
    (scope ?? '')
      .split(/\s+/)
      .map((value) => value.trim())
      .filter(Boolean)
  );

  scopes.add(MICROSOFT_REFRESH_SCOPE);

  return Array.from(scopes).join(' ');
}

export function ensureMicrosoftClaimsCapability(claims: string | null | undefined): string {
  if (!claims) {
    return JSON.stringify(MICROSOFT_CLIENT_CAPABILITY_CLAIMS);
  }

  try {
    const parsed = JSON.parse(claims) as ClaimsRequest;
    const accessTokenClaims = parsed.access_token ?? {};
    const xmsCc = accessTokenClaims.xms_cc ?? {};
    const values = new Set((xmsCc.values ?? []).map((value) => value.toLowerCase()));
    values.add('cp1');

    return JSON.stringify({
      ...parsed,
      access_token: {
        ...accessTokenClaims,
        xms_cc: {
          ...xmsCc,
          values: Array.from(values),
        },
      },
    });
  } catch {
    return claims;
  }
}

export function getMicrosoftOAuthPrompt(requestedPrompt: string | null | undefined): string | null {
  if (requestedPrompt) {
    return requestedPrompt;
  }

  const configuredPrompt = process.env.MS365_MCP_OAUTH_PROMPT?.trim();
  if (configuredPrompt === 'disabled') {
    return null;
  }

  return configuredPrompt || 'select_account';
}

export class OAuthTokenExchangeError extends Error {
  public readonly statusCode: number;
  public readonly oauthError: string;
  public readonly oauthErrorDescription: string;

  constructor(operation: string, statusCode: number, responseBody: string) {
    const errorBody = parseOAuthErrorBody(responseBody);
    const oauthError = errorBody.error || 'invalid_request';
    const oauthErrorDescription = sanitizeOAuthErrorDescription(
      errorBody.error_description || responseBody || `${operation} failed`
    );

    super(`${operation} failed: ${oauthErrorDescription}`);
    this.name = 'OAuthTokenExchangeError';
    this.statusCode = statusCode;
    this.oauthError = oauthError;
    this.oauthErrorDescription = oauthErrorDescription;
  }
}

function parseOAuthErrorBody(responseBody: string): OAuthErrorBody {
  try {
    const parsed = JSON.parse(responseBody) as OAuthErrorBody;
    return {
      error: typeof parsed.error === 'string' ? parsed.error : undefined,
      error_description:
        typeof parsed.error_description === 'string' ? parsed.error_description : undefined,
    };
  } catch {
    return {};
  }
}

function sanitizeOAuthErrorDescription(description: string): string {
  return description.replace(/[\r\n]+/g, ' ').slice(0, 1000);
}

/**
 * Microsoft Bearer Token Auth Middleware validates that the request has a valid Microsoft access token
 * The token is passed in the Authorization header as a Bearer token
 */
export const microsoftBearerTokenAuthMiddleware = (
  req: Request & { microsoftAuth?: { accessToken: string; refreshToken: string } },
  res: Response,
  next: NextFunction
): void => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Missing or invalid access token' });
    return;
  }

  const accessToken = authHeader.substring(7);

  // For Microsoft Graph, we don't validate the token here - we'll let the API calls fail if it's invalid
  // and handle token refresh in the GraphClient

  // Extract refresh token from a custom header (if provided)
  const refreshToken = (req.headers['x-microsoft-refresh-token'] as string) || '';

  // Store tokens in request for later use
  req.microsoftAuth = {
    accessToken,
    refreshToken,
  };

  next();
};

/**
 * Exchange authorization code for access token
 */
export async function exchangeCodeForToken(
  code: string,
  redirectUri: string,
  clientId: string,
  clientSecret: string | undefined,
  tenantId: string = 'common',
  codeVerifier?: string,
  cloudType: CloudType = 'global',
  claims?: string
): Promise<{
  access_token: string;
  token_type: string;
  scope: string;
  expires_in: number;
  refresh_token: string;
}> {
  const cloudEndpoints = getCloudEndpoints(cloudType);
  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
    client_id: clientId,
  });

  // Add client_secret for confidential clients
  if (clientSecret) {
    params.append('client_secret', clientSecret);
  }

  // Add code_verifier for PKCE flow
  if (codeVerifier) {
    params.append('code_verifier', codeVerifier);
  }

  if (claims) {
    params.append('claims', claims);
  }

  const response = await fetch(`${cloudEndpoints.authority}/${tenantId}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params,
  });

  if (!response.ok) {
    const error = await response.text();
    logger.error(`Failed to exchange code for token: ${error}`);
    throw new OAuthTokenExchangeError('Authorization code exchange', response.status, error);
  }

  return response.json();
}

/**
 * Refresh an access token
 */
export async function refreshAccessToken(
  refreshToken: string,
  clientId: string,
  clientSecret: string | undefined,
  tenantId: string = 'common',
  cloudType: CloudType = 'global'
): Promise<{
  access_token: string;
  token_type: string;
  scope: string;
  expires_in: number;
  refresh_token?: string;
}> {
  const cloudEndpoints = getCloudEndpoints(cloudType);
  const params = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: clientId,
  });

  if (clientSecret) {
    params.append('client_secret', clientSecret);
  }

  const response = await fetch(`${cloudEndpoints.authority}/${tenantId}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params,
  });

  if (!response.ok) {
    const error = await response.text();
    logger.error(`Failed to refresh token: ${error}`);
    throw new OAuthTokenExchangeError('Refresh token exchange', response.status, error);
  }

  return response.json();
}
