// MANINY DIGITAL — Static authentication-boundary analysis stage.
// Detects URL patterns that suggest auth-sensitive endpoints.

import {
  buildFinding,
  safeParseUrl,
  getPathSegments,
  containsAuthPath,
  getQueryParamNames,
} from './stage-utils.js';
import type { StageResult } from '../types.js';

const UNAUTHENTICATED_ADMIN_SIGNALS = [
  'admin', 'panel', 'console', 'manage', 'management',
  'config', 'configuration', 'setup', 'install',
];

const CREDENTIAL_PARAM_SIGNALS = [
  'token', 'api_key', 'apikey', 'secret', 'password',
  'pwd', 'pass', 'auth', 'bearer', 'access_token', 'refresh_token',
];

/** Detect paths that look like admin/management panels (unauthenticated access risk). */
function checkAdminPath(
  host: string,
  path: string,
  url: string,
  segments: string[]
): StageResult['findings'] {
  const matched = segments.find(s =>
    UNAUTHENTICATED_ADMIN_SIGNALS.includes(s.toLowerCase())
  );
  if (!matched) return [];

  return [
    buildFinding({
      host,
      path,
      url,
      severity: 'high',
      category: 'auth',
      title: 'Admin/Management Endpoint Detected',
      description:
        `The URL path contains the segment '${matched}', which typically indicates ` +
        'an administrative or management interface. If this endpoint is accessible ' +
        'without valid authentication, it represents a critical privilege escalation risk.',
      evidence: `Path segment: /${matched}/`,
      exploitability: 68,
      reproductionSteps: [
        `1. Navigate to ${url} without an authenticated session.`,
        '2. If a 200 or functional response is returned, the endpoint is unprotected.',
        '3. Attempt to perform administrative actions.',
      ],
      remediationHint:
        'Enforce authentication (preferably MFA) on all administrative endpoints. ' +
        'Consider IP allow-listing or VPN requirement for admin access.',
    }),
  ];
}

/** Detect credentials or tokens exposed as query parameters. */
function checkCredentialInQuery(
  host: string,
  path: string,
  url: string,
  params: string[]
): StageResult['findings'] {
  const matched = params.filter(p =>
    CREDENTIAL_PARAM_SIGNALS.includes(p.toLowerCase())
  );
  if (matched.length === 0) return [];

  return matched.map(param =>
    buildFinding({
      host,
      path,
      url,
      severity: 'critical',
      category: 'auth',
      title: 'Credential/Token in URL Query String',
      description:
        `The query parameter '${param}' suggests a sensitive credential or token ` +
        'is embedded in the URL. Query strings are stored in browser history, ' +
        'server access logs, and proxy caches, exposing the token to unintended parties.',
      evidence: `Query parameter: ${param}`,
      exploitability: 82,
      reproductionSteps: [
        `1. Inspect the URL: ${url}`,
        `2. Note that the parameter '${param}' is visible in the URL bar.`,
        '3. Check browser history, server logs, or proxy logs for logged URLs.',
        '4. Extract and replay the token to access the resource as the victim.',
      ],
      remediationHint:
        'Transmit sensitive tokens via POST body or Authorization header, never in ' +
        'the URL. Tokens appearing in URLs should be immediately invalidated.',
    })
  );
}

/** Detect IDOR patterns (numeric IDs in paths or params under auth-sensitive routes). */
function checkIdorPattern(
  host: string,
  path: string,
  url: string,
  segments: string[],
  params: string[]
): StageResult['findings'] {
  const hasAuthPath = containsAuthPath(segments);
  const hasNumericSegment = segments.some(s => /^\d+$/.test(s));
  const hasIdParam = params.some(p =>
    ['id', 'user_id', 'userId', 'account_id', 'accountId'].includes(p)
  );

  if (!hasAuthPath) return [];
  if (!hasNumericSegment && !hasIdParam) return [];

  return [
    buildFinding({
      host,
      path,
      url,
      severity: 'high',
      category: 'auth',
      title: 'Potential IDOR (Insecure Direct Object Reference)',
      description:
        'A URL that combines an authentication-sensitive path with a numeric ID ' +
        'parameter may allow horizontal privilege escalation if the server does not ' +
        'validate that the requesting user owns the referenced object.',
      evidence: `Path: ${path}, Params: ${params.join(', ')}`,
      exploitability: 62,
      reproductionSteps: [
        `1. Authenticate as User A. Navigate to: ${url}`,
        '2. Note the ID value in the URL.',
        '3. While still authenticated as User A, change the ID to User B\'s object ID.',
        "4. If User B's data is returned, IDOR is confirmed.",
      ],
      remediationHint:
        'Implement server-side authorisation checks on every object access. ' +
        'Verify that the authenticated user owns or has permission for the requested object.',
    }),
  ];
}

/**
 * Run the auth static analysis stage on a single URL.
 * Returns potential auth-related findings based on URL structure alone.
 */
export function runAuthStage(urlStr: string): StageResult {
  const findings: StageResult['findings'] = [];
  const errors: string[] = [];

  const parsed = safeParseUrl(urlStr);
  if (!parsed) {
    errors.push(`Cannot parse URL: ${urlStr}`);
    return { findings, errors };
  }

  const host = parsed.hostname;
  const path = parsed.pathname;
  const segments = getPathSegments(path);
  const params = getQueryParamNames(urlStr);

  findings.push(
    ...checkAdminPath(host, path, urlStr, segments),
    ...checkCredentialInQuery(host, path, urlStr, params),
    ...checkIdorPattern(host, path, urlStr, segments, params)
  );

  return { findings, errors };
}
