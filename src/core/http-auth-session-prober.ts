// MANINY DIGITAL — Auth/CORS session prober.
// Session-aware CORS origin reflection tester and Set-Cookie attribute analyzer.

import { fetchUrl } from '../utils/http-client.js';
import { buildFinding } from '../stages/stage-utils.js';
import { analyseCorsHeaders } from '../stages/cors-stage.js';
import type { Finding } from '../types.js';
import type { SessionManager } from './session-manager.js';

export interface AuthSessionOptions {
  timeoutMs?:   number;
  probeOrigin?: string;
  session?:     SessionManager;
}

export interface AuthSessionResult {
  url:      string;
  findings: Finding[];
  errors:   string[];
}

const DEFAULT_PROBE_ORIGIN = 'https://evil.maniny-probe.example';

// ---------------------------------------------------------------------------
// Cookie attribute analyser
// ---------------------------------------------------------------------------

function analyseCookies(
  urlStr: string, host: string, path: string,
  setCookieValues: string[]
): Finding[] {
  return setCookieValues.flatMap(cookie => {
    const findings: Finding[] = [];
    const lc   = cookie.toLowerCase();
    const name = cookie.split('=')[0]?.trim() ?? 'unknown';

    if (!lc.includes('secure')) {
      findings.push(buildFinding({
        host, path, url: urlStr,
        severity: 'high', category: 'auth',
        title:    `Cookie Missing 'Secure' Flag: ${name}`,
        description:
          `Cookie '${name}' is transmitted over plain HTTP. ` +
          'Network interception (MITM) exposes the session token.',
        evidence:       `Set-Cookie: ${cookie.slice(0, 120)}`,
        exploitability: 65,
        remediationHint: `Add Secure: Set-Cookie: ${name}=…; Secure; HttpOnly; SameSite=Strict`,
        source: 'live', verified: true,
      }));
    }

    if (!lc.includes('httponly')) {
      findings.push(buildFinding({
        host, path, url: urlStr,
        severity: 'medium', category: 'auth',
        title:    `Cookie Missing 'HttpOnly' Flag: ${name}`,
        description:
          `Cookie '${name}' is readable via JavaScript (no HttpOnly). ` +
          'Any XSS vulnerability on this domain can steal this token.',
        evidence:       `Set-Cookie: ${cookie.slice(0, 120)}`,
        exploitability: 50,
        remediationHint: `Add HttpOnly: Set-Cookie: ${name}=…; HttpOnly`,
        source: 'live', verified: true,
      }));
    }

    const ssMatch = lc.match(/samesite=([a-z]+)/);
    const ss      = ssMatch?.[1] ?? null;
    if (ss === null || ss === 'none') {
      findings.push(buildFinding({
        host, path, url: urlStr,
        severity: 'medium', category: 'auth',
        title:    `Cookie Weak SameSite Policy: ${name}`,
        description:
          `Cookie '${name}' has SameSite=${ss ?? 'absent'}, allowing cross-site request forgery.`,
        evidence:       `SameSite: ${ss ?? 'absent'}`,
        exploitability: 40,
        remediationHint: 'Set SameSite=Strict (or at minimum SameSite=Lax).',
        source: 'live', verified: false,
      }));
    }

    return findings;
  });
}

// ---------------------------------------------------------------------------
// CORS multi-vector test
// ---------------------------------------------------------------------------

const CORS_TEST_ORIGINS = [
  'https://evil.maniny-probe.example',
  'null',                            // null origin (sandbox iframe)
  'https://evil.example.com',
];

async function testCorsVectors(
  urlStr: string, host: string, path: string,
  sessionHeaders: Record<string, string>,
  timeoutMs: number
): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const origin of CORS_TEST_ORIGINS) {
    const resp = await fetchUrl(urlStr, {
      method: 'GET',
      headers: { ...sessionHeaders, Origin: origin },
      timeoutMs,
    });

    if (resp.error || resp.status === 0) continue;

    const result = analyseCorsHeaders(urlStr, origin, resp.headers);
    findings.push(...result.findings);

    // Vary header check — ensure Origin is in Vary (good sign)
    const vary = String(resp.headers['vary'] ?? '').toLowerCase();
    const acao  = String(resp.headers['access-control-allow-origin'] ?? '');
    if (acao && !vary.includes('origin')) {
      findings.push(buildFinding({
        host, path, url: urlStr,
        severity: 'low', category: 'cors',
        title:    'CORS Response Missing Vary: Origin Header',
        description:
          'The server sets Access-Control-Allow-Origin but does not include "Origin" ' +
          'in the Vary header. CDN and caching proxies may serve CORS responses to ' +
          'incorrect origins.',
        evidence:       `ACAO: ${acao} | Vary: ${vary || '(absent)'}`,
        exploitability: 18,
        remediationHint: 'Add: Vary: Origin to responses that include ACAO.',
        source: 'live',
      }));
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Main prober
// ---------------------------------------------------------------------------

export async function probeAuthSession(
  urlStr: string,
  opts: AuthSessionOptions = {}
): Promise<AuthSessionResult> {
  const {
    timeoutMs = 7_000,
    session,
  } = opts;

  const findings: Finding[] = [];
  const errors:   string[]  = [];

  let host = '';
  let path = '/';
  try {
    const u = new URL(urlStr);
    host = u.hostname;
    path = u.pathname;
  } catch {
    errors.push(`Cannot parse URL: ${urlStr}`);
    return { url: urlStr, findings, errors };
  }

  const sessionHeaders = session?.buildHeaders() ?? {};

  // 1. CORS multi-vector test
  const corsFindings = await testCorsVectors(urlStr, host, path, sessionHeaders, timeoutMs)
    .catch(() => [] as Finding[]);
  findings.push(...corsFindings);

  // 2. Standard GET to capture Set-Cookie
  const resp = await fetchUrl(urlStr, {
    method: 'GET',
    headers: sessionHeaders,
    timeoutMs,
  });

  if (!resp.error && resp.status !== 0) {
    // Update session jar with any new cookies
    session?.updateFromSetCookie(resp.headers['set-cookie']);

    // 3. Cookie attribute analysis
    const rawCookies = resp.headers['set-cookie'];
    const cookieList = Array.isArray(rawCookies)
      ? rawCookies
      : rawCookies ? [rawCookies] : [];

    findings.push(...analyseCookies(urlStr, host, path, cookieList));
  } else if (resp.error) {
    errors.push(`Network error on ${urlStr}: ${resp.error}`);
  }

  return { url: urlStr, findings, errors };
}
