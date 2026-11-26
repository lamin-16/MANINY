// MANINY DIGITAL — Live CORS reflection, Set-Cookie attribute, and auth boundary prober.
// Sends real HTTP requests with crafted Origin headers to verify CORS policies.

import { fetchUrl } from '../utils/http-client.js';
import { buildFinding } from '../stages/stage-utils.js';
import { analyseCorsHeaders } from '../stages/cors-stage.js';
import type { Finding, StageResult } from '../types.js';

export interface AuthSessionProbeOptions {
  timeoutMs?: number;
  /** Attacker-controlled origin to use in CORS tests. */
  probeOrigin?: string;
}

export interface AuthSessionProbeResult {
  url: string;
  findings: Finding[];
  errors: string[];
}

const DEFAULT_PROBE_ORIGIN = 'https://evil.maniny-probe.example';

// ---------------------------------------------------------------------------
// Cookie attribute analyser
// ---------------------------------------------------------------------------

function analyseCookieAttributes(
  urlStr: string,
  host: string,
  path: string,
  setCookieValues: string[]
): Finding[] {
  const findings: Finding[] = [];

  for (const cookie of setCookieValues) {
    const lc = cookie.toLowerCase();
    const name = cookie.split('=')[0]?.trim() ?? 'unknown';

    const isSecure = lc.includes('secure');
    const isHttpOnly = lc.includes('httponly');
    const sameSite = (() => {
      const m = lc.match(/samesite=([a-z]+)/);
      return m?.[1] ?? null;
    })();

    if (!isSecure) {
      findings.push(
        buildFinding({
          host, path, url: urlStr,
          severity: 'high',
          category: 'auth',
          title: `Cookie Missing 'Secure' Flag: ${name}`,
          description:
            `The cookie '${name}' is set without the Secure flag. ` +
            'This allows the cookie to be transmitted over plain HTTP, ' +
            'exposing it to network-level interception.',
          evidence: `Set-Cookie header: ${cookie.slice(0, 120)}`,
          exploitability: 65,
          remediationHint: `Add the Secure attribute: Set-Cookie: ${name}=...; Secure; HttpOnly; SameSite=Strict`,
          source: 'live',
          verified: true,
        })
      );
    }

    if (!isHttpOnly) {
      findings.push(
        buildFinding({
          host, path, url: urlStr,
          severity: 'medium',
          category: 'auth',
          title: `Cookie Missing 'HttpOnly' Flag: ${name}`,
          description:
            `The cookie '${name}' is accessible from JavaScript (no HttpOnly flag). ` +
            'XSS vulnerabilities can steal this cookie and hijack the session.',
          evidence: `Set-Cookie header: ${cookie.slice(0, 120)}`,
          exploitability: 45,
          remediationHint: `Add the HttpOnly attribute: Set-Cookie: ${name}=...; HttpOnly`,
          source: 'live',
          verified: true,
        })
      );
    }

    if (sameSite === null || sameSite === 'none') {
      findings.push(
        buildFinding({
          host, path, url: urlStr,
          severity: 'medium',
          category: 'auth',
          title: `Cookie Weak SameSite Policy: ${name}`,
          description:
            `The cookie '${name}' has no SameSite attribute or is set to SameSite=None. ` +
            'This may allow the cookie to be sent in cross-site requests, increasing CSRF risk.',
          evidence: `SameSite value: ${sameSite ?? 'absent'}`,
          exploitability: 38,
          remediationHint:
            'Set SameSite=Strict (or at least SameSite=Lax) on all session cookies.',
          source: 'live',
          verified: false,
        })
      );
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Main prober
// ---------------------------------------------------------------------------

/**
 * Probe a URL for CORS misconfiguration and insecure cookie attributes.
 * Uses a crafted Origin header to test for arbitrary origin reflection.
 */
export async function probeAuthSession(
  urlStr: string,
  opts: AuthSessionProbeOptions = {}
): Promise<AuthSessionProbeResult> {
  const { timeoutMs = 7_000, probeOrigin = DEFAULT_PROBE_ORIGIN } = opts;
  const findings: Finding[] = [];
  const errors: string[] = [];

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

  // Send a GET with a crafted Origin header to test CORS reflection.
  const response = await fetchUrl(urlStr, {
    method: 'GET',
    headers: { Origin: probeOrigin },
    timeoutMs,
  });

  if (response.error) {
    errors.push(`Network error on ${urlStr}: ${response.error}`);
    return { url: urlStr, findings, errors };
  }

  // Analyse CORS response headers.
  const corsResult: StageResult = analyseCorsHeaders(
    urlStr,
    probeOrigin,
    response.headers
  );
  findings.push(...corsResult.findings);

  // Analyse Set-Cookie attributes.
  const rawCookies = response.headers['set-cookie'];
  const cookieValues: string[] = Array.isArray(rawCookies)
    ? rawCookies
    : rawCookies
    ? [rawCookies]
    : [];

  findings.push(...analyseCookieAttributes(urlStr, host, path, cookieValues));

  return { url: urlStr, findings, errors };
}

/**
 * Run auth session probes against multiple URLs in sequence.
 * Returns a flattened list of all findings.
 */
export async function probeAuthSessions(
  urls: string[],
  opts: AuthSessionProbeOptions = {}
): Promise<Finding[]> {
  const results: Finding[] = [];
  for (const url of urls) {
    const result = await probeAuthSession(url, opts);
    results.push(...result.findings);
  }
  return results;
}
