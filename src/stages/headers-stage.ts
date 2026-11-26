// MANINY DIGITAL — Static headers-risk analysis stage.
// Flags URLs that use plain HTTP or expose patterns linked to missing security headers.
// No network requests — URL structural analysis only.

import { URL } from 'node:url';
import {
  buildFinding,
  safeParseUrl,
  hasSensitiveExtension,
  isPlainHttp,
} from './stage-utils.js';
import type { StageResult } from '../types.js';

/**
 * Analyse a URL for static indicators of missing/weak security headers.
 * Returns potential findings; live stages later validate these.
 */
export function runHeadersStage(urlStr: string): StageResult {
  const findings: StageResult['findings'] = [];
  const errors: string[] = [];

  const parsed = safeParseUrl(urlStr);
  if (!parsed) {
    errors.push(`Cannot parse URL: ${urlStr}`);
    return { findings, errors };
  }

  const host = parsed.hostname;
  const path = parsed.pathname;

  // Plain HTTP → no HSTS possible
  if (isPlainHttp(urlStr)) {
    findings.push(
      buildFinding({
        host,
        path,
        url: urlStr,
        severity: 'high',
        category: 'headers',
        title: 'Plaintext HTTP (no TLS)',
        description:
          'The target URL uses plain HTTP. Credentials, tokens, and session cookies ' +
          'transmitted over this connection are exposed to network-level interception. ' +
          'No HSTS header is possible without TLS.',
        evidence: `Protocol: ${parsed.protocol}`,
        exploitability: 60,
        reproductionSteps: [
          `1. Open the URL: ${urlStr}`,
          '2. Observe that the connection is not encrypted (no padlock in browser).',
          '3. Use a network capture tool on the same LAN to intercept the request.',
        ],
        remediationHint:
          'Redirect all HTTP traffic to HTTPS. Enable HSTS with includeSubDomains ' +
          'and a min-age of 31536000.',
      })
    );
  }

  // Sensitive file extension exposed via URL
  if (hasSensitiveExtension(path)) {
    findings.push(
      buildFinding({
        host,
        path,
        url: urlStr,
        severity: 'critical',
        category: 'headers',
        title: 'Potentially Sensitive File Exposed',
        description:
          'The URL path contains a file extension commonly associated with sensitive ' +
          'files (backups, keys, credentials, database dumps). If the web server ' +
          'serves this file, its contents may be exfiltrated without authentication.',
        evidence: `Path: ${path}`,
        exploitability: 80,
        reproductionSteps: [
          `1. Request the URL: ${urlStr}`,
          '2. Inspect the HTTP response code and body.',
          '3. If status 200 and body contains sensitive data, this is confirmed exploitable.',
        ],
        remediationHint:
          'Block access to sensitive file extensions at the web server level. ' +
          'Remove backup and configuration files from the web root entirely.',
      })
    );
  }

  // No X-Content-Type-Options / X-Frame-Options — flag API-looking endpoints
  const pathLower = path.toLowerCase();
  if (
    pathLower.startsWith('/api/') ||
    pathLower.endsWith('.json') ||
    pathLower.endsWith('.xml')
  ) {
    findings.push(
      buildFinding({
        host,
        path,
        url: urlStr,
        severity: 'low',
        category: 'headers',
        title: 'API Endpoint May Lack Security Headers',
        description:
          'API endpoints frequently omit security headers such as ' +
          'X-Content-Type-Options, X-Frame-Options, and Content-Security-Policy. ' +
          'Without these, the response may be framed or MIME-sniffed by browsers.',
        evidence: `Path pattern matches API endpoint: ${path}`,
        exploitability: 18,
        remediationHint:
          'Set X-Content-Type-Options: nosniff, X-Frame-Options: DENY, and a ' +
          'strict Content-Security-Policy on all API responses.',
      })
    );
  }

  return { findings, errors };
}

/**
 * Analyse an already-collected set of response headers for missing
 * security headers. Used by the live probe stage after a real HTTP response.
 */
export function analyseResponseHeaders(
  urlStr: string,
  headers: Record<string, string | string[] | undefined>
): StageResult {
  const findings: StageResult['findings'] = [];
  const errors: string[] = [];

  const parsed = safeParseUrl(urlStr);
  if (!parsed) {
    errors.push(`Cannot parse URL: ${urlStr}`);
    return { findings, errors };
  }

  const host = parsed.hostname;
  const path = parsed.pathname;

  const checks: Array<{
    header: string;
    title: string;
    description: string;
    remediation: string;
    severity: StageResult['findings'][0]['severity'];
    exploitability: number;
  }> = [
    {
      header: 'strict-transport-security',
      title: 'Missing HSTS Header',
      description:
        'The Strict-Transport-Security (HSTS) header is absent. Clients may connect ' +
        'over plain HTTP before the browser knows to upgrade, enabling SSL stripping attacks.',
      remediation:
        'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
      severity: 'medium',
      exploitability: 35,
    },
    {
      header: 'x-frame-options',
      title: 'Missing X-Frame-Options Header',
      description:
        'The X-Frame-Options header is absent. This page may be embedded in a ' +
        'malicious iframe to perform clickjacking attacks against authenticated users.',
      remediation: 'Add: X-Frame-Options: DENY or SAMEORIGIN',
      severity: 'medium',
      exploitability: 30,
    },
    {
      header: 'x-content-type-options',
      title: 'Missing X-Content-Type-Options Header',
      description:
        'Without X-Content-Type-Options: nosniff, some browsers may MIME-sniff responses ' +
        'and execute content as a different type, enabling certain XSS variants.',
      remediation: 'Add: X-Content-Type-Options: nosniff',
      severity: 'low',
      exploitability: 15,
    },
    {
      header: 'content-security-policy',
      title: 'Missing Content-Security-Policy Header',
      description:
        'No Content-Security-Policy header was found. A CSP is a defence-in-depth ' +
        'measure that significantly reduces XSS impact by controlling resource loading.',
      remediation:
        'Define a strict CSP. At minimum: Content-Security-Policy: default-src ' +
        "'self'; script-src 'self'",
      severity: 'medium',
      exploitability: 32,
    },
  ];

  for (const check of checks) {
    const val = headers[check.header];
    if (val === undefined) {
      findings.push(
        buildFinding({
          host,
          path,
          url: urlStr,
          severity: check.severity,
          category: 'headers',
          title: check.title,
          description: check.description,
          evidence: `Response header '${check.header}' is absent`,
          exploitability: check.exploitability,
          remediationHint: check.remediation,
          source: 'live',
          verified: false,
        })
      );
    }
  }

  return { findings, errors };
}
