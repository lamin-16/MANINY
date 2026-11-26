// MANINY DIGITAL — Static CORS misconfiguration analysis stage.
// Flags URL patterns that commonly have CORS issues; live stages confirm.

import {
  buildFinding,
  safeParseUrl,
  getPathSegments,
} from './stage-utils.js';
import type { StageResult } from '../types.js';

const API_INDICATORS = [
  'api', 'graphql', 'rest', 'v1', 'v2', 'v3',
  'json', 'rpc', 'gateway', 'service', 'ws',
];

/** Check if the URL looks like a cross-origin API endpoint. */
function looksLikeApi(segments: string[], pathname: string): boolean {
  const hasApiSegment = segments.some(s =>
    API_INDICATORS.includes(s.toLowerCase())
  );
  const hasJsonExt =
    pathname.endsWith('.json') ||
    pathname.endsWith('.jsonp');

  return hasApiSegment || hasJsonExt;
}

/**
 * Run the CORS static analysis stage on a single URL.
 * Flags potential CORS targets for follow-up live testing.
 */
export function runCorsStage(urlStr: string): StageResult {
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

  if (!looksLikeApi(segments, path)) {
    return { findings, errors };
  }

  findings.push(
    buildFinding({
      host,
      path,
      url: urlStr,
      severity: 'low',
      category: 'cors',
      title: 'API Endpoint May Have Permissive CORS Policy',
      description:
        'The URL pattern suggests this is a cross-origin API endpoint. If the server ' +
        'reflects the Origin header without validation (Access-Control-Allow-Origin: *  ' +
        'or echo of arbitrary origins with Allow-Credentials: true), attackers can read ' +
        'authenticated API responses from a cross-origin context.',
      evidence: `API path pattern: ${path}`,
      exploitability: 22,
      reproductionSteps: [
        '1. Send a preflight OPTIONS request with Origin: https://attacker.example.com',
        '2. Inspect Access-Control-Allow-Origin in the response.',
        '3. If the response echoes the attacker origin AND sets Allow-Credentials: true, ' +
          'this is fully exploitable CORS.',
      ],
      remediationHint:
        'Define an explicit CORS allow-list. Never combine Access-Control-Allow-Origin: * ' +
        'with Access-Control-Allow-Credentials: true. Validate the Origin header against ' +
        'a strict server-side allow-list.',
    })
  );

  return { findings, errors };
}

/**
 * Analyse CORS-related response headers from a live probe.
 * Returns critical/high findings for genuinely exploitable configurations.
 */
export function analyseCorsHeaders(
  urlStr: string,
  requestOrigin: string,
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

  const acao = toString(headers['access-control-allow-origin']);
  const acac = toString(headers['access-control-allow-credentials']);

  if (!acao) return { findings, errors };

  // Case 1: Wildcard + credentials (browser rejects, but flag for awareness)
  if (acao === '*' && acac === 'true') {
    findings.push(
      buildFinding({
        host, path, url: urlStr,
        severity: 'high',
        category: 'cors',
        title: 'Invalid CORS: Wildcard + Allow-Credentials',
        description:
          'The server sets Access-Control-Allow-Origin: * and Allow-Credentials: true. ' +
          'While browsers reject this combination, misconfigured environments or non-browser ' +
          'clients may still be vulnerable.',
        evidence: `ACAO: ${acao} | ACAC: ${acac}`,
        exploitability: 55,
        remediationHint: 'Remove wildcard; use an explicit allow-listed origin.',
        source: 'live',
        verified: true,
      })
    );
    return { findings, errors };
  }

  // Case 2: Origin reflection + credentials (fully exploitable CORS)
  if (acao === requestOrigin && acac === 'true') {
    findings.push(
      buildFinding({
        host, path, url: urlStr,
        severity: 'critical',
        category: 'cors',
        title: 'Exploitable CORS: Arbitrary Origin Reflection + Allow-Credentials',
        description:
          'The server reflects an arbitrary Origin back in Access-Control-Allow-Origin ' +
          'and sets Access-Control-Allow-Credentials: true. An attacker on any domain can ' +
          "make credentialed cross-origin requests and read the authenticated user's data.",
        evidence:
          `Sent Origin: ${requestOrigin} | ACAO: ${acao} | ACAC: ${acac}`,
        exploitability: 95,
        reproductionSteps: [
          '1. Create a page at https://attacker.example.com with:',
          '   fetch("' + urlStr + '", { credentials: "include" })',
          '   .then(r => r.text()).then(d => exfiltrate(d))',
          '2. Trick an authenticated victim into visiting your page.',
          '3. The victim\'s cookies are sent; the response is readable from the attacker\'s origin.',
        ],
        remediationHint:
          'Validate the Origin header against an explicit server-side allow-list. ' +
          'Never dynamically reflect arbitrary Origins when Allow-Credentials is true.',
        source: 'live',
        verified: true,
      })
    );
  }

  return { findings, errors };
}

function toString(val: string | string[] | undefined): string {
  if (Array.isArray(val)) return val[0] ?? '';
  return val ?? '';
}
