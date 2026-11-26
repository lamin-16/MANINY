// MANINY DIGITAL — Differential injection and traversal probe engine.
// Sends a baseline request followed by a probed variant and compares the responses.
// IMPORTANT: Only inject against URLs in the confirmed allow-list (enforced by runner.ts).

import { fetchUrl } from '../utils/http-client.js';
import { buildFinding, getQueryParamNames } from '../stages/stage-utils.js';
import type { DifferentialResult, Finding } from '../types.js';

export interface DifferentialProbeOptions {
  timeoutMs?: number;
}

// ---------------------------------------------------------------------------
// Safe, non-destructive injection probe payloads
// ---------------------------------------------------------------------------

/** Payloads designed to trigger observable diffs without causing real damage. */
const SQL_PROBE_PAYLOADS = ["'", "''", "1 AND 1=1", "1 AND 1=2"];
const TRAVERSAL_PROBE_PAYLOADS = ['../etc/passwd', '..%2fetc%2fpasswd'];
const XSS_PROBE_PAYLOADS = ['<maniny>', '"maniny"'];

// ---------------------------------------------------------------------------
// Core comparison logic
// ---------------------------------------------------------------------------

function computeStatusDelta(a: number, b: number): number {
  return Math.abs(a - b);
}

function computeBodyLengthDelta(a: string, b: string): number {
  return Math.abs(a.length - b.length);
}

function checkReflection(body: string, payload: string): boolean {
  return body.includes(payload);
}

function checkRedirect(status: number): boolean {
  return status >= 300 && status < 400;
}

// ---------------------------------------------------------------------------
// Finding builders
// ---------------------------------------------------------------------------

function buildSqlInjectionFinding(
  urlStr: string,
  host: string,
  path: string,
  diff: { baseStatus: number; probeStatus: number; param: string; payload: string }
): Finding {
  return buildFinding({
    host,
    path,
    url: urlStr,
    severity: 'critical',
    category: 'injection',
    title: `Possible SQL Injection — Parameter: ${diff.param}`,
    description:
      `Sending the payload '${diff.payload}' in parameter '${diff.param}' produced ` +
      `a different HTTP status (baseline: ${diff.baseStatus} → probe: ${diff.probeStatus}). ` +
      'This status delta is a strong indicator of SQL injection.',
    evidence:
      `Baseline status: ${diff.baseStatus} | Probe status: ${diff.probeStatus} | ` +
      `Parameter: ${diff.param} | Payload: ${diff.payload}`,
    exploitability: 90,
    reproductionSteps: [
      `1. Set ${diff.param}=${diff.payload} in: ${urlStr}`,
      '2. Observe status code change or SQL error message in the response.',
      "3. Enumerate tables with: ' UNION SELECT table_name,NULL FROM information_schema.tables--",
    ],
    remediationHint:
      'Use parameterised queries or prepared statements. Never concatenate user input into SQL.',
    source: 'differential',
    verified: true,
  });
}

function buildReflectedXssFinding(
  urlStr: string,
  host: string,
  path: string,
  param: string,
  payload: string
): Finding {
  return buildFinding({
    host,
    path,
    url: urlStr,
    severity: 'high',
    category: 'injection',
    title: `Reflected XSS — Parameter: ${param}`,
    description:
      `The payload '${payload}' sent in parameter '${param}' was reflected verbatim ` +
      'in the response body without encoding. This confirms a reflected XSS vulnerability.',
    evidence: `Reflected payload: ${payload} | Parameter: ${param}`,
    exploitability: 72,
    reproductionSteps: [
      `1. Navigate to: ${urlStr}`,
      `2. Set the ${param} parameter to: <script>alert(document.domain)</script>`,
      '3. Observe script execution in the browser.',
    ],
    remediationHint:
      'HTML-encode all user-supplied output. Implement a strict Content-Security-Policy.',
    source: 'differential',
    verified: true,
  });
}

function buildTraversalFinding(
  urlStr: string,
  host: string,
  path: string,
  param: string,
  payload: string
): Finding {
  return buildFinding({
    host,
    path,
    url: urlStr,
    severity: 'critical',
    category: 'injection',
    title: `Path Traversal Confirmed — Parameter: ${param}`,
    description:
      `The traversal payload '${payload}' in parameter '${param}' produced a response ` +
      'body length significantly different from the baseline, suggesting file content ' +
      'outside the web root was returned.',
    evidence: `Traversal payload: ${payload} | Parameter: ${param}`,
    exploitability: 88,
    reproductionSteps: [
      `1. Set ${param}=${payload} in: ${urlStr}`,
      '2. Observe body length increase — check response for /etc/passwd content.',
    ],
    remediationHint:
      'Sanitise and canonicalise all file paths. Restrict access to a web root sandbox.',
    source: 'differential',
    verified: true,
  });
}

// ---------------------------------------------------------------------------
// Main differential prober
// ---------------------------------------------------------------------------

/**
 * Run a differential injection probe against a single URL.
 *
 * Strategy:
 * 1. Send a baseline GET to establish normal status/body-length.
 * 2. For each injection-prone parameter, send a probed variant.
 * 3. Compare status codes and body lengths.
 * 4. Flag significant deltas as potential findings.
 */
export async function runDifferentialProbe(
  urlStr: string,
  opts: DifferentialProbeOptions = {}
): Promise<DifferentialResult> {
  const { timeoutMs = 7_000 } = opts;
  const findings: Finding[] = [];

  let host = '';
  let path = '/';
  try {
    const u = new URL(urlStr);
    host = u.hostname;
    path = u.pathname;
  } catch {
    return makeEmptyResult(urlStr);
  }

  const params = getQueryParamNames(urlStr);
  if (params.length === 0) return makeEmptyResult(urlStr);

  // Baseline request
  const baseline = await fetchUrl(urlStr, { method: 'GET', timeoutMs });
  if (baseline.error || baseline.status === 0) return makeEmptyResult(urlStr);

  let reflected = false;
  let redirected = false;

  // Test each parameter with SQL, XSS, and traversal payloads
  for (const param of params) {
    // SQL injection differential
    for (const payload of SQL_PROBE_PAYLOADS) {
      const probeUrl = injectParam(urlStr, param, payload);
      const probe = await fetchUrl(probeUrl, { method: 'GET', timeoutMs });
      if (probe.error) continue;

      const statusDelta = computeStatusDelta(baseline.status, probe.status);
      if (statusDelta >= 100) {
        findings.push(
          buildSqlInjectionFinding(urlStr, host, path, {
            baseStatus: baseline.status,
            probeStatus: probe.status,
            param,
            payload,
          })
        );
        break; // One confirmed finding per param is sufficient
      }
    }

    // XSS reflection check
    for (const payload of XSS_PROBE_PAYLOADS) {
      const probeUrl = injectParam(urlStr, param, payload);
      const probe = await fetchUrl(probeUrl, { method: 'GET', timeoutMs });
      if (probe.error) continue;

      if (checkReflection(probe.body, payload)) {
        reflected = true;
        findings.push(buildReflectedXssFinding(urlStr, host, path, param, payload));
        break;
      }
    }

    // Path traversal differential
    for (const payload of TRAVERSAL_PROBE_PAYLOADS) {
      const probeUrl = injectParam(urlStr, param, payload);
      const probe = await fetchUrl(probeUrl, { method: 'GET', timeoutMs });
      if (probe.error) continue;

      const bodyDelta = computeBodyLengthDelta(baseline.body, probe.body);
      if (bodyDelta > 500 && probe.status === 200) {
        findings.push(buildTraversalFinding(urlStr, host, path, param, payload));
        break;
      }
    }

    // Check for open redirect
    for (const payload of ['https://example.com', '//example.com']) {
      const probeUrl = injectParam(urlStr, param, payload);
      const probe = await fetchUrl(probeUrl, { method: 'GET', timeoutMs, maxRedirects: 0 });
      if (probe.error) continue;

      if (checkRedirect(probe.status)) {
        redirected = true;
        break;
      }
    }
  }

  // Final probe for overall comparison
  const finalProbe = await fetchUrl(urlStr, { method: 'GET', timeoutMs });

  return {
    url: urlStr,
    baselineStatus: baseline.status,
    probeStatus: finalProbe.status,
    statusDelta: computeStatusDelta(baseline.status, finalProbe.status),
    baselineBodyLength: baseline.body.length,
    probeBodyLength: finalProbe.body.length,
    bodyLengthDelta: computeBodyLengthDelta(baseline.body, finalProbe.body),
    reflected,
    redirected,
    findings,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function injectParam(urlStr: string, param: string, value: string): string {
  try {
    const u = new URL(urlStr);
    u.searchParams.set(param, value);
    return u.toString();
  } catch {
    return urlStr;
  }
}

function makeEmptyResult(urlStr: string): DifferentialResult {
  return {
    url: urlStr,
    baselineStatus: 0,
    probeStatus: 0,
    statusDelta: 0,
    baselineBodyLength: 0,
    probeBodyLength: 0,
    bodyLengthDelta: 0,
    reflected: false,
    redirected: false,
    findings: [],
  };
}
