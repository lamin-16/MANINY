// MANINY DIGITAL — Live HTTP probe runner.
// Session-aware HEAD/GET probe with tech fingerprinting and JWT analysis.

import { fetchUrl } from '../utils/http-client.js';
import { analyseResponseHeaders } from '../stages/headers-stage.js';
import { fingerprintTech, techFindingsFrom } from './tech-fingerprinter.js';
import { analyzeAllJwts } from './jwt-analyzer.js';
import type { Finding, LiveProbeResult, TechFingerprint } from '../types.js';
import type { SessionManager } from './session-manager.js';

export interface LiveProbeOptions {
  timeoutMs?: number;
  method?:    'HEAD' | 'GET';
  session?:   SessionManager;
}

export interface LiveProbeAnalysis {
  findings:    Finding[];
  fingerprint: TechFingerprint | null;
  wafDetected: boolean;
}

/** Perform a single live probe and return the raw HTTP response data. */
export async function runLiveProbe(
  urlStr: string,
  opts: LiveProbeOptions = {}
): Promise<LiveProbeResult> {
  const { timeoutMs = 7_000, method = 'HEAD', session } = opts;

  let host = '';
  try { host = new URL(urlStr).hostname; } catch { /* unparseable */ }

  const headers = session?.buildHeaders() ?? {};
  const httpResponse = await fetchUrl(urlStr, { method, timeoutMs, headers });

  // If HEAD returned no body, follow up with GET to enable body-based analysis
  if (method === 'HEAD' && !httpResponse.error) {
    const getResponse = await fetchUrl(urlStr, { method: 'GET', timeoutMs, headers });
    return { url: urlStr, host, httpResponse: getResponse };
  }

  return { url: urlStr, host, httpResponse };
}

/** Analyse a completed LiveProbeResult — headers, tech, JWTs, security headers. */
export function analyseLiveProbe(probe: LiveProbeResult): LiveProbeAnalysis {
  const empty: LiveProbeAnalysis = { findings: [], fingerprint: null, wafDetected: false };

  if (probe.httpResponse.error || probe.httpResponse.status === 0) return empty;

  const { url, host, httpResponse } = probe;
  let path = '/';
  try { path = new URL(url).pathname; } catch { /* ok */ }

  const findings: Finding[] = [];

  // Security header analysis
  const headerResult = analyseResponseHeaders(url, httpResponse.headers);
  findings.push(...headerResult.findings);

  // Technology fingerprinting
  const fingerprint = fingerprintTech(host, httpResponse.headers, httpResponse.body);
  findings.push(...techFindingsFrom(url, host, path, fingerprint));

  // JWT analysis (from both request and response)
  findings.push(...analyzeAllJwts(url, host, path, httpResponse.headers, httpResponse.body));

  return {
    findings,
    fingerprint,
    wafDetected: fingerprint.wafDetected,
  };
}

/** Convenience wrapper: probe + analyse in one call. */
export async function probeAndAnalyse(
  urlStr: string,
  opts: LiveProbeOptions = {}
): Promise<LiveProbeAnalysis> {
  const probe = await runLiveProbe(urlStr, opts);
  return analyseLiveProbe(probe);
}
