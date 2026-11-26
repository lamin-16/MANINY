// MANINY DIGITAL — Safe, non-destructive live HTTP probe runner.
// Makes real HEAD/GET requests to authorised targets and returns structured results.

import { fetchUrl } from '../utils/http-client.js';
import { analyseResponseHeaders } from '../stages/headers-stage.js';
import type { Finding, LiveProbeResult, StageResult } from '../types.js';

export interface LiveProbeOptions {
  timeoutMs?: number;
  method?: 'HEAD' | 'GET';
}

/**
 * Perform a live HEAD probe against a URL.
 * Returns the raw HTTP response data for downstream analysis.
 * Network errors are captured in the result — not thrown.
 */
export async function runLiveProbe(
  urlStr: string,
  opts: LiveProbeOptions = {}
): Promise<LiveProbeResult> {
  const { timeoutMs = 7_000, method = 'HEAD' } = opts;

  let host: string;
  try {
    host = new URL(urlStr).hostname;
  } catch {
    host = '';
  }

  const httpResponse = await fetchUrl(urlStr, { method, timeoutMs });

  return { url: urlStr, host, httpResponse };
}

/**
 * Analyse a completed LiveProbeResult and produce header-related findings.
 * Returns an empty list when the probe resulted in a network error.
 */
export function analyseLiveProbe(probe: LiveProbeResult): Finding[] {
  if (probe.httpResponse.error) return [];
  if (probe.httpResponse.status === 0) return [];

  const result: StageResult = analyseResponseHeaders(
    probe.url,
    probe.httpResponse.headers
  );

  return result.findings;
}

/**
 * Convenience wrapper: probe a URL and immediately return analysed findings.
 */
export async function probeAndAnalyse(
  urlStr: string,
  opts: LiveProbeOptions = {}
): Promise<Finding[]> {
  const probe = await runLiveProbe(urlStr, opts);
  return analyseLiveProbe(probe);
}

/**
 * Run live probes against multiple URLs in parallel.
 * Returns a flattened array of all analysed findings.
 */
export async function runLiveProbes(
  urls: string[],
  opts: LiveProbeOptions = {}
): Promise<Finding[]> {
  const probes = await Promise.all(urls.map(u => probeAndAnalyse(u, opts)));
  return probes.flat();
}
