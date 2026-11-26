// MANINY DIGITAL — Static injection vector analysis stage.
// Flags URL patterns that commonly harbour SQL, path-traversal, and command injection.

import {
  buildFinding,
  safeParseUrl,
  getPathSegments,
  getQueryParamNames,
  isInjectionProne,
} from './stage-utils.js';
import type { StageResult } from '../types.js';

const PATH_TRAVERSAL_SIGNALS = [
  '..', '%2e%2e', '%252e%252e', '..%2f', '..%5c',
  '%c0%ae', '%e0%80%ae',
];

/** Detect path-traversal sequences baked into the URL. */
function checkPathTraversal(
  host: string,
  path: string,
  url: string
): StageResult['findings'] {
  const rawUrl = url.toLowerCase();
  const hasTraversal = PATH_TRAVERSAL_SIGNALS.some(seq => rawUrl.includes(seq));
  if (!hasTraversal) return [];

  return [
    buildFinding({
      host,
      path,
      url,
      severity: 'critical',
      category: 'injection',
      title: 'Path Traversal Sequence in URL',
      description:
        'The URL contains a directory traversal sequence ("../" or its encoded variants). ' +
        'If the server does not normalise and sanitise the path before use, an attacker ' +
        'may traverse outside the web root and read arbitrary files on the system.',
      evidence: `URL contains traversal sequence: ${url}`,
      exploitability: 88,
      reproductionSteps: [
        `1. Send a GET request to: ${url}`,
        '2. Observe whether the response contains content from outside the web root.',
        '3. Try variations: ../../etc/passwd, %2e%2e%2fetc%2fpasswd, etc.',
      ],
      remediationHint:
        'Canonicalise and validate all file paths server-side. Restrict file-system ' +
        'access to a defined web root using chroot or equivalent mechanisms.',
      source: 'static',
      verified: false,
    }),
  ];
}

/** Detect injection-prone query parameters. */
function checkInjectionParams(
  host: string,
  path: string,
  url: string,
  params: string[]
): StageResult['findings'] {
  const proneParams = params.filter(isInjectionProne);
  if (proneParams.length === 0) return [];

  return [
    buildFinding({
      host,
      path,
      url,
      severity: 'medium',
      category: 'injection',
      title: 'Injection-Prone Query Parameters Detected',
      description:
        `The URL contains query parameters (${proneParams.join(', ')}) that are ` +
        'commonly used as injection sinks for SQL injection, XSS, or server-side ' +
        'template injection. These require live differential testing to confirm exploitability.',
      evidence: `Injection-prone parameters: ${proneParams.join(', ')}`,
      exploitability: 42,
      reproductionSteps: [
        `1. Identify the parameter(s): ${proneParams.join(', ')} in URL: ${url}`,
        "2. Inject a SQL payload: ' OR '1'='1",
        "3. Inject an XSS payload: <script>alert(1)</script>",
        '4. Observe server response for errors, reflection, or altered behaviour.',
      ],
      remediationHint:
        'Use parameterised queries for all database operations. ' +
        'Apply strict input validation and output encoding for all user-supplied data.',
      source: 'static',
      verified: false,
    }),
  ];
}

/** Detect open-redirect vectors in URL parameters. */
const REDIRECT_PARAMS = ['redirect', 'next', 'return', 'returnto', 'url', 'redir'];

function checkOpenRedirect(
  host: string,
  path: string,
  url: string,
  params: string[]
): StageResult['findings'] {
  const matched = params.filter(p =>
    REDIRECT_PARAMS.includes(p.toLowerCase())
  );
  if (matched.length === 0) return [];

  return matched.map(param =>
    buildFinding({
      host,
      path,
      url,
      severity: 'medium',
      category: 'injection',
      title: 'Potential Open Redirect Parameter',
      description:
        `The parameter '${param}' is commonly used to redirect users after an action. ` +
        'If the server does not validate that the redirect target is within the same ' +
        'origin, an attacker can redirect victims to phishing or malware sites.',
      evidence: `Redirect parameter: ${param}`,
      exploitability: 38,
      reproductionSteps: [
        `1. Modify the ${param} parameter in: ${url}`,
        '2. Set its value to: https://attacker.example.com',
        '3. Send the modified URL to a victim. Observe whether the server follows the redirect.',
      ],
      remediationHint:
        'Validate redirect destinations against an allow-list of trusted origins. ' +
        'Never redirect to arbitrary user-supplied URLs.',
    })
  );
}

/**
 * Run the injection static analysis stage on a single URL.
 */
export function runInjectionStage(urlStr: string): StageResult {
  const findings: StageResult['findings'] = [];
  const errors: string[] = [];

  const parsed = safeParseUrl(urlStr);
  if (!parsed) {
    errors.push(`Cannot parse URL: ${urlStr}`);
    return { findings, errors };
  }

  const host = parsed.hostname;
  const path = parsed.pathname;
  const params = getQueryParamNames(urlStr);

  findings.push(
    ...checkPathTraversal(host, path, urlStr),
    ...checkInjectionParams(host, path, urlStr, params),
    ...checkOpenRedirect(host, path, urlStr, params)
  );

  return { findings, errors };
}
