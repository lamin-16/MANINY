// MANINY DIGITAL — JWT weakness analyzer.
// Detects alg:none, weak algorithms, expired tokens accepted, and sensitive data in payload.

import { buildFinding } from '../stages/stage-utils.js';
import type { Finding } from '../types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function base64UrlDecode(str: string): string {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/')
    + '=='.slice(0, (4 - (str.length % 4)) % 4);
  try {
    return Buffer.from(padded, 'base64').toString('utf-8');
  } catch {
    return '';
  }
}

function parseJwtParts(token: string): {
  header:  Record<string, unknown>;
  payload: Record<string, unknown>;
} | null {
  const parts = token.split('.');
  if (parts.length < 2) return null;

  try {
    const header  = JSON.parse(base64UrlDecode(parts[0] ?? '')) as Record<string, unknown>;
    const payload = JSON.parse(base64UrlDecode(parts[1] ?? '')) as Record<string, unknown>;
    return { header, payload };
  } catch {
    return null;
  }
}

/** Extract JWT tokens from Authorization headers or response bodies. */
export function extractJwts(
  headers: Record<string, string | string[] | undefined>,
  body: string
): string[] {
  const tokens = new Set<string>();

  // Authorization: Bearer <token>
  const auth = headers['authorization'];
  const authStr = Array.isArray(auth) ? (auth[0] ?? '') : (auth ?? '');
  const bearerMatch = authStr.match(/^Bearer\s+([\w-]+\.[\w-]+\.[\w-]*)$/i);
  if (bearerMatch?.[1]) tokens.add(bearerMatch[1]);

  // JWT pattern in body or response (3 base64url segments separated by dots)
  const JWT_PATTERN = /(ey[\w-]+\.ey[\w-]+\.[\w-]*)/g;
  for (const match of body.matchAll(JWT_PATTERN)) {
    if (match[1]) tokens.add(match[1]);
  }

  return [...tokens];
}

// ---------------------------------------------------------------------------
// Weakness detection
// ---------------------------------------------------------------------------

/** Analyze a single JWT and return any findings. */
export function analyzeJwt(
  token: string,
  urlStr: string,
  host: string,
  path: string
): Finding[] {
  const parsed = parseJwtParts(token);
  if (!parsed) return [];

  const { header, payload } = parsed;
  const findings: Finding[] = [];
  const alg = typeof header['alg'] === 'string' ? header['alg'] : '';

  // --- alg: none ---
  if (/^none$/i.test(alg)) {
    findings.push(
      buildFinding({
        host, path, url: urlStr,
        severity:       'critical',
        category:       'auth',
        title:          'JWT Algorithm Set to "none" — Signature Bypass',
        description:
          'The JWT uses alg:"none", meaning the server accepts unsigned tokens. ' +
          'An attacker can craft any payload (e.g., admin:true) without knowing ' +
          'the signing secret and the server will accept it.',
        evidence:       `JWT header: ${JSON.stringify(header)}`,
        exploitability: 95,
        reproductionSteps: [
          '1. Decode the JWT header+payload.',
          '2. Modify payload claims (e.g. set "admin": true, "role": "superuser").',
          '3. Re-encode with alg:"none" and an empty signature.',
          '4. Send the crafted token — the server should accept it.',
        ],
        remediationHint:
          'Explicitly reject tokens with alg:"none". Use an allow-list of accepted ' +
          'algorithms (e.g. RS256 or ES256). Never trust the alg field from the token itself.',
        source:  'live',
        verified: true,
      })
    );
  }

  // --- Symmetric algorithm used with API (HS256/HS384/HS512) ---
  if (/^HS\d+$/i.test(alg)) {
    findings.push(
      buildFinding({
        host, path, url: urlStr,
        severity:       'medium',
        category:       'auth',
        title:          `JWT Uses Symmetric Algorithm: ${alg}`,
        description:
          `The JWT is signed with ${alg} (HMAC). If the secret is weak or reused ` +
          'across services, an attacker can brute-force or guess it and forge arbitrary tokens. ' +
          'Asymmetric algorithms (RS256, ES256) are preferred for APIs.',
        evidence:       `JWT alg: ${alg}`,
        exploitability: 42,
        remediationHint:
          'Prefer RS256 or ES256 for JWTs. If HMAC is required, use a cryptographically ' +
          'random secret of at least 256 bits.',
        source: 'live',
      })
    );
  }

  // --- Expired token accepted ---
  const exp = typeof payload['exp'] === 'number' ? payload['exp'] : null;
  if (exp !== null && exp < Math.floor(Date.now() / 1000)) {
    findings.push(
      buildFinding({
        host, path, url: urlStr,
        severity:       'high',
        category:       'auth',
        title:          'JWT Expired Token Accepted',
        description:
          'The server accepted a JWT whose "exp" claim has already elapsed. ' +
          'This allows captured tokens to remain valid indefinitely, negating ' +
          'the purpose of token expiration.',
        evidence:       `exp: ${exp} (expired ${new Date(exp * 1000).toISOString()})`,
        exploitability: 70,
        reproductionSteps: [
          '1. Capture a JWT from a previous authenticated session.',
          '2. Wait until the token\'s "exp" time has passed.',
          '3. Re-send the expired token — if accepted, expiration is not enforced.',
        ],
        remediationHint:
          'Validate the "exp" claim on every request. Use short-lived tokens (15–60 min) ' +
          'with refresh token rotation.',
        source:  'live',
        verified: true,
      })
    );
  }

  // --- Sensitive claims in unencrypted payload ---
  const sensitiveKeys = ['password', 'pwd', 'secret', 'ssn', 'credit_card', 'card'];
  const foundKeys = Object.keys(payload).filter(k =>
    sensitiveKeys.some(s => k.toLowerCase().includes(s))
  );

  if (foundKeys.length > 0) {
    findings.push(
      buildFinding({
        host, path, url: urlStr,
        severity:       'high',
        category:       'auth',
        title:          'Sensitive Data in JWT Payload',
        description:
          `The JWT payload contains potentially sensitive claim(s): ${foundKeys.join(', ')}. ` +
          'JWT payloads are only Base64-encoded — not encrypted. Anyone who intercepts ' +
          'the token can read these values.',
        evidence:       `Sensitive claim keys: ${foundKeys.join(', ')}`,
        exploitability: 65,
        remediationHint:
          'Never store sensitive data in JWT payloads. Use JWE (JSON Web Encryption) ' +
          'if payload confidentiality is required.',
        source: 'live',
      })
    );
  }

  return findings;
}

/** Analyze all JWTs extracted from a response. */
export function analyzeAllJwts(
  urlStr: string,
  host: string,
  path: string,
  headers: Record<string, string | string[] | undefined>,
  body: string
): Finding[] {
  const tokens = extractJwts(headers, body);
  return tokens.flatMap(t => analyzeJwt(t, urlStr, host, path));
}
