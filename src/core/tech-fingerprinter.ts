// MANINY DIGITAL — Technology fingerprinter: server, framework, WAF, CDN detection.
// Derives intelligence from response headers without additional requests.

import { buildFinding } from '../stages/stage-utils.js';
import type { Finding, TechEntry, TechFingerprint } from '../types.js';

// ---------------------------------------------------------------------------
// Signature definitions
// ---------------------------------------------------------------------------

interface Sig {
  header:       string;
  pattern:      RegExp;
  tech:         string;
  category:     TechEntry['category'];
  versionGroup?: number;  // regex capture group index for version
}

const TECH_SIGNATURES: Sig[] = [
  // --- Servers ---
  { header: 'server', pattern: /nginx\/?([\d.]+)?/i,                tech: 'Nginx',       category: 'server', versionGroup: 1 },
  { header: 'server', pattern: /apache\/?([\d.]+)?/i,               tech: 'Apache',      category: 'server', versionGroup: 1 },
  { header: 'server', pattern: /microsoft-iis\/?([\d.]+)?/i,        tech: 'IIS',         category: 'server', versionGroup: 1 },
  { header: 'server', pattern: /lighttpd\/?([\d.]+)?/i,             tech: 'Lighttpd',    category: 'server', versionGroup: 1 },
  { header: 'server', pattern: /openresty\/?([\d.]+)?/i,            tech: 'OpenResty',   category: 'server', versionGroup: 1 },
  { header: 'server', pattern: /caddy/i,                             tech: 'Caddy',       category: 'server' },
  { header: 'server', pattern: /gunicorn\/?([\d.]+)?/i,             tech: 'Gunicorn',    category: 'server', versionGroup: 1 },
  { header: 'server', pattern: /kestrel/i,                           tech: 'Kestrel',     category: 'server' },
  { header: 'server', pattern: /tomcat\/?([\d.]+)?/i,               tech: 'Tomcat',      category: 'server', versionGroup: 1 },

  // --- Languages ---
  { header: 'x-powered-by', pattern: /php\/([\d.]+)/i,              tech: 'PHP',         category: 'language', versionGroup: 1 },
  { header: 'x-powered-by', pattern: /asp\.net/i,                   tech: 'ASP.NET',     category: 'language' },
  { header: 'x-powered-by', pattern: /mono/i,                       tech: 'Mono',        category: 'language' },

  // --- Frameworks ---
  { header: 'x-powered-by',    pattern: /express/i,                 tech: 'Express.js',  category: 'framework' },
  { header: 'x-powered-by',    pattern: /next\.js/i,                tech: 'Next.js',     category: 'framework' },
  { header: 'x-generator',     pattern: /wordpress ([\d.]+)/i,      tech: 'WordPress',   category: 'framework', versionGroup: 1 },
  { header: 'x-drupal-cache',  pattern: /.+/,                       tech: 'Drupal',      category: 'framework' },
  { header: 'x-shopify-stage', pattern: /.+/,                       tech: 'Shopify',     category: 'framework' },
  { header: 'x-joomla',        pattern: /.+/,                       tech: 'Joomla',      category: 'framework' },
  { header: 'x-magento-cache-debug', pattern: /.+/,                 tech: 'Magento',     category: 'framework' },
  { header: 'x-laravel',       pattern: /.+/,                       tech: 'Laravel',     category: 'framework' },
  { header: 'x-django-version', pattern: /([\d.]+)/i,               tech: 'Django',      category: 'framework', versionGroup: 1 },

  // --- CDN ---
  { header: 'cf-ray',               pattern: /.+/,                  tech: 'Cloudflare',  category: 'cdn' },
  { header: 'x-amz-cf-id',          pattern: /.+/,                  tech: 'CloudFront',  category: 'cdn' },
  { header: 'x-fastly-request-id',  pattern: /.+/,                  tech: 'Fastly',      category: 'cdn' },
  { header: 'x-akamai-transformed', pattern: /.+/,                  tech: 'Akamai',      category: 'cdn' },
  { header: 'via',                   pattern: /varnish/i,            tech: 'Varnish',     category: 'cdn' },
  { header: 'x-cache',               pattern: /cloudfront/i,         tech: 'CloudFront',  category: 'cdn' },

  // --- WAF ---
  { header: 'x-sucuri-id',          pattern: /.+/,                  tech: 'Sucuri',      category: 'waf' },
  { header: 'x-sucuri-cache',       pattern: /.+/,                  tech: 'Sucuri',      category: 'waf' },
  { header: 'x-iinfo',              pattern: /.+/,                  tech: 'Imperva',     category: 'waf' },
  { header: 'x-fw-hash',            pattern: /.+/,                  tech: 'Fastly WAF',  category: 'waf' },
  { header: 'x-waf-event-info',     pattern: /.+/,                  tech: 'Generic WAF', category: 'waf' },
  { header: 'server',               pattern: /mod_security/i,       tech: 'ModSecurity', category: 'waf' },
];

const WAF_BODY_PATTERNS: RegExp[] = [
  /cloudflare ray id/i,
  /blocked by cloudflare/i,
  /incapsula incident/i,
  /request unsuccessful\. incapsula/i,
  /sucuri website firewall/i,
  /mod_security/i,
  /the requested url was rejected/i,
  /access denied.*reference.*#/i,
];

// ---------------------------------------------------------------------------
// Core fingerprinting logic
// ---------------------------------------------------------------------------

function headerStr(
  headers: Record<string, string | string[] | undefined>,
  name: string
): string {
  const v = headers[name.toLowerCase()];
  return Array.isArray(v) ? (v[0] ?? '') : (v ?? '');
}

/** Inspect response headers and body to derive technology stack. */
export function fingerprintTech(
  host: string,
  headers: Record<string, string | string[] | undefined>,
  body: string
): TechFingerprint {
  const techMap = new Map<string, TechEntry>();
  let wafDetected = false;

  for (const sig of TECH_SIGNATURES) {
    const val = headerStr(headers, sig.header);
    if (!val) continue;

    const match = val.match(sig.pattern);
    if (!match) continue;

    if (sig.category === 'waf') wafDetected = true;

    const key = sig.tech;
    if (!techMap.has(key)) {
      const version =
        sig.versionGroup !== undefined
          ? (match[sig.versionGroup] ?? undefined)
          : undefined;
      if (version !== undefined) { techMap.set(key, { name: sig.tech, category: sig.category, version }); } else { techMap.set(key, { name: sig.tech, category: sig.category }); }
    }
  }

  // Body-based WAF detection
  if (!wafDetected && WAF_BODY_PATTERNS.some(p => p.test(body))) {
    wafDetected = true;
    techMap.set('WAF (body-detected)', { name: 'WAF (body-detected)', category: 'waf' });
  }

  return { host, techs: [...techMap.values()], wafDetected };
}

// ---------------------------------------------------------------------------
// Security findings derived from tech fingerprint
// ---------------------------------------------------------------------------

/** Emit findings for version disclosure or dangerous tech exposure. */
export function techFindingsFrom(
  urlStr: string,
  host: string,
  path: string,
  fp: TechFingerprint
): Finding[] {
  const findings: Finding[] = [];

  for (const tech of fp.techs) {
    // Version disclosure
    if (tech.version) {
      findings.push(
        buildFinding({
          host, path, url: urlStr,
          severity:       'low',
          category:       'headers',
          title:          `Version Disclosure: ${tech.name} ${tech.version}`,
          description:
            `The response header reveals the exact version of ${tech.name} ` +
            `(${tech.version}). Attackers use version information to find ` +
            `known CVEs for the specific installed version.`,
          evidence:       `${tech.name} version ${tech.version} in response header`,
          exploitability: 15,
          remediationHint:
            `Configure the web server to suppress the version number ` +
            `from '${tech.category}' headers.`,
          source: 'live',
        })
      );
    }

    // WAF presence — informational (helps downstream stages calibrate)
    if (tech.category === 'waf') {
      findings.push(
        buildFinding({
          host, path, url: urlStr,
          severity:       'info',
          category:       'headers',
          title:          `WAF Detected: ${tech.name}`,
          description:
            `A Web Application Firewall (${tech.name}) was detected. ` +
            `Active injection probes may be blocked or rate-limited.`,
          evidence:       `WAF signature: ${tech.name}`,
          exploitability: 0,
          remediationHint: 'WAF presence noted. Ensure WAF rules are kept current.',
          source: 'live',
        })
      );
    }
  }

  return findings;
}
