import { fetchUrl } from '../utils/http-client.js';
import { buildFinding } from '../stages/stage-utils.js';
import type { Finding } from '../types.js';

export interface TakeoverOptions {
  timeoutMs?: number;
}

interface TakeoverSignature {
  service:  string;
  patterns: RegExp[];
  severity: 'critical' | 'high';
}

const SIGNATURES: TakeoverSignature[] = [
  {
    service:  'GitHub Pages',
    patterns: [/there isn't a github pages site here/i, /for root urls.*github/i],
    severity: 'critical',
  },
  {
    service:  'AWS S3',
    patterns: [/nosuchbucket/i, /the specified bucket does not exist/i],
    severity: 'critical',
  },
  {
    service:  'AWS CloudFront',
    patterns: [/bad request.*cloudfront/i],
    severity: 'high',
  },
  {
    service:  'Heroku',
    patterns: [/no such app/i, /there is no app configured at that hostname/i],
    severity: 'critical',
  },
  {
    service:  'Netlify',
    patterns: [/not found.*netlify/i, /netlify.*page not found/i],
    severity: 'critical',
  },
  {
    service:  'Vercel',
    patterns: [/the deployment could not be found/i],
    severity: 'critical',
  },
  {
    service:  'Shopify',
    patterns: [/sorry, this shop is currently unavailable/i],
    severity: 'critical',
  },
  {
    service:  'Ghost',
    patterns: [/the thing you were looking for is no longer here/i],
    severity: 'high',
  },
  {
    service:  'Tumblr',
    patterns: [/whatever you were looking for doesn't currently exist/i],
    severity: 'high',
  },
  {
    service:  'WordPress.com',
    patterns: [/do you want to register.*\.wordpress\.com/i],
    severity: 'critical',
  },
  {
    service:  'Zendesk',
    patterns: [/help center closed/i],
    severity: 'high',
  },
  {
    service:  'Fastly',
    patterns: [/fastly error.*unknown domain/i],
    severity: 'critical',
  },
  {
    service:  'Azure',
    patterns: [/404 web site not found.*microsoft/i, /this microsoft azure app/i],
    severity: 'high',
  },
  {
    service:  'Unbounce',
    patterns: [/the page you're looking for doesn't exist/i],
    severity: 'high',
  },
  {
    service:  'Cargo',
    patterns: [/if you're moving your domain away from cargo/i],
    severity: 'high',
  },
  {
    service:  'Fly.io',
    patterns: [/404.*fly\.io/i],
    severity: 'high',
  },
  {
    service:  'Render',
    patterns: [/there's nothing here, yet.*render/i],
    severity: 'high',
  },
];

function matchSignature(body: string): TakeoverSignature | null {
  for (const sig of SIGNATURES) {
    if (sig.patterns.some(p => p.test(body))) return sig;
  }
  return null;
}

export async function checkSubdomainTakeover(
  urlStr: string,
  opts: TakeoverOptions = {}
): Promise<Finding[]> {
  const { timeoutMs = 7_000 } = opts;

  let host = '';
  let path = '/';
  try {
    const u = new URL(urlStr);
    host = u.hostname;
    path = u.pathname;
  } catch {
    return [];
  }

  const resp = await fetchUrl(urlStr, { method: 'GET', timeoutMs }).catch(() => null);
  if (!resp || resp.error) return [];

  const sig = matchSignature(resp.body);
  if (!sig) return [];

  return [
    buildFinding({
      host, path, url: urlStr,
      severity:       sig.severity,
      category:       'takeover',
      title:          `Subdomain Takeover — ${sig.service}`,
      description:
        `The subdomain '${host}' resolves but returns a '${sig.service}' ` +
        `unclaimed-resource error page. An attacker can register the resource ` +
        `on ${sig.service} and serve arbitrary content under this trusted domain, ` +
        `enabling phishing, session cookie theft, and CSP bypass.`,
      evidence:       `HTTP ${resp.status} · ${sig.service} takeover fingerprint matched`,
      exploitability: sig.severity === 'critical' ? 93 : 75,
      reproductionSteps: [
        `1. Verify the DNS record for '${host}' points to ${sig.service}.`,
        `2. Register/claim the resource name on ${sig.service}.`,
        '3. Serve a phishing page or malicious script from the now-controlled subdomain.',
        '4. Cookies scoped to the parent domain are readable from the takeover subdomain.',
      ],
      remediationHint:
        `Remove or update the DNS record for '${host}'. ` +
        'Audit all CNAME records pointing to third-party services that no longer have an active resource.',
      source:   'live',
      verified: true,
    }),
  ];
}

export async function checkSubdomainTakeovers(
  urls: string[],
  opts: TakeoverOptions = {}
): Promise<Finding[]> {
  const results = await Promise.allSettled(urls.map(u => checkSubdomainTakeover(u, opts)));
  return results.flatMap(r => r.status === 'fulfilled' ? r.value : []);
}
