// MANINY DIGITAL — Scan orchestrator v2.
// Integrates: static stages, session manager, rate limiter, live probe,
// tech fingerprinting, JWT analysis, auth/CORS prober, differential injection,
// elite engine, and hybrid chain correlation.

import { createRequire } from 'node:module';
const _require = createRequire(import.meta.url);
const _pkg = (_require('../package.json') as { version: string });

import { filterAllowedUrls }  from './utils/host-validator.js';
import { uniqueById, generateScanId } from './utils/deduplicator.js';
import { warn } from './utils/json-output.js';

import { runHeadersStage }    from './stages/headers-stage.js';
import { runAuthStage }       from './stages/auth-stage.js';
import { runInjectionStage }  from './stages/injection-stage.js';
import { runCorsStage }       from './stages/cors-stage.js';

import { probeAndAnalyse }    from './core/live-probe-runner.js';
import { probeAuthSession }   from './core/http-auth-session-prober.js';
import { runDifferentialProbe } from './core/differential-injection-prober.js';
import { runEliteEngine }     from './core/elite-attack-engine.js';
import { SessionManager }     from './core/session-manager.js';
import { RateLimiter }        from './core/rate-limiter.js';

import { runSsrfProbe }             from './core/ssrf-prober.js';
import { checkSubdomainTakeovers }  from './core/subdomain-takeover.js';
import {
  hybridChains,
  buildComplianceResults,
  buildAgentOutputs,
  buildTopExploitabilityRank,
  buildSummary,
} from './core/exploit-chain-verifier.js';

import type {
  AttackReport,
  Finding,
  ScanConfig,
  TechFingerprint,
} from './types.js';

// ---------------------------------------------------------------------------
// Per-URL result collector
// ---------------------------------------------------------------------------

interface UrlScanResult {
  staticFindings: Finding[];
  liveFindings:   Finding[];
  diffFindings:   Finding[];
  fingerprint:    TechFingerprint | null;
  wafDetected:    boolean;
}

async function scanUrl(
  urlStr:      string,
  session:     SessionManager,
  rateLimiter: RateLimiter,
  timeoutMs:   number,
  checkSsrf:   boolean,
  checkTakeover: boolean
): Promise<UrlScanResult> {
  let host = '';
  try { host = new URL(urlStr).hostname; } catch { /* ok */ }

  // Phase 1 — Static stages (zero network)
  const staticFindings: Finding[] = [
    ...runHeadersStage(urlStr).findings,
    ...runAuthStage(urlStr).findings,
    ...runInjectionStage(urlStr).findings,
    ...runCorsStage(urlStr).findings,
  ];

  // Phase 2 — Live HTTP probe (tech fingerprint + header analysis + JWTs)
  await rateLimiter.throttle(host);
  const liveAnalysis = await probeAndAnalyse(urlStr, { timeoutMs, session })
    .catch(() => ({ findings: [], fingerprint: null, wafDetected: false }));

  // Phase 3 — Auth/CORS session probe
  await rateLimiter.throttle(host);
  const authResult = await probeAuthSession(urlStr, { timeoutMs, session })
    .catch(() => ({ findings: [], errors: [] }));

  // Phase 4 — Differential injection
  await rateLimiter.throttle(host);
  const diffResult = await runDifferentialProbe(urlStr, {
    timeoutMs,
    session,
    wafPresent: liveAnalysis.wafDetected,
  }).catch(() => ({ findings: [] }));

  const ssrfFindings = checkSsrf
    ? await runSsrfProbe(urlStr, { timeoutMs, session }).catch(() => [])
    : [];

  const takeoverFindings = checkTakeover
    ? await checkSubdomainTakeovers([urlStr], { timeoutMs }).catch(() => [])
    : [];

  return {
    staticFindings,
    liveFindings: [...liveAnalysis.findings, ...authResult.findings],
    diffFindings: [...diffResult.findings, ...ssrfFindings, ...takeoverFindings],
    fingerprint:  liveAnalysis.fingerprint,
    wafDetected:  liveAnalysis.wafDetected,
  };
}

// ---------------------------------------------------------------------------
// Concurrency worker pool
// ---------------------------------------------------------------------------

async function scanWithPool(
  urls:        string[],
  concurrency: number,
  fn:          (url: string) => Promise<UrlScanResult>
): Promise<UrlScanResult[]> {
  const results: UrlScanResult[] = [];
  const queue = [...urls];

  async function worker(): Promise<void> {
    while (queue.length > 0) {
      const url = queue.shift();
      if (!url) return;
      results.push(await fn(url));
    }
  }

  const workers = Array.from(
    { length: Math.min(concurrency, urls.length) },
    () => worker()
  );
  await Promise.all(workers);
  return results;
}

// ---------------------------------------------------------------------------
// httpx NDJSON pipe reader
// ---------------------------------------------------------------------------

async function readHttpxUrls(): Promise<string[]> {
  const { createInterface } = await import('node:readline');
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  const urls: string[] = [];

  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const obj = JSON.parse(trimmed) as Record<string, unknown>;
      const url = typeof obj['url'] === 'string' ? obj['url'] : null;
      if (url) urls.push(url);
    } catch { /* skip non-JSON lines */ }
  }
  return urls;
}

// ---------------------------------------------------------------------------
// Main scan entry point
// ---------------------------------------------------------------------------

export async function runScan(config: ScanConfig): Promise<AttackReport> {
  const {
    allowedHosts,
    targetUrls: configUrls,
    timeoutMs,
    session:     sessionConfig,
    rateLimitMs,
    concurrency,
    fromHttpxPipe,
    checkSsrf,
    checkTakeover,
  } = config;

  // Collect URLs — from CLI args or httpx NDJSON stdin pipe
  const rawUrls = fromHttpxPipe
    ? await readHttpxUrls().catch(() => configUrls)
    : configUrls;

  const { allowed, rejected } = filterAllowedUrls(rawUrls, allowedHosts);

  if (rejected.length > 0) {
    warn(`Rejected ${rejected.length} URL(s) not in --allow-hosts: ${rejected.join(', ')}`);
  }
  if (allowed.length === 0) {
    warn('No URLs passed the allow-hosts gate. Producing empty report.');
  }

  const session     = new SessionManager(sessionConfig);
  const rateLimiter = new RateLimiter(rateLimitMs);

  // Scan all allowed URLs using the concurrency pool
  const urlResults = await scanWithPool(
    allowed,
    concurrency,
    url => scanUrl(url, session, rateLimiter, timeoutMs, checkSsrf, checkTakeover)
  );

  // Flatten per-stage finding buckets
  const allStatic:  Finding[] = urlResults.flatMap(r => r.staticFindings);
  const allLive:    Finding[] = urlResults.flatMap(r => r.liveFindings);
  const allDiff:    Finding[] = urlResults.flatMap(r => r.diffFindings);
  const allPrints:  TechFingerprint[] = urlResults
    .map(r => r.fingerprint)
    .filter((fp): fp is TechFingerprint => fp !== null);

  // Phase 5 — Elite engine enrichment
  const preElite   = [...allStatic, ...allLive, ...allDiff];
  const enriched   = runEliteEngine(preElite);
  const allElite   = enriched.filter(ef =>
    !preElite.some(pf => pf.id === ef.id && pf.severity === ef.severity)
  );

  // Merge & deduplicate
  const allFindings = uniqueById([...enriched, ...allElite]);

  // Hybrid chain correlation
  const chains   = hybridChains(allFindings);
  const chainIds = chains.map(c => c.id);

  // Report sections
  const topRank    = buildTopExploitabilityRank(allFindings);
  const compliance = buildComplianceResults(allFindings);
  const summary    = buildSummary(allFindings, chains);

  // Per-host agent outputs
  const hostSet = new Set(allowed.map(u => {
    try { return new URL(u).hostname; } catch { return ''; }
  }).filter(Boolean));

  const agents = [...hostSet].flatMap(host =>
    buildAgentOutputs({
      staticFindings: allStatic.filter(f => f.host === host),
      liveFindings:   allLive.filter(f => f.host === host),
      diffFindings:   allDiff.filter(f => f.host === host),
      eliteFindings:  allElite.filter(f => f.host === host),
      host,
      chainIds: chains.filter(c => c.host === host).map(c => c.id),
    })
  );

  return {
    scanId:    generateScanId(),
    timestamp: new Date().toISOString(),
    version:   _pkg.version,
    target:    { hosts: allowedHosts, urls: allowed },
    summary,
    findings:              allFindings,
    hybridChains:          chains,
    topExploitabilityRank: topRank,
    agents,
    compliance,
    techFingerprints:      allPrints,
  };
}
