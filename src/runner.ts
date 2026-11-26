// MANINY DIGITAL — Scan orchestrator.
// Coordinates static stages, live probes, differential injection, and chain scoring
// into a single AttackReport.

import { filterAllowedUrls } from './utils/host-validator.js';
import { uniqueById, generateScanId } from './utils/deduplicator.js';
import { warn } from './utils/json-output.js';

import { runHeadersStage } from './stages/headers-stage.js';
import { runAuthStage } from './stages/auth-stage.js';
import { runInjectionStage } from './stages/injection-stage.js';
import { runCorsStage } from './stages/cors-stage.js';

import { probeAndAnalyse } from './core/live-probe-runner.js';
import { probeAuthSession } from './core/http-auth-session-prober.js';
import { runDifferentialProbe } from './core/differential-injection-prober.js';
import { runEliteEngine } from './core/elite-attack-engine.js';

import {
  hybridChains,
  buildComplianceResults,
  buildAgentOutputs,
  buildTopExploitabilityRank,
  buildSummary,
} from './core/exploit-chain-verifier.js';

import type { AttackReport, Finding, ScanConfig } from './types.js';

// ---------------------------------------------------------------------------
// Main scan entry point
// ---------------------------------------------------------------------------

/**
 * Run a full MANINY scan and return a structured AttackReport.
 *
 * The scan proceeds in four phases per URL:
 * 1. Static analysis (no network).
 * 2. Live HTTP probe.
 * 3. Auth/CORS session probe.
 * 4. Differential injection probe.
 *
 * All findings are deduplicated with uniqueById, then correlated into
 * hybridChains and scored by the exploit chain verifier.
 */
export async function runScan(config: ScanConfig): Promise<AttackReport> {
  const { allowedHosts, targetUrls, timeoutMs } = config;

  const { allowed, rejected } = filterAllowedUrls(targetUrls, allowedHosts);

  if (rejected.length > 0) {
    warn(
      `Rejected ${rejected.length} URL(s) not covered by --allow-hosts: ` +
        rejected.join(', ')
    );
  }

  if (allowed.length === 0) {
    warn('No target URLs passed the allow-hosts gate. Producing empty report.');
  }

  const allStaticFindings: Finding[] = [];
  const allLiveFindings: Finding[] = [];
  const allDiffFindings: Finding[] = [];
  const allEliteFindings: Finding[] = [];

  for (const url of allowed) {
    const host = extractHost(url);

    // Phase 1 — Static stages (no network, always fast)
    const staticFindings: Finding[] = [
      ...runHeadersStage(url).findings,
      ...runAuthStage(url).findings,
      ...runInjectionStage(url).findings,
      ...runCorsStage(url).findings,
    ];
    allStaticFindings.push(...staticFindings);

    // Phase 2 — Live HTTP probe
    const liveFindings = await probeAndAnalyse(url, { timeoutMs }).catch(() => []);
    allLiveFindings.push(...liveFindings);

    // Phase 3 — Auth/CORS session probe
    const authResult = await probeAuthSession(url, { timeoutMs }).catch(() => ({
      findings: [],
      errors: [],
    }));
    allLiveFindings.push(...authResult.findings);

    // Phase 4 — Differential injection probe
    const diffResult = await runDifferentialProbe(url, { timeoutMs }).catch(() => ({
      findings: [],
    }));
    allDiffFindings.push(...diffResult.findings);
  }

  // Apply elite engine to all collected findings
  const preElite = [
    ...allStaticFindings,
    ...allLiveFindings,
    ...allDiffFindings,
  ];
  const eliteFindings = runEliteEngine(preElite);
  allEliteFindings.push(
    ...eliteFindings.filter(ef =>
      !preElite.some(pf => pf.id === ef.id && pf.severity === ef.severity)
    )
  );

  // Merge and deduplicate
  const allFindings = uniqueById([...eliteFindings, ...allEliteFindings]);

  // Hybrid chain correlation
  const chains = hybridChains(allFindings);
  const chainIds = chains.map(c => c.id);

  // Build output sections
  const topRank = buildTopExploitabilityRank(allFindings);
  const compliance = buildComplianceResults(allFindings);
  const summary = buildSummary(allFindings, chains);

  // Build per-host agent outputs
  const hostSet = new Set(allowed.map(extractHost).filter(Boolean));
  const agents = [...hostSet].flatMap(host =>
    buildAgentOutputs({
      staticFindings: allStaticFindings.filter(f => f.host === host),
      liveFindings: allLiveFindings.filter(f => f.host === host),
      diffFindings: allDiffFindings.filter(f => f.host === host),
      eliteFindings: allEliteFindings.filter(f => f.host === host),
      host,
      chainIds: chains.filter(c => c.host === host).map(c => c.id),
    })
  );

  return {
    scanId: generateScanId(),
    timestamp: new Date().toISOString(),
    version: '0.2.0',
    target: {
      hosts: allowedHosts,
      urls: allowed,
    },
    summary,
    findings: allFindings,
    hybridChains: chains,
    topExploitabilityRank: topRank,
    agents,
    compliance,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function extractHost(urlStr: string): string {
  try {
    return new URL(urlStr).hostname;
  } catch {
    return '';
  }
}
