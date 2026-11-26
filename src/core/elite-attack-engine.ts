// MANINY DIGITAL — Elite attack verification engine.
// Upgrades confirmed findings, generates reproduction matrices, and applies
// chain-aware risk escalation.

import type { Finding, Severity } from '../types.js';
import { buildFinding } from '../stages/stage-utils.js';
import { generateFindingId } from '../utils/deduplicator.js';

// ---------------------------------------------------------------------------
// Risk method definitions
// ---------------------------------------------------------------------------

/** An elite risk method adds context and escalates verified findings. */
interface RiskMethod {
  id: string;
  appliesToCategories: string[];
  appliesToStatuses: Array<Finding['status']>;
  minExploitability: number;
  upgradeToSeverity: Severity | null;
  addReproductionSteps: string[];
  escalateby: number; // points added to exploitability
}

const RISK_METHODS: RiskMethod[] = [
  {
    id: 'elite-cors-chain',
    appliesToCategories: ['cors'],
    appliesToStatuses: ['verified_exploitable'],
    minExploitability: 70,
    upgradeToSeverity: 'critical',
    addReproductionSteps: [
      'Create a malicious page that makes a credentialed fetch to the target.',
      'Exfiltrate response data to an attacker-controlled server.',
      'Demonstrate reading authenticated API responses cross-origin.',
    ],
    escalateby: 10,
  },
  {
    id: 'elite-sql-exfil',
    appliesToCategories: ['injection'],
    appliesToStatuses: ['verified_exploitable'],
    minExploitability: 80,
    upgradeToSeverity: 'critical',
    addReproductionSteps: [
      "Enumerate database schema: ' UNION SELECT table_name,column_name FROM information_schema.columns--",
      "Exfiltrate data: ' UNION SELECT username,password FROM users LIMIT 10--",
      'Crack or use password hashes offline.',
    ],
    escalateby: 5,
  },
  {
    id: 'elite-auth-escalate',
    appliesToCategories: ['auth'],
    appliesToStatuses: ['verified_exploitable'],
    minExploitability: 60,
    upgradeToSeverity: 'critical',
    addReproductionSteps: [
      'Brute-force or token-predict the credential parameter.',
      'Replay captured credentials to access privileged endpoints.',
      'Enumerate user accounts via IDOR.',
    ],
    escalateby: 8,
  },
  {
    id: 'elite-header-chain',
    appliesToCategories: ['headers'],
    appliesToStatuses: ['potential', 'verified_exploitable'],
    minExploitability: 25,
    upgradeToSeverity: null, // no severity upgrade, just add steps
    addReproductionSteps: [
      'Combine missing HSTS with an XSS or injection finding for a chained attack.',
      'Demonstrate session theft via missing HttpOnly + XSS in the same response.',
    ],
    escalateby: 3,
  },
];

// ---------------------------------------------------------------------------
// Core engine functions
// ---------------------------------------------------------------------------

/**
 * Apply elite verification heuristics to a set of findings.
 * Returns new enriched Finding objects — originals are not mutated.
 */
export function runEliteEngine(findings: Finding[]): Finding[] {
  return findings.map(f => applyRiskMethods(f));
}

function applyRiskMethods(finding: Finding): Finding {
  const applicable = RISK_METHODS.filter(
    rm =>
      rm.appliesToCategories.includes(finding.category) &&
      rm.appliesToStatuses.includes(finding.status) &&
      finding.exploitability >= rm.minExploitability
  );

  if (applicable.length === 0) return finding;

  let { severity, exploitability, reproductionSteps } = finding;

  for (const rm of applicable) {
    if (rm.upgradeToSeverity !== null) {
      severity = higherSeverity(severity, rm.upgradeToSeverity);
    }
    exploitability = Math.min(100, exploitability + rm.escalateby);
    reproductionSteps = [
      ...reproductionSteps,
      ...rm.addReproductionSteps.filter(s => !reproductionSteps.includes(s)),
    ];
  }

  return {
    ...finding,
    severity,
    exploitability,
    reproductionSteps,
  };
}

/** Return the more severe of two severity values. */
function higherSeverity(a: Severity, b: Severity): Severity {
  const rank: Record<Severity, number> = {
    critical: 5, high: 4, medium: 3, low: 2, info: 1,
  };
  return (rank[a] ?? 0) >= (rank[b] ?? 0) ? a : b;
}

// ---------------------------------------------------------------------------
// Reproduction matrix generator
// ---------------------------------------------------------------------------

export interface ReproductionMatrix {
  findingId: string;
  title: string;
  severity: Severity;
  exploitability: number;
  steps: string[];
  remediationHint: string;
}

/**
 * Generate a step-by-step reproduction matrix for all verified findings.
 * Used by --elite-matrix flag output.
 */
export function buildReproductionMatrix(findings: Finding[]): ReproductionMatrix[] {
  return findings
    .filter(f => f.status === 'verified_exploitable')
    .sort((a, b) => b.exploitability - a.exploitability)
    .map(f => ({
      findingId: f.id,
      title: f.title,
      severity: f.severity,
      exploitability: f.exploitability,
      steps:
        f.reproductionSteps.length > 0
          ? f.reproductionSteps
          : [`Reproduce the condition described in finding '${f.title}'.`],
      remediationHint: f.remediationHint,
    }));
}
