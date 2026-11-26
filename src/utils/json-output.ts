// MANINY DIGITAL — JSON output formatting for CLI modes.

import type {
  AttackReport,
  Finding,
  HybridChain,
  ReportSummary,
} from '../types.js';

/**
 * Write structured JSON to stdout with 2-space indentation.
 * All runtime errors go to stderr; stdout stays machine-parseable.
 */
export function printJson(value: unknown): void {
  process.stdout.write(JSON.stringify(value, null, 2) + '\n');
}

/** Write a warning message to stderr (never pollutes stdout JSON). */
export function warn(message: string): void {
  process.stderr.write(`[MANINY WARN] ${message}\n`);
}

/** Write an error message to stderr. */
export function errorOut(message: string): void {
  process.stderr.write(`[MANINY ERROR] ${message}\n`);
}

// ---------------------------------------------------------------------------
// Per-mode output selectors
// ---------------------------------------------------------------------------

/** Full --attack-report JSON: every field included. */
export function formatAttackReport(report: AttackReport): AttackReport {
  return report;
}

/** --top-exploitability-rank: sorted findings list only. */
export function formatTopRank(findings: Finding[]): Finding[] {
  return [...findings]
    .filter(f => f.status === 'verified_exploitable')
    .sort((a, b) => b.exploitability - a.exploitability)
    .slice(0, 20);
}

/** --elite-matrix: hybrid chains with reproduction steps. */
export function formatEliteMatrix(chains: HybridChain[]): HybridChain[] {
  return [...chains].sort((a, b) => b.score - a.score);
}

/** Default CLI output: compact summary + findings + chains. */
export interface DefaultOutput {
  scanId: string;
  timestamp: string;
  version: string;
  target: AttackReport['target'];
  summary: ReportSummary;
  findings: Finding[];
  hybridChains: HybridChain[];
}

export function formatDefault(report: AttackReport): DefaultOutput {
  return {
    scanId: report.scanId,
    timestamp: report.timestamp,
    version: report.version,
    target: report.target,
    summary: report.summary,
    findings: report.findings,
    hybridChains: report.hybridChains,
  };
}
