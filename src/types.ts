// MANINY DIGITAL — Shared type definitions
// All identifiers, comments, and documentation: English only.

// ---------------------------------------------------------------------------
// Primitive enumerations
// ---------------------------------------------------------------------------

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type FindingStatus =
  | 'verified_exploitable'
  | 'potential'
  | 'info';

export type FindingSource =
  | 'static'
  | 'live'
  | 'differential'
  | 'elite';

export type ChainType =
  | 'cors_to_csrf'
  | 'inject_to_rce'
  | 'auth_bypass_to_data'
  | 'mixed';

export type ComplianceStatus = 'pass' | 'fail' | 'partial';

// ---------------------------------------------------------------------------
// Core finding model
// ---------------------------------------------------------------------------

export interface Finding {
  /** Deterministic SHA-style ID derived from host + path + category + title. */
  id: string;
  host: string;
  path: string;
  url: string;
  severity: Severity;
  /** Lowercase, snake_case category label: cors, auth, injection, headers, etc. */
  category: string;
  title: string;
  description: string;
  /** Raw response fragment or observed deviation used as evidence. */
  evidence: string;
  status: FindingStatus;
  /** Weighted exploitability score 0–100. */
  exploitability: number;
  reproductionSteps: string[];
  remediationHint: string;
  source: FindingSource;
  timestamp: string;
}

// ---------------------------------------------------------------------------
// Hybrid chain model
// ---------------------------------------------------------------------------

export interface HybridChain {
  id: string;
  host: string;
  title: string;
  chainType: ChainType;
  /** Weighted score 0–100 (not a simple sum of finding scores). */
  score: number;
  findings: Finding[];
  reproductionSteps: string[];
  impact: string;
  timestamp: string;
}

// ---------------------------------------------------------------------------
// Multi-agent output
// ---------------------------------------------------------------------------

export interface AgentOutput {
  agentId: string;
  role: string;
  host: string;
  findings: Finding[];
  chainIds: string[];
  timestamp: string;
}

// ---------------------------------------------------------------------------
// Compliance mapping
// ---------------------------------------------------------------------------

export interface ComplianceResult {
  framework: string;
  control: string;
  status: ComplianceStatus;
  /** IDs of findings that caused a 'fail' or 'partial' status. */
  relatedFindingIds: string[];
}

// ---------------------------------------------------------------------------
// Top-level attack report
// ---------------------------------------------------------------------------

export interface ReportSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  verified: number;
  chains: number;
}

export interface AttackReport {
  scanId: string;
  timestamp: string;
  version: string;
  target: {
    hosts: string[];
    urls: string[];
  };
  summary: ReportSummary;
  findings: Finding[];
  hybridChains: HybridChain[];
  topExploitabilityRank: Finding[];
  agents: AgentOutput[];
  compliance: ComplianceResult[];
}

// ---------------------------------------------------------------------------
// Scan configuration (from CLI args)
// ---------------------------------------------------------------------------

export interface ScanConfig {
  allowedHosts: string[];
  targetUrls: string[];
  timeoutMs: number;
  topRank: boolean;
  attackReport: boolean;
  eliteMatrix: boolean;
}

// ---------------------------------------------------------------------------
// Internal data-transfer types
// ---------------------------------------------------------------------------

export interface StageResult {
  findings: Finding[];
  errors: string[];
}

export interface HttpResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  responseTimeMs: number;
  error?: string;
}

export interface LiveProbeResult {
  url: string;
  host: string;
  httpResponse: HttpResponse;
}

export interface DifferentialResult {
  url: string;
  baselineStatus: number;
  probeStatus: number;
  statusDelta: number;
  baselineBodyLength: number;
  probeBodyLength: number;
  bodyLengthDelta: number;
  reflected: boolean;
  redirected: boolean;
  findings: Finding[];
}
