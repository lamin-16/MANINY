// MANINY DIGITAL — Shared type definitions.

// ---------------------------------------------------------------------------
// Primitive enumerations
// ---------------------------------------------------------------------------

export type Severity       = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FindingStatus  = 'verified_exploitable' | 'potential' | 'info';
export type FindingSource  = 'static' | 'live' | 'differential' | 'elite';
export type ChainType      = 'cors_to_csrf' | 'inject_to_rce' | 'auth_bypass_to_data' | 'mixed';
export type ComplianceStatus = 'pass' | 'fail' | 'partial';
export type SqliMethod     = 'error_based' | 'boolean_based' | 'time_based';

// ---------------------------------------------------------------------------
// Core finding model
// ---------------------------------------------------------------------------

export interface Finding {
  id:                string;
  host:              string;
  path:              string;
  url:               string;
  severity:          Severity;
  category:          string;
  title:             string;
  description:       string;
  evidence:          string;
  status:            FindingStatus;
  exploitability:    number;        // 0–100
  reproductionSteps: string[];
  remediationHint:   string;
  source:            FindingSource;
  timestamp:         string;
}

// ---------------------------------------------------------------------------
// Tech fingerprint
// ---------------------------------------------------------------------------

export interface TechEntry {
  name:     string;
  category: 'server' | 'framework' | 'language' | 'waf' | 'cdn';
  version?: string;
}

export interface TechFingerprint {
  host:        string;
  techs:       TechEntry[];
  wafDetected: boolean;
}

// ---------------------------------------------------------------------------
// Hybrid chain model
// ---------------------------------------------------------------------------

export interface HybridChain {
  id:               string;
  host:             string;
  title:            string;
  chainType:        ChainType;
  score:            number;   // 0–100 weighted
  findings:         Finding[];
  reproductionSteps: string[];
  impact:           string;
  timestamp:        string;
}

// ---------------------------------------------------------------------------
// Multi-agent output
// ---------------------------------------------------------------------------

export interface AgentOutput {
  agentId:   string;
  role:      string;
  host:      string;
  findings:  Finding[];
  chainIds:  string[];
  timestamp: string;
}

// ---------------------------------------------------------------------------
// Compliance mapping
// ---------------------------------------------------------------------------

export interface ComplianceResult {
  framework:          string;
  control:            string;
  status:             ComplianceStatus;
  relatedFindingIds:  string[];
}

// ---------------------------------------------------------------------------
// Top-level attack report
// ---------------------------------------------------------------------------

export interface ReportSummary {
  total:    number;
  critical: number;
  high:     number;
  medium:   number;
  low:      number;
  info:     number;
  verified: number;
  chains:   number;
}

export interface AttackReport {
  scanId:    string;
  timestamp: string;
  version:   string;
  target: {
    hosts: string[];
    urls:  string[];
  };
  summary:               ReportSummary;
  findings:              Finding[];
  hybridChains:          HybridChain[];
  topExploitabilityRank: Finding[];
  agents:                AgentOutput[];
  compliance:            ComplianceResult[];
  techFingerprints:      TechFingerprint[];
}

// ---------------------------------------------------------------------------
// Session configuration (from --cookie / --bearer-token / --header flags)
// ---------------------------------------------------------------------------

export interface SessionConfig {
  cookies:       Record<string, string>;
  bearerToken?:  string;
  customHeaders: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Scan configuration (from CLI args)
// ---------------------------------------------------------------------------

export interface ScanConfig {
  allowedHosts:  string[];
  targetUrls:    string[];
  timeoutMs:     number;
  topRank:       boolean;
  attackReport:  boolean;
  eliteMatrix:   boolean;
  session:       SessionConfig;
  rateLimitMs:   number;
  concurrency:   number;
  fromHttpxPipe:  boolean;
  checkSsrf:      boolean;
  checkTakeover:  boolean;
}

// ---------------------------------------------------------------------------
// Internal data-transfer types
// ---------------------------------------------------------------------------

export interface StageResult {
  findings: Finding[];
  errors:   string[];
}

export interface HttpResponse {
  status:        number;
  headers:       Record<string, string | string[] | undefined>;
  body:          string;
  responseTimeMs: number;
  error?:        string;
}

export interface LiveProbeResult {
  url:          string;
  host:         string;
  httpResponse: HttpResponse;
}

export interface DifferentialResult {
  url:                 string;
  baselineStatus:      number;
  probeStatus:         number;
  statusDelta:         number;
  baselineBodyLength:  number;
  probeBodyLength:     number;
  bodyLengthDelta:     number;
  reflected:           boolean;
  redirected:          boolean;
  findings:            Finding[];
}

export interface HttpxInput {
  url:          string;
  'status-code'?: number;
  headers?:     Record<string, string>;
  tech?:        string[];
}
