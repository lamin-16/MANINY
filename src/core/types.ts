export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type Category =
  | "code-pattern"
  | "secret-exposure"
  | "http-hardening"
  | "dependency";

export type FindingStatus =
  | "detected"
  | "verified_exploitable"
  | "needs_review"
  | "patched"
  | "verified_fixed"
  | "rolled_back";

export type RunMode = "detect" | "verify" | "fix" | "review" | "pipeline";

export type ReportFormat = "json" | "sarif" | "both";

export interface EvidenceRecord {
  stage: "verify" | "review";
  probeType: "static-proof" | "safe-http-check" | "remediation-check";
  target: string;
  confirmed: boolean;
  message: string;
  timestamp: string;
}

export interface FixArtifact {
  fixId: string;
  ruleId: string;
  filePath: string;
  backupContent: string;
  unifiedDiff: string;
  appliedAt: string;
  rolledBackAt?: string;
}

export interface Finding {
  id: string;
  ruleId: string;
  title: string;
  category: Category;
  severity: Severity;
  filePath?: string;
  line?: number;
  targetUrl?: string;
  description: string;
  status: FindingStatus;
  evidence: EvidenceRecord[];
  fix?: FixArtifact;
}

export interface ManinyPolicy {
  workspaceRoot: string;
  allowedTargetHosts: string[];
  allowSafeOffensiveProbes: boolean;
  allowAutoFix: boolean;
  maxAutoFixSeverity: Exclude<Severity, "info">;
  blockedPathSubstrings: string[];
}

export interface SecurityRuleDefinition {
  ruleId: string;
  title: string;
  category: Category;
  severity: Severity;
  description: string;
  detectLine: (line: string) => boolean;
  verifyLine?: (line: string) => boolean;
  fixLine?: (line: string) => { changed: boolean; nextLine: string };
}

export interface PipelineReport {
  tool: "MANINY";
  version: string;
  mode: RunMode;
  workspaceRoot: string;
  generatedAt: string;
  summary: {
    total: number;
    detected: number;
    verifiedExploitable: number;
    needsReview: number;
    patched: number;
    verifiedFixed: number;
    rolledBack: number;
  };
  findings: Finding[];
}
