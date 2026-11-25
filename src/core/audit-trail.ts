import crypto from "node:crypto";
import { Finding } from "./types.js";

export interface ExecutionAuditRecord {
  auditId: string;
  integritySha256: string;
  findingsCount: number;
  verifiedCount: number;
  fixedCount: number;
  rolledBackCount: number;
  generatedAt: string;
}

export function buildExecutionAudit(findings: Finding[]): ExecutionAuditRecord {
  const canonicalPayload = JSON.stringify(
    findings.map((f) => ({
      id: f.id,
      ruleId: f.ruleId,
      severity: f.severity,
      status: f.status,
      filePath: f.filePath ?? "",
      line: f.line ?? 0,
      targetUrl: f.targetUrl ?? "",
      evidenceCount: f.evidence.length,
      fixId: f.fix?.fixId ?? "",
    }))
  );

  const digest = crypto.createHash("sha256").update(canonicalPayload).digest("hex");

  return {
    auditId: `ARTEX-AUD-${digest.slice(0, 12).toUpperCase()}`,
    integritySha256: digest,
    findingsCount: findings.length,
    verifiedCount: findings.filter(
      (f) => f.status === "verified_exploitable" || f.status === "verified_fixed"
    ).length,
    fixedCount: findings.filter((f) => f.status === "patched" || f.status === "verified_fixed")
      .length,
    rolledBackCount: findings.filter((f) => f.status === "rolled_back").length,
    generatedAt: new Date().toISOString(),
  };
}
