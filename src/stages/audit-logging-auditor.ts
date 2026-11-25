import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const AUDIT_LOGGING_RULES: LineAuditRule[] = [
  {
    id: "MANINY-LOG-001",
    severity: "low",
    category: "code-pattern",
    title: "Security or audit log invocation lacks visible actor, request, or correlation context",
    regex: /\b(auditLog|recordSecurityEvent|logAudit)\s*\([^\r\n)]*(?![^\r\n]*(actor|userId|requestId|correlationId|ip))/i,
    description: "Include actor, correlation, and contextual identifiers in security and audit logs for traceability.",
  },
  {
    id: "MANINY-LOG-002",
    severity: "medium",
    category: "code-pattern",
    title: "Audit or security logging explicitly suppressed or disabled on line",
    regex: /\b(disableAuditLog|skipAuditLog|auditLoggingEnabled)\b[^\r\n;,)]*[:=]\s*(true|false)/i,
    description: "Keep audit logging enabled on security-sensitive actions to preserve forensic visibility.",
  },
];

export async function runAuditLoggingAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, AUDIT_LOGGING_RULES);
}
