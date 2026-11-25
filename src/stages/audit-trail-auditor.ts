import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const AUDIT_TRAIL_RULES: LineAuditRule[] = [
  {
    id: "MANINY-AUD-001",
    severity: "medium",
    category: "code-pattern",
    title: "Audit log entry lacks visible actor, timestamp, or integrity context",
    regex: /\b(recordAuditEvent|writeAuditLog|appendAuditTrail)\s*\([^\r\n)]*(\b(action|event|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(actorId|userId|timestamp|verifyAuditIntegrity))/i,
    description: "Include actor identity, timestamp, and integrity context when recording security and operational audit events.",
  },
  {
    id: "MANINY-AUD-002",
    severity: "high",
    category: "code-pattern",
    title: "Audit logging or tamper protection explicitly disabled",
    regex: /\b(disableAuditLog|skipAuditTrail|allowAuditDeletion)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep security audit logging enabled and protect audit trails against unauthorized modification or deletion.",
  },
];

export async function runAuditTrailAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, AUDIT_TRAIL_RULES);
}
