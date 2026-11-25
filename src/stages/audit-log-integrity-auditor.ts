import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const AUDIT_LOG_INTEGRITY_RULES: LineAuditRule[] = [
  {
    id: "MANINY-ALG-001",
    severity: "medium",
    category: "code-pattern",
    title: "Audit log write or export lacks visible signing, hash chaining, PII redaction, or integrity check",
    regex: /\b(appendAuditEntry|sealAuditChain|exportComplianceLog)\s*\([^\r\n)]*(\b(entry|event|logBatch|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(signAuditRecord|hashChainPrev|redactPiiFields|verifyLogIntegrity))/i,
    description: "Sign or hash-chain audit records to detect tampering, redact sensitive PII, and verify log integrity.",
  },
  {
    id: "MANINY-ALG-002",
    severity: "low",
    category: "code-pattern",
    title: "Audit log integrity or PII redaction explicitly disabled",
    regex: /\b(disableAuditSigning|skipAuditPiiRedaction)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep audit log integrity signing and sensitive field redaction active.",
  },
];

export async function runAuditLogIntegrityAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, AUDIT_LOG_INTEGRITY_RULES);
}
