import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const SENSITIVE_DATA_RULES: LineAuditRule[] = [
  {
    id: "MANINY-SEN-001",
    severity: "high",
    category: "code-pattern",
    title: "Sensitive credential or personal field logged or serialized without visible masking",
    regex: /\b(console\.log|console\.info|console\.warn|dumpPayload|logUser)\s*\([^\r\n)]*\b(password|secret|privateKey|creditCard|ssn)\b[^\r\n)]*(?![^\r\n]*(redact|mask|sanitize|hash))/i,
    description: "Redact or omit sensitive credentials and personal identifiers before logging or serializing payloads.",
  },
  {
    id: "MANINY-SEN-002",
    severity: "medium",
    category: "code-pattern",
    title: "Sensitive field redaction or data masking explicitly bypassed on line",
    regex: /\b(skipRedaction|disableMasking|exposeSecrets)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep sensitive field redaction and masking enabled across logs and diagnostic outputs.",
  },
];

export async function runSensitiveDataAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, SENSITIVE_DATA_RULES);
}
