import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const SESSION_STORAGE_RULES: LineAuditRule[] = [
  {
    id: "MANINY-STO-001",
    severity: "medium",
    category: "code-pattern",
    title: "Session or local cache write handles sensitive token or dynamic key without visible guard",
    regex: /\b(saveSessionState|writeLocalCache|persistClientStorage)\s*\([^\r\n)]*(\b(authToken|sessionSecret|storageKey)\b|\$\{)[^\r\n)]*(?![^\r\n]*(encryptStorage|sanitizeStorageKey|isAllowedStorageKey|redact))/i,
    description: "Avoid storing raw auth secrets in unencrypted client/local storage and validate dynamic storage keys.",
  },
  {
    id: "MANINY-STO-002",
    severity: "low",
    category: "code-pattern",
    title: "Storage encryption or key validation guard explicitly bypassed",
    regex: /\b(skipStorageEncryption|allowUnsafeStorageKey)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep storage encryption and key validation guards enabled for session and cache state.",
  },
];

export async function runSessionStorageAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, SESSION_STORAGE_RULES);
}
