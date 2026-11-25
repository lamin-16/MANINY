import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const KMS_KEY_MANAGEMENT_RULES: LineAuditRule[] = [
  {
    id: "MANINY-KMS-001",
    severity: "high",
    category: "code-pattern",
    title: "KMS key provisioning, unwrapping, or rotation lacks visible context, policy, or rotation guard",
    regex: /\b(provisionKmsKey|unwrapDataKey|scheduleKeyRotation)\s*\([^\r\n)]*(\b(keyArn|keyId|cipherBlob|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(encryptionContext|enforceKeyPolicy|requireMfaForKey|rotationDays))/i,
    description: "Bind data key operations to an encryption context, enforce least-privilege KMS policies, and schedule regular key rotation.",
  },
  {
    id: "MANINY-KMS-002",
    severity: "medium",
    category: "code-pattern",
    title: "KMS key policy or encryption context check explicitly bypassed",
    regex: /\b(skipKmsPolicyCheck|allowUnboundDataKey)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep KMS policy enforcement and authenticated encryption context checks enabled.",
  },
];

export async function runKmsKeyManagementAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, KMS_KEY_MANAGEMENT_RULES);
}
