import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const SECRET_ROTATION_RULES: LineAuditRule[] = [
  {
    id: "MANINY-SEC-001",
    severity: "high",
    category: "code-pattern",
    title: "Secret or credential provisioning lacks visible rotation, expiry, or vault guard",
    regex: /\b(rotateSecret|provisionApiKey|issueAccessKey)\s*\([^\r\n)]*(\b(plaintextKey|staticSecret|rawToken)\b|\$\{)[^\r\n)]*(?![^\r\n]*(rotateKey|verifyExpiration|vaultClient|expiresAt))/i,
    description: "Enforce key rotation, expiration bounds, and secure secret storage when provisioning or rotating credentials.",
  },
  {
    id: "MANINY-SEC-002",
    severity: "medium",
    category: "code-pattern",
    title: "Secret rotation or key expiration check explicitly disabled",
    regex: /\b(skipKeyRotation|disableSecretExpiry)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep secret rotation policies and credential expiration checks enabled.",
  },
];

export async function runSecretRotationAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, SECRET_ROTATION_RULES);
}
