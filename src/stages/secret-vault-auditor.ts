import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const SECRET_VAULT_RULES: LineAuditRule[] = [
  {
    id: "MANINY-VLT-001",
    severity: "high",
    category: "code-pattern",
    title: "Secret vault lease or rotation handler lacks visible TTL bound, identity check, or revocation",
    regex: /\b(leaseSecretCredential|rotateVaultSecret|revokeSecretLease)\s*\([^\r\n)]*(\b(secretPath|leaseId|requester|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(maxLeaseTtl|verifySecretIdentity|revokeLease|auditSecretAccess))/i,
    description: "Enforce bounded lease TTLs, verify caller identity, and revoke expired or compromised secret leases.",
  },
  {
    id: "MANINY-VLT-002",
    severity: "medium",
    category: "code-pattern",
    title: "Vault lease expiration or secret rotation check explicitly bypassed",
    regex: /\b(skipVaultLeaseExpiry|allowStaticVaultSecret)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep secret lease expiration and periodic credential rotation enabled.",
  },
];

export async function runSecretVaultAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, SECRET_VAULT_RULES);
}
