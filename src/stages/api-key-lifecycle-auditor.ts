import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const API_KEY_LIFECYCLE_RULES: LineAuditRule[] = [
  {
    id: "MANINY-AKL-001",
    severity: "high",
    category: "code-pattern",
    title: "API key issuance, rotation, or revocation lacks visible scope, expiration, hashing, or audit guard",
    regex: /\b(issueApiKey|rotateApiKeySecret|revokeApiKey)\s*\([^\r\n)]*(\b(keyId|scopes|secret|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(enforceKeyScopes|setKeyExpiration|hashApiKeySecret|auditKeyLifecycle))/i,
    description: "Enforce least-privilege scopes, set expiration timestamps, hash secrets at rest, and audit key lifecycle events.",
  },
  {
    id: "MANINY-AKL-002",
    severity: "medium",
    category: "code-pattern",
    title: "API key expiration or scope validation explicitly bypassed",
    regex: /\b(skipApiKeyExpiry|disableKeyScopes)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep API key expiration and scope checks enabled to limit blast radius.",
  },
];

export async function runApiKeyLifecycleAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, API_KEY_LIFECYCLE_RULES);
}
