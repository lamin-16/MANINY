import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const QUOTA_GOVERNANCE_RULES: LineAuditRule[] = [
  {
    id: "MANINY-QTA-001",
    severity: "medium",
    category: "code-pattern",
    title: "Quota or resource allocation lacks visible cap, tenant isolation, or validation check",
    regex: /\b(allocateTenantQuota|enforceResourceLimit|checkStorageCap)\s*\([^\r\n)]*(\b(tenantId|requestedBytes|quotaLimit|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(maxQuota|tenantIsolation|enforceCap|validateQuota))/i,
    description: "Enforce per-tenant resource caps, validate requested sizes, and isolate quota accounting across tenants.",
  },
  {
    id: "MANINY-QTA-002",
    severity: "low",
    category: "code-pattern",
    title: "Resource quota or storage cap check explicitly bypassed",
    regex: /\b(skipQuotaEnforcement|allowUnboundedResource)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep resource quota enforcement active to prevent noisy-neighbor exhaustion.",
  },
];

export async function runQuotaGovernanceAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, QUOTA_GOVERNANCE_RULES);
}
