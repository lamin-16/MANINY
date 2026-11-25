import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const TENANT_ISOLATION_RULES: LineAuditRule[] = [
  {
    id: "MANINY-TNI-001",
    severity: "high",
    category: "code-pattern",
    title: "Multi-tenant operation lacks visible tenant context, RLS scope, or cross-tenant guard",
    regex: /\b(resolveTenantContext|scopeTenantQuery|assertSameTenant)\s*\([^\r\n)]*(\b(tenantId|orgId|workspaceId|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(verifyTenantMembership|enforceTenantScope|auditCrossTenantAccess|requireTenantId))/i,
    description: "Verify tenant membership, enforce tenant scoping on data queries, and audit cross-tenant access attempts.",
  },
  {
    id: "MANINY-TNI-002",
    severity: "medium",
    category: "code-pattern",
    title: "Tenant isolation or tenant scope check explicitly bypassed",
    regex: /\b(skipTenantScope|allowCrossTenantAccess)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep tenant isolation and query scoping enforced across multi-tenant boundaries.",
  },
];

export async function runTenantIsolationAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, TENANT_ISOLATION_RULES);
}
