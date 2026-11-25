import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const ACCESS_CONTROL_RULES: LineAuditRule[] = [
  {
    id: "MANINY-ACL-001",
    severity: "high",
    category: "code-pattern",
    title: "Privileged or admin route handler lacks visible role or permission guard on line",
    regex: /\b(deleteUser|assignRole|updatePermissions|adminAction)\b[^\r\n;{)]*(?![^\r\n]*(authorize|requireRole|permission|hasRole|allowlist))/i,
    description: "Enforce explicit role or permission authorization checks on privileged and administrative operations.",
  },
  {
    id: "MANINY-ACL-002",
    severity: "medium",
    category: "code-pattern",
    title: "Authorization or access check explicitly bypassed on line",
    regex: /\b(skipAuth|bypassAuth|allowAllRoles)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Never bypass authentication or role authorization checks in production code paths.",
  },
];

export async function runAccessControlAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, ACCESS_CONTROL_RULES);
}
