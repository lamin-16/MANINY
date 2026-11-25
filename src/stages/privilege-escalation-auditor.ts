import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const PRIVILEGE_ESCALATION_RULES: LineAuditRule[] = [
  {
    id: "MANINY-PRV-001",
    severity: "high",
    category: "code-pattern",
    title: "Privilege grant or role escalation lacks visible grantor authority, role ceiling, or audit trail",
    regex: /\b(grantPrivilegedRole|escalateUserPermissions|assignAdminScope)\s*\([^\r\n)]*(\b(role|permissions|targetUserId|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(verifyGrantorAuthority|enforceRoleCeiling|requireApprovalTrail|auditPrivilegeChange))/i,
    description: "Verify grantor authority, enforce privilege ceilings, require approval trails, and audit role elevations.",
  },
  {
    id: "MANINY-PRV-002",
    severity: "medium",
    category: "code-pattern",
    title: "Role ceiling or grantor authority check explicitly bypassed",
    regex: /\b(skipRoleCeiling|bypassGrantorCheck)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep privilege boundary and grantor authority checks active.",
  },
];

export async function runPrivilegeEscalationAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, PRIVILEGE_ESCALATION_RULES);
}
