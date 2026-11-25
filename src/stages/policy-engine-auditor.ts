import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const POLICY_ENGINE_RULES: LineAuditRule[] = [
  {
    id: "MANINY-POL-001",
    severity: "high",
    category: "code-pattern",
    title: "Policy evaluation or permission check uses wildcard or permissive default without visible guard",
    regex: /\b(evaluatePolicy|checkPermissionPolicy|authorizeAction)\b[^\r\n;{)]*(\*|\b(allowAll|skipPolicyCheck|adminOverride)\b)[^\r\n;{)]*(?![^\r\n]*(denyByDefault|enforcePolicy|validateSubject))/i,
    description: "Enforce default-deny authorization policies and explicit subject/resource checks in policy evaluation logic.",
  },
  {
    id: "MANINY-POL-002",
    severity: "medium",
    category: "code-pattern",
    title: "Policy enforcement or authorization guard explicitly bypassed in configuration",
    regex: /\b(disablePolicyEnforcement|bypassAccessPolicy)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep access policy enforcement active to prevent unauthorized actions or privilege escalation.",
  },
];

export async function runPolicyEngineAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, POLICY_ENGINE_RULES);
}
