import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const SCIM_PROVISIONING_RULES: LineAuditRule[] = [
  {
    id: "MANINY-SCM-001",
    severity: "high",
    category: "code-pattern",
    title: "SCIM provisioning or group patch lacks visible bearer token, scope, or tenant boundary guard",
    regex: /\b(provisionScimUser|patchScimGroup|validateScimBearerToken)\s*\([^\r\n)]*(\b(scimPayload|groupPatch|bearerToken|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(verifyScimToken|enforceScimScope|validateTenantBoundary|auditScimEvent))/i,
    description: "Verify SCIM bearer tokens, enforce provisioning scopes, validate tenant boundaries, and record SCIM changes.",
  },
  {
    id: "MANINY-SCM-002",
    severity: "medium",
    category: "code-pattern",
    title: "SCIM token or tenant isolation check explicitly bypassed",
    regex: /\b(skipScimAuth|disableTenantIsolation)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep SCIM authentication and tenant isolation checks active.",
  },
];

export async function runScimProvisioningAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, SCIM_PROVISIONING_RULES);
}
