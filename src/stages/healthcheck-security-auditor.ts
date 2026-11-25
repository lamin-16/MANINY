import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const HEALTHCHECK_SECURITY_RULES: LineAuditRule[] = [
  {
    id: "MANINY-HLT-001",
    severity: "medium",
    category: "code-pattern",
    title: "Health or readiness handler exposes environment variables or internal config details",
    regex: /\b(healthCheck|readinessHandler|statusEndpoint)\b[^\r\n;{)]*(process\.env|databaseUrl|connectionString|secretKey)[^\r\n;{)]*(?![^\r\n]*(redact|sanitize|minimal))/i,
    description: "Keep public health and readiness responses minimal and avoid leaking environment variables or connection strings.",
  },
  {
    id: "MANINY-HLT-002",
    severity: "low",
    category: "code-pattern",
    title: "Diagnostic or health endpoint explicitly skips authentication or access guard",
    regex: /\b(skipHealthAuth|publicDiagnostics)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Restrict verbose diagnostic and internal status endpoints behind authentication or internal network controls.",
  },
];

export async function runHealthcheckSecurityAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, HEALTHCHECK_SECURITY_RULES);
}
