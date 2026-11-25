import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const ENV_CONFIG_RULES: LineAuditRule[] = [
  {
    id: "MANINY-ENV-001",
    severity: "high",
    category: "code-pattern",
    title: "Secret or credential environment lookup falls back to hardcoded literal string",
    regex: /process\.env\.[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY)[A-Z0-9_]*\s*\|\|\s*['"`][^'"`\n]+['"`]/,
    description: "Avoid hardcoded fallback literals for sensitive environment credentials; fail explicitly when secrets are missing.",
  },
  {
    id: "MANINY-ENV-002",
    severity: "medium",
    category: "code-pattern",
    title: "Debug or verbose security mode enabled via environment flag",
    regex: /\b(DEBUG|INSECURE_MODE|ALLOW_INSECURE)\b[^\r\n;,=]*[:=]\s*['"]?(true|1|\*)['"]?/i,
    description: "Ensure verbose debug and insecure compatibility toggles are disabled in production configurations.",
  },
];

export async function runEnvConfigAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, ENV_CONFIG_RULES);
}
