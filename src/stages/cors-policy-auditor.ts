import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const CORS_POLICY_RULES: LineAuditRule[] = [
  {
    id: "MANINY-COR-001",
    severity: "medium",
    category: "code-pattern",
    title: "CORS configuration reflects dynamic request origin or wildcard without visible allowlist check",
    regex: /\b(configureCors|corsOptions|setCorsHeaders)\b[^\r\n;{)]*(req\.headers\.origin|origin\s*:\s*true|\*\s*)[^\r\n;{)]*(?![^\r\n]*(allowedOrigins|trustedOrigins|isAllowedOrigin|originAllowlist))/i,
    description: "Validate incoming request origins against an explicit allowlist before granting cross-origin access.",
  },
  {
    id: "MANINY-COR-002",
    severity: "low",
    category: "code-pattern",
    title: "CORS credentialed access paired with overly broad origin configuration",
    regex: /\b(credentials\s*:\s*true|Access-Control-Allow-Credentials\s*[:=]\s*['"]?true['"]?)[^\r\n;,)]*(\*|req\.headers\.origin)/i,
    description: "Avoid combining credentialed cross-origin requests with wildcard or unvalidated reflected origins.",
  },
];

export async function runCorsPolicyAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, CORS_POLICY_RULES);
}
