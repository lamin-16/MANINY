import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const TOKEN_ENTROPY_RULES: LineAuditRule[] = [
  {
    id: "MANINY-ENT-001",
    severity: "high",
    category: "code-pattern",
    title: "Token, nonce, or session identifier relies on predictable or non-CSPRNG source",
    regex: /\b(generateToken|createSessionId|generateNonce|createResetToken)\b[^\r\n;{)]*(\bMath\.random\b|\bDate\.now\b)[^\r\n;{)]*(?![^\r\n]*(randomBytes|randomUUID|getRandomValues|csprng))/i,
    description: "Use cryptographically secure random generators such as crypto.randomBytes or crypto.randomUUID for security tokens.",
  },
  {
    id: "MANINY-ENT-002",
    severity: "low",
    category: "code-pattern",
    title: "Low-entropy or short static token prefix configured on line",
    regex: /\b(tokenLength|secretMinLength)\b[^\r\n;,)]*[:=]\s*([1-9]|1[0-5])\b/i,
    description: "Ensure security tokens and secrets use sufficient byte length and high entropy.",
  },
];

export async function runTokenEntropyAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, TOKEN_ENTROPY_RULES);
}
