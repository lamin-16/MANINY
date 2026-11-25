import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const RATE_LIMIT_RULES: LineAuditRule[] = [
  {
    id: "MANINY-RLM-001",
    severity: "medium",
    category: "code-pattern",
    title: "Authentication or credential flow lacks visible rate limit or request cap on line",
    regex: /\b(loginUser|resetPassword|requestOtp|handleAuth)\b[^\r\n;{)]*(?![^\r\n]*(rateLimit|windowMs|maxRequests|throttle|backoff))/i,
    description: "Apply rate limiting and request throttling on authentication, password reset, and OTP endpoints.",
  },
  {
    id: "MANINY-RLM-002",
    severity: "low",
    category: "code-pattern",
    title: "Rate limiting explicitly disabled or bypassed on line",
    regex: /\b(rateLimitEnabled|skipRateLimit|disableRateLimit)\b[^\r\n;,)]*[:=]\s*(false|true)/i,
    description: "Keep rate limiting active to mitigate brute-force and credential-stuffing traffic.",
  },
];

export async function runRateLimitAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, RATE_LIMIT_RULES);
}
