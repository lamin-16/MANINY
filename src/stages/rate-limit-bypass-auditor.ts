import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const RATE_LIMIT_BYPASS_RULES: LineAuditRule[] = [
  {
    id: "MANINY-RLB-001",
    severity: "high",
    category: "code-pattern",
    title: "Rate limiter relies on spoofable client key or lacks visible quota enforcement",
    regex: /\b(applyRateLimit|checkRequestQuota|resolveClientThrottleKey)\s*\([^\r\n)]*(\b(x-forwarded-for|clientIp|req\.headers)\b|\$\{)[^\r\n)]*(?![^\r\n]*(deriveClientIdentity|trustedProxy|enforceQuota|maxRequests))/i,
    description: "Derive throttle keys from trusted identity or verified proxy context and enforce explicit request quotas.",
  },
  {
    id: "MANINY-RLB-002",
    severity: "medium",
    category: "code-pattern",
    title: "Rate limiting or quota check explicitly bypassed",
    regex: /\b(skipRateLimit|disableThrottle)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep rate limiting enabled on authentication, billing, and write endpoints.",
  },
];

export async function runRateLimitBypassAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, RATE_LIMIT_BYPASS_RULES);
}
