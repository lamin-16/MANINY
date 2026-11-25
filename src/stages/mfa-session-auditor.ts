import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const MFA_SESSION_RULES: LineAuditRule[] = [
  {
    id: "MANINY-MFA-001",
    severity: "high",
    category: "code-pattern",
    title: "MFA verification or session revocation lacks visible OTP check, rate guard, or session invalidation",
    regex: /\b(verifyMfaCode|enrollMfaFactor|revokeSessionDevice)\s*\([^\r\n)]*(\b(otpToken|mfaCode|sessionId)\b|\$\{)[^\r\n)]*(?![^\r\n]*(verifyOtp|rateLimitMfa|revokeSession|invalidateSession))/i,
    description: "Verify one-time codes with rate limits during MFA checks and invalidate revoked sessions immediately.",
  },
  {
    id: "MANINY-MFA-002",
    severity: "medium",
    category: "code-pattern",
    title: "Multi-factor authentication or session invalidation check explicitly bypassed",
    regex: /\b(skipMfaChallenge|allowStaleSession)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep multi-factor verification and stale session revocation active for protected accounts.",
  },
];

export async function runMfaSessionAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, MFA_SESSION_RULES);
}
