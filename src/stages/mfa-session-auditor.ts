import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const MFA_SESSION_RULES: LineAuditRule[] = [
  {
    id: "MANINY-MFA-001",
    severity: "high",
    category: "code-pattern",
    title: "OTP or MFA verification handler lacks visible rate limit, expiry, or attempt cap",
    regex: /\b(verifyOtp|verifyMfaCode|checkChallenge)\b[^\r\n;{)]*(?![^\r\n]*(maxAttempts|expiresAt|rateLimit|attempts))/i,
    description: "Enforce attempt limits, expiration windows, and rate limiting on OTP and MFA verification flows.",
  },
  {
    id: "MANINY-MFA-002",
    severity: "medium",
    category: "code-pattern",
    title: "Logout or session termination flow lacks visible session revocation or cookie clear",
    regex: /\b(logoutUser|destroySession|revokeToken)\b[^\r\n;{)]*(?![^\r\n]*(clearCookie|invalidate|revoke|deleteSession))/i,
    description: "Revoke server-side sessions and clear authentication cookies completely on sign-out.",
  },
];

export async function runMfaSessionAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, MFA_SESSION_RULES);
}
