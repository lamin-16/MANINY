import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const SESSION_REVOCATION_RULES: LineAuditRule[] = [
  {
    id: "MANINY-RVK-001",
    severity: "high",
    category: "code-pattern",
    title: "Session revocation or refresh token rotation lacks ownership, token family, or audit check",
    regex: /\b(revokeUserSessions|rotateRefreshToken|invalidateSessionToken)\s*\([^\r\n)]*(\b(sessionId|refreshToken|userId|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(verifySessionOwner|recordRevocationEvent|markTokenRevoked|enforceTokenFamily))/i,
    description: "Verify session ownership, enforce refresh token family rotation, mark tokens revoked, and audit revocation actions.",
  },
  {
    id: "MANINY-RVK-002",
    severity: "medium",
    category: "code-pattern",
    title: "Session revocation or token rotation check explicitly bypassed",
    regex: /\b(skipSessionRevocation|disableTokenRotation)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep session revocation and refresh token rotation active to contain compromised sessions.",
  },
];

export async function runSessionRevocationAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, SESSION_REVOCATION_RULES);
}
