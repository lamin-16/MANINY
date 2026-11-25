import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const PASSWORD_RECOVERY_RULES: LineAuditRule[] = [
  {
    id: "MANINY-PWD-001",
    severity: "high",
    category: "code-pattern",
    title: "Password reset or account recovery flow lacks visible token verification or single-use guard",
    regex: /\b(requestPasswordReset|verifyResetToken|completePasswordReset)\s*\([^\r\n)]*(\b(resetToken|req\.body|email)\b|\$\{)[^\r\n)]*(?![^\r\n]*(verifyResetToken|consumeResetToken|randomBytes|expiresAt))/i,
    description: "Use cryptographically random time-limited reset tokens and invalidate them immediately after use.",
  },
  {
    id: "MANINY-PWD-002",
    severity: "medium",
    category: "code-pattern",
    title: "Password reset token validation or expiration check explicitly bypassed",
    regex: /\b(skipResetTokenCheck|allowReusableResetToken)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep reset token expiration and single-use validation enabled during password recovery.",
  },
];

export async function runPasswordRecoveryAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, PASSWORD_RECOVERY_RULES);
}
