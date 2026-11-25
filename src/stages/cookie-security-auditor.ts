import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const COOKIE_SECURITY_RULES: LineAuditRule[] = [
  {
    id: "MANINY-COK-001",
    severity: "medium",
    category: "code-pattern",
    title: "Cookie configuration lacks visible HttpOnly, Secure, or SameSite protection flags",
    regex: /\b(setCookie|serializeCookie|cookieOptions)\s*\([^\r\n)]*(?![^\r\n]*(httpOnly|secure|sameSite))/i,
    description: "Set HttpOnly, Secure, and SameSite flags on sensitive cookies to reduce XSS and cross-site exposure.",
  },
  {
    id: "MANINY-COK-002",
    severity: "low",
    category: "code-pattern",
    title: "Cookie HttpOnly or Secure safeguard explicitly disabled on line",
    regex: /\b(httpOnly|secure)\b[^\r\n;,)]*[:=]\s*false/i,
    description: "Keep HttpOnly and Secure enabled on session and authentication cookies.",
  },
];

export async function runCookieSecurityAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, COOKIE_SECURITY_RULES);
}
