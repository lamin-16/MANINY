import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const CSRF_PROTECTION_RULES: LineAuditRule[] = [
  {
    id: "MANINY-CRF-001",
    severity: "medium",
    category: "code-pattern",
    title: "State-changing handler lacks visible CSRF token or origin guard on line",
    regex: /\b(handlePost|handlePut|handlePatch|handleDelete)\b[^\r\n;{)]*(?![^\r\n]*(csrf|xsrf|sameSite|originCheck|token))/i,
    description: "Protect state-changing endpoints with anti-CSRF tokens, origin validation, or SameSite cookie controls.",
  },
  {
    id: "MANINY-CRF-002",
    severity: "low",
    category: "code-pattern",
    title: "CSRF or SameSite protection explicitly weakened or disabled on line",
    regex: /\b(csrfProtection|sameSite)\b[^\r\n;,)]*[:=]\s*['"]?(false|none)['"]?/i,
    description: "Avoid disabling CSRF protection or setting permissive SameSite=None without strict cross-site safeguards.",
  },
];

export async function runCsrfProtectionAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, CSRF_PROTECTION_RULES);
}
