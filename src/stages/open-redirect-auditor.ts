import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const OPEN_REDIRECT_RULES: LineAuditRule[] = [
  {
    id: "MANINY-RDR-001",
    severity: "medium",
    category: "code-pattern",
    title: "Redirect target accepts dynamic or external URL input without visible validation",
    regex: /\b(redirectTo|handleRedirect|resolveRedirectUrl)\s*\([^\r\n)]*(\b(req\.query|req\.body|returnTo|redirectUrl|nextUrl)\b|\$\{)[^\r\n)]*(?![^\r\n]*(allowlist|isRelative|safeRedirect|trustedOrigin))/i,
    description: "Validate redirect targets against relative paths or an explicit allowlist of trusted origins.",
  },
  {
    id: "MANINY-RDR-002",
    severity: "low",
    category: "code-pattern",
    title: "Open redirect validation explicitly bypassed or set to allow external hosts",
    regex: /\b(allowExternalRedirect|skipRedirectCheck)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep redirect target validation enabled to prevent open-redirect phishing flows.",
  },
];

export async function runOpenRedirectAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, OPEN_REDIRECT_RULES);
}
