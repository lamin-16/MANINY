import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const REVERSE_PROXY_RULES: LineAuditRule[] = [
  {
    id: "MANINY-PRX-001",
    severity: "medium",
    category: "code-pattern",
    title: "Reverse proxy or forwarding handler lacks visible target validation or header sanitization",
    regex: /\b(configureProxy|forwardProxyRequest|resolveProxyTarget)\s*\([^\r\n)]*(\b(proxyTarget|targetUrl|x-forwarded-for)\b|\$\{)[^\r\n)]*(?![^\r\n]*(validateProxyTarget|allowedProxyTargets|sanitizeHeader|trustedProxies))/i,
    description: "Validate proxy destinations against an allowlist and sanitize forwarding headers before proxying requests.",
  },
  {
    id: "MANINY-PRX-002",
    severity: "low",
    category: "code-pattern",
    title: "Unrestricted proxy trust or header spoofing guard explicitly bypassed",
    regex: /\b(trustAllProxies|skipProxyValidation)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Restrict proxy trust to known reverse proxy hops and keep target validation active.",
  },
];

export async function runReverseProxyAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, REVERSE_PROXY_RULES);
}
