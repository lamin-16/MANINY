import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const SSRF_GUARD_RULES: LineAuditRule[] = [
  {
    id: "MANINY-SSR-001",
    severity: "high",
    category: "code-pattern",
    title: "Outbound HTTP or webhook call uses dynamic URL without visible host or SSRF check",
    regex: /\b(fetchUrl|sendWebhook|httpClient)\s*\([^\r\n)]*(\b(req\.query|req\.body|targetUrl|webhookUrl|endpointUrl)\b|\$\{)[^\r\n)]*(?![^\r\n]*(allowlist|isSafeHost|blockPrivateIp|validateHost))/i,
    description: "Validate outbound request targets against an explicit host allowlist and block internal or private network addresses.",
  },
  {
    id: "MANINY-SSR-002",
    severity: "medium",
    category: "code-pattern",
    title: "SSRF or private-network URL guard explicitly bypassed on line",
    regex: /\b(allowPrivateIp|skipSsrfCheck|disableHostCheck)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep outbound host and private-IP protections enabled to prevent server-side request forgery.",
  },
];

export async function runSsrfGuardAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, SSRF_GUARD_RULES);
}
