import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const HTTP_HEADERS_RULES: LineAuditRule[] = [
  {
    id: "MANINY-HDR-001",
    severity: "medium",
    category: "code-pattern",
    title: "HTTP response header setup lacks visible security hardening headers",
    regex: /\b(writeHead|setResponseHeaders|configureHeaders)\s*\([^\r\n)]*(?![^\r\n]*(Content-Security-Policy|X-Content-Type-Options|X-Frame-Options|Strict-Transport-Security|helmet))/i,
    description: "Set defensive HTTP response headers such as X-Content-Type-Options, CSP, and HSTS on responses.",
  },
  {
    id: "MANINY-HDR-002",
    severity: "low",
    category: "code-pattern",
    title: "Wildcard CORS or frame-ancestors allowance configured on HTTP response",
    regex: /\b(Access-Control-Allow-Origin|frame-ancestors)\b[^\r\n;,=]*[:=]\s*['"`]?\*['"`]?/i,
    description: "Restrict cross-origin and framing policies to trusted origins rather than wildcard values.",
  },
];

export async function runHttpHeadersAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, HTTP_HEADERS_RULES);
}
