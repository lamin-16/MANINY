import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const XSS_SINK_GUARD_RULES: LineAuditRule[] = [
  {
    id: "MANINY-XSS-001",
    severity: "high",
    category: "code-pattern",
    title: "HTML or template rendering lacks visible sanitization, escaping, or safe text encoding",
    regex: /\b(renderHtmlFragment|injectRichSnippet|formatTemplateOutput)\s*\([^\r\n)]*(\b(html|snippet|template|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(sanitizeHtml|escapeHtml|encodeTextContent|applyStrictCsp))/i,
    description: "Sanitize rich HTML with an allowlist, escape untrusted strings for context, and enforce strict CSP.",
  },
  {
    id: "MANINY-XSS-002",
    severity: "medium",
    category: "code-pattern",
    title: "HTML sanitization or output escaping explicitly skipped",
    regex: /\b(skipHtmlSanitization|rawUnescapedHtml)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep HTML sanitization and context-aware output escaping enabled.",
  },
];

export async function runXssSinkGuardAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, XSS_SINK_GUARD_RULES);
}
