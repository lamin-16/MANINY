import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const SEARCH_QUERY_RULES: LineAuditRule[] = [
  {
    id: "MANINY-SRQ-001",
    severity: "medium",
    category: "code-pattern",
    title: "Search query or filter builder uses raw dynamic input without visible escaping or sanitization",
    regex: /\b(buildSearchFilter|queryIndex|runSearchQuery)\s*\([^\r\n)]*(\b(req\.query|searchTerm|rawQuery)\b|\$\{)[^\r\n)]*(?![^\r\n]*(sanitizeQuery|escapeRegex|validateFilter|maxLimit))/i,
    description: "Sanitize or escape user search inputs and enforce query bounds before executing search or index queries.",
  },
  {
    id: "MANINY-SRQ-002",
    severity: "low",
    category: "code-pattern",
    title: "Search result limit or query complexity check explicitly bypassed",
    regex: /\b(bypassSearchLimit|unlimitedSearchResults)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep result limits and search query guards enabled to prevent expensive or abusive queries.",
  },
];

export async function runSearchQueryAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, SEARCH_QUERY_RULES);
}
