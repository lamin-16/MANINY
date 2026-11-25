import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const INDEX_ENGINE_RULES: LineAuditRule[] = [
  {
    id: "MANINY-IDX-001",
    severity: "medium",
    category: "code-pattern",
    title: "Database or search index operation interpolates dynamic identifier without visible validation",
    regex: /\b(buildDbIndex|reindexCollection|createSearchIndex)\s*\([^\r\n)]*(\b(req\.body|indexName|fieldName)\b|\$\{)[^\r\n)]*(?![^\r\n]*(allowedIndexes|sanitizeIdentifier|validateIndexName))/i,
    description: "Validate index and field identifiers against an explicit allowlist or sanitizer before creating or rebuilding indexes.",
  },
  {
    id: "MANINY-IDX-002",
    severity: "low",
    category: "code-pattern",
    title: "Index rebuilding lock or resource guard explicitly bypassed",
    regex: /\b(skipIndexLock|bypassReindexGuard)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep concurrency and resource guards enabled during index creation and reindexing operations.",
  },
];

export async function runIndexEngineAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, INDEX_ENGINE_RULES);
}
