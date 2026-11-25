import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const SQL_NOSQL_BIND_RULES: LineAuditRule[] = [
  {
    id: "MANINY-BND-001",
    severity: "high",
    category: "code-pattern",
    title: "Query or filter execution lacks visible bound parameters, schema check, or operator guard",
    regex: /\b(executeParameterizedQuery|buildFilterPredicate|runAggregationPipeline)\s*\([^\r\n)]*(\b(sql|filter|pipeline|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(bindParams|validateFilterSchema|stripDollarOperators|assertSafeQuery))/i,
    description: "Use bound parameters, validate filter schemas, and reject untrusted query/aggregation operators.",
  },
  {
    id: "MANINY-BND-002",
    severity: "medium",
    category: "code-pattern",
    title: "Query parameter binding or operator guard explicitly bypassed",
    regex: /\b(allowRawQueryString|skipOperatorSanitization)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep parameterized queries and filter sanitization enabled.",
  },
];

export async function runSqlNosqlBindAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, SQL_NOSQL_BIND_RULES);
}
