import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const GRAPHQL_SECURITY_RULES: LineAuditRule[] = [
  {
    id: "MANINY-GQL-001",
    severity: "medium",
    category: "code-pattern",
    title: "GraphQL server or schema setup lacks visible depth or complexity limit guard",
    regex: /\b(createGraphqlServer|graphqlYoga|apolloServer)\b[^\r\n;{)]*(schema|typeDefs)[^\r\n;{)]*(?![^\r\n]*(depthLimit|maxDepth|complexityLimit|queryComplexity))/i,
    description: "Configure query depth and complexity limits on GraphQL endpoints to mitigate nested query denial-of-service risks.",
  },
  {
    id: "MANINY-GQL-002",
    severity: "low",
    category: "code-pattern",
    title: "GraphQL introspection or query depth guard explicitly disabled or bypassed",
    regex: /\b(disableDepthLimit|skipQueryComplexity)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep GraphQL query depth and complexity protections active in production environments.",
  },
];

export async function runGraphqlSecurityAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, GRAPHQL_SECURITY_RULES);
}
