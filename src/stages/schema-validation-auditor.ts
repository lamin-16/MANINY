import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const SCHEMA_VALIDATION_RULES: LineAuditRule[] = [
  {
    id: "MANINY-SCH-001",
    severity: "medium",
    category: "code-pattern",
    title: "Schema validation or payload parser lacks visible strict schema, safeParse, or depth guard",
    regex: /\b(validateSchemaPayload|parseValidatedBody|compileValidationSchema)\s*\([^\r\n)]*(\b(req\.body|rawPayload|inputData)\b|\$\{)[^\r\n)]*(?![^\r\n]*(safeParse|strictSchema|zodSchema|maxDepth))/i,
    description: "Validate incoming payloads with explicit schemas, safe parsing, and nesting/size bounds before processing.",
  },
  {
    id: "MANINY-SCH-002",
    severity: "low",
    category: "code-pattern",
    title: "Schema validation or unknown-field rejection explicitly disabled",
    regex: /\b(skipSchemaValidation|allowUnknownFields)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep schema validation enabled and reject unexpected fields on untrusted inputs.",
  },
];

export async function runSchemaValidationAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, SCHEMA_VALIDATION_RULES);
}
