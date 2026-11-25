import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const DESERIALIZATION_RULES: LineAuditRule[] = [
  {
    id: "MANINY-DES-001",
    severity: "high",
    category: "code-pattern",
    title: "Untrusted payload deserialized without visible schema or structure validation",
    regex: /\b(deserializePayload|unserialize|parseUntrusted)\s*\([^\r\n)]*(\b(req\.body|rawPayload|inputData)\b|\$\{)[^\r\n)]*(?![^\r\n]*(schema|safeParse|validate|zod|ajv))/i,
    description: "Validate untrusted payloads against a strict schema before deserializing or acting on structured input.",
  },
  {
    id: "MANINY-DES-002",
    severity: "high",
    category: "code-pattern",
    title: "Unsafe YAML or dynamic code parser invoked on line",
    regex: /\b(yaml\.load|loadYamlUnsafe|new Function)\s*\(/i,
    description: "Use safe parsing modes such as yaml.safeLoad or strict JSON/schema parsers instead of unsafe loaders.",
  },
];

export async function runDeserializationAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, DESERIALIZATION_RULES);
}
