import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const DESERIALIZATION_GUARD_RULES: LineAuditRule[] = [
  {
    id: "MANINY-DSR-001",
    severity: "high",
    category: "code-pattern",
    title: "Deserialization or payload parsing lacks visible schema validation, allowlist, or safe parser",
    regex: /\b(deserializeUntrustedPayload|parseUnsafeYaml|reviveSerializedObject)\s*\([^\r\n)]*(\b(payload|raw|input|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(validatePayloadSchema|allowedClassList|safeJsonParse|rejectPrototypeKeys))/i,
    description: "Validate deserialized structures against a strict schema, enforce type allowlists, and block prototype pollution keys.",
  },
  {
    id: "MANINY-DSR-002",
    severity: "medium",
    category: "code-pattern",
    title: "Unsafe deserialization guard explicitly bypassed",
    regex: /\b(allowUnsafeDeserialization|skipSchemaValidation)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep schema validation and safe deserialization controls enabled.",
  },
];

export async function runDeserializationGuardAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, DESERIALIZATION_GUARD_RULES);
}
