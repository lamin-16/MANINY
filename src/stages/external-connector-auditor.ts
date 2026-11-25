import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const EXTERNAL_CONNECTOR_RULES: LineAuditRule[] = [
  {
    id: "MANINY-CON-001",
    severity: "medium",
    category: "code-pattern",
    title: "External connector or third-party API call lacks visible target host or secret handling guard",
    regex: /\b(callExternalConnector|invokeThirdPartyApi|connectIntegration)\s*\([^\r\n)]*(\b(req\.body|endpointUrl|targetHost)\b|\$\{)[^\r\n)]*(?![^\r\n]*(validateEndpoint|allowedHosts|maskSecret|sanitize))/i,
    description: "Validate external integration targets against allowed hosts and protect credentials or payloads before calling connectors.",
  },
  {
    id: "MANINY-CON-002",
    severity: "low",
    category: "code-pattern",
    title: "Connector TLS or endpoint allowlist verification explicitly bypassed",
    regex: /\b(skipConnectorAllowlist|insecureConnectorTls)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep endpoint allowlisting and secure transport checks enabled for external connectors.",
  },
];

export async function runExternalConnectorAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, EXTERNAL_CONNECTOR_RULES);
}
