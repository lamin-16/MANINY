import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const REALTIME_SOCKET_RULES: LineAuditRule[] = [
  {
    id: "MANINY-SCK-001",
    severity: "medium",
    category: "code-pattern",
    title: "Realtime or WebSocket event handler processes dynamic payload without visible auth or schema check",
    regex: /\b(handleSocketEvent|createSocketServer|onRealtimeMessage)\s*\([^\r\n)]*(\b(messagePayload|rawEvent|socketData)\b|\$\{)[^\r\n)]*(?![^\r\n]*(authenticateSocket|authorizeRoom|validateEvent|schema))/i,
    description: "Authenticate socket connections, verify channel authorization, and validate realtime payloads before handling events.",
  },
  {
    id: "MANINY-SCK-002",
    severity: "low",
    category: "code-pattern",
    title: "Realtime message size limit or socket authentication explicitly disabled",
    regex: /\b(skipSocketAuth|unlimitedSocketPayload)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep socket authentication and payload size limits enabled to prevent unauthorized or oversized realtime frames.",
  },
];

export async function runRealtimeSocketAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, REALTIME_SOCKET_RULES);
}
