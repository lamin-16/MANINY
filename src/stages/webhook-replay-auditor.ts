import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const WEBHOOK_REPLAY_RULES: LineAuditRule[] = [
  {
    id: "MANINY-WBR-001",
    severity: "high",
    category: "code-pattern",
    title: "Webhook verification lacks visible timestamp tolerance, replay nonce, or HMAC check",
    regex: /\b(verifyWebhookSignature|guardWebhookReplay|validateWebhookTimestamp)\s*\([^\r\n)]*(\b(signature|timestamp|nonce|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(timestampTolerance|dedupeWebhookNonce|verifyHmacSignature|rejectStaleWebhook))/i,
    description: "Validate HMAC signatures, enforce timestamp freshness windows, and deduplicate webhook event IDs/nonces.",
  },
  {
    id: "MANINY-WBR-002",
    severity: "medium",
    category: "code-pattern",
    title: "Webhook replay protection or signature check explicitly bypassed",
    regex: /\b(skipWebhookReplayCheck|allowStaleWebhook)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep webhook signature and replay checks enabled.",
  },
];

export async function runWebhookReplayAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, WEBHOOK_REPLAY_RULES);
}
