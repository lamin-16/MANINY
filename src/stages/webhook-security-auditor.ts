import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const WEBHOOK_SECURITY_RULES: LineAuditRule[] = [
  {
    id: "MANINY-WHK-001",
    severity: "high",
    category: "code-pattern",
    title: "Webhook handler processes incoming payload without visible signature or secret verification",
    regex: /\b(handleWebhook|processWebhook|onWebhookEvent)\s*\([^\r\n)]*(req\.body|rawBody|payload)[^\r\n)]*(?![^\r\n]*(verifySignature|webhookSecret|hmac|signature))/i,
    description: "Verify webhook signatures and shared secrets before processing external event payloads.",
  },
  {
    id: "MANINY-WHK-002",
    severity: "medium",
    category: "code-pattern",
    title: "Webhook signature verification explicitly bypassed or disabled",
    regex: /\b(skipWebhookVerification|disableWebhookAuth|allowUnsignedWebhook)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep webhook signature verification enabled to prevent spoofed event delivery.",
  },
];

export async function runWebhookSecurityAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, WEBHOOK_SECURITY_RULES);
}
