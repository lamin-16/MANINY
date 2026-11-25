import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const NOTIFICATION_QUEUE_RULES: LineAuditRule[] = [
  {
    id: "MANINY-NTF-001",
    severity: "medium",
    category: "code-pattern",
    title: "Notification or queue dispatch lacks visible recipient check, payload sanitization, or job validation",
    regex: /\b(sendNotification|enqueueJob|publishEvent)\s*\([^\r\n)]*(\b(recipient|payload|queueName|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(sanitizePayload|validateRecipient|verifyQueueJob|redact))/i,
    description: "Validate recipients and job payloads and redact sensitive fields before dispatching notifications or queued tasks.",
  },
  {
    id: "MANINY-NTF-002",
    severity: "low",
    category: "code-pattern",
    title: "Notification or queue payload validation explicitly bypassed",
    regex: /\b(skipQueueValidation|allowUnverifiedRecipient)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep queue job validation and recipient verification enabled.",
  },
];

export async function runNotificationQueueAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, NOTIFICATION_QUEUE_RULES);
}
