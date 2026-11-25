import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const NOTIFICATION_SECURITY_RULES: LineAuditRule[] = [
  {
    id: "MANINY-NTF-001",
    severity: "medium",
    category: "code-pattern",
    title: "Outbound email, SMS, or push notification interpolates dynamic input without visible sanitization",
    regex: /\b(sendEmail|sendSms|sendPushNotification)\s*\([^\r\n)]*(\b(req\.body|req\.query|recipient|userInput)\b|\$\{)[^\r\n)]*(?![^\r\n]*(sanitize|escapeHtml|validateRecipient|isSafeUrl))/i,
    description: "Sanitize dynamic content and validate recipient targets or links before dispatching notifications.",
  },
  {
    id: "MANINY-NTF-002",
    severity: "low",
    category: "code-pattern",
    title: "Notification template HTML escaping or link validation explicitly bypassed",
    regex: /\b(skipHtmlEscape|allowRawNotificationHtml)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep HTML escaping enabled for notification bodies unless strictly sanitized.",
  },
];

export async function runNotificationSecurityAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, NOTIFICATION_SECURITY_RULES);
}
