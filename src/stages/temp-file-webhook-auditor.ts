import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const TEMP_FILE_WEBHOOK_RULES: LineAuditRule[] = [
  {
    id: "MANINY-TFW-001",
    severity: "medium",
    category: "code-pattern",
    title: "Temporary file or outbound webhook handler lacks visible path guard, cleanup, or target validation",
    regex: /\b(createTempWorkspace|cleanupTempPath|dispatchWebhookEvent)\s*\([^\r\n)]*(\b(tempDir|webhookUrl|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(isSafeTempPath|unlinkSync|rmSync|validateWebhookUrl))/i,
    description: "Validate temporary paths and outbound webhook endpoints, and ensure temporary artifacts are cleaned up safely.",
  },
  {
    id: "MANINY-TFW-002",
    severity: "low",
    category: "code-pattern",
    title: "Temporary file cleanup or webhook target check explicitly disabled",
    regex: /\b(skipTempCleanup|allowUnsafeWebhook)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep temporary cleanup and outbound webhook destination checks enabled.",
  },
];

export async function runTempFileWebhookAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, TEMP_FILE_WEBHOOK_RULES);
}
