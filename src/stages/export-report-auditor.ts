import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const EXPORT_REPORT_RULES: LineAuditRule[] = [
  {
    id: "MANINY-EXP-001",
    severity: "medium",
    category: "code-pattern",
    title: "Data export or report generator references sensitive fields without visible redaction or access guard",
    regex: /\b(exportReport|generateCsvExport|buildExportStream)\b[^\r\n;{)]*(password|secret|token|ssn|apiKey|rawRows)[^\r\n;{)]*(?![^\r\n]*(redact|mask|sanitize|authorize))/i,
    description: "Mask or exclude sensitive fields and enforce authorization checks before exporting reports or datasets.",
  },
  {
    id: "MANINY-EXP-002",
    severity: "low",
    category: "code-pattern",
    title: "Report row limit or export redaction guard explicitly bypassed",
    regex: /\b(skipExportRedaction|unlimitedExportRows)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep sensitive field redaction and export size limits active when generating downloadable reports.",
  },
];

export async function runExportReportAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, EXPORT_REPORT_RULES);
}
