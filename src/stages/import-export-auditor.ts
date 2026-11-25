import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const IMPORT_EXPORT_RULES: LineAuditRule[] = [
  {
    id: "MANINY-IEX-001",
    severity: "medium",
    category: "code-pattern",
    title: "Import or export handler lacks visible schema check, size bound, or access guard",
    regex: /\b(importDataRecords|exportReportBundle|parseImportArchive)\s*\([^\r\n)]*(\b(req\.body|archivePath|importSource|exportScope)\b|\$\{)[^\r\n)]*(?![^\r\n]*(validateImportSchema|sanitizeExportPath|authorizeExport|maxImportBytes))/i,
    description: "Validate imported schemas and size limits, restrict export scopes, and sanitize output paths.",
  },
  {
    id: "MANINY-IEX-002",
    severity: "low",
    category: "code-pattern",
    title: "Import schema validation or export scope guard explicitly bypassed",
    regex: /\b(skipImportValidation|allowUnrestrictedExport)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep import validation and export authorization checks enabled.",
  },
];

export async function runImportExportAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, IMPORT_EXPORT_RULES);
}
