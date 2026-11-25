import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const FILE_TRANSFER_RULES: LineAuditRule[] = [
  {
    id: "MANINY-TRF-001",
    severity: "high",
    category: "code-pattern",
    title: "File upload or transfer lacks visible type, size, or safe path check",
    regex: /\b(uploadFile|saveUpload|handleUpload)\b[^\r\n;{)]*(?![^\r\n]*(mime|allowedTypes|maxSize|safePath|resolveSafe))/i,
    description: "Validate uploaded file types, size limits, and destination paths before persisting files.",
  },
  {
    id: "MANINY-TRF-002",
    severity: "medium",
    category: "code-pattern",
    title: "Arbitrary remote file fetch or download uses unvalidated URL or input",
    regex: /\b(downloadFile|fetchRemoteFile)\s*\([^\r\n)]*(\b(req\.query|req\.body|req\.params)\b|\$\{)[^\r\n)]*(?![^\r\n]*(allowlist|safeUrl|validateUrl))/i,
    description: "Restrict outbound file downloads to validated URLs and trusted hosts.",
  },
];

export async function runFileTransferAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, FILE_TRANSFER_RULES);
}
