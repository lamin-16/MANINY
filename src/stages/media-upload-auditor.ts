import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const MEDIA_UPLOAD_RULES: LineAuditRule[] = [
  {
    id: "MANINY-MED-001",
    severity: "medium",
    category: "code-pattern",
    title: "Media or file upload handler processes input without visible type, size, or filename validation",
    regex: /\b(uploadMedia|handleFileUpload|processImageUpload)\s*\([^\r\n)]*(\b(req\.file|originalname|fileName|uploadStream)\b|\$\{)[^\r\n)]*(?![^\r\n]*(allowedMimeTypes|maxFileSize|sanitizeFilename|validateUpload))/i,
    description: "Validate MIME types, file size bounds, and safe filenames before storing or processing uploaded files.",
  },
  {
    id: "MANINY-MED-002",
    severity: "low",
    category: "code-pattern",
    title: "Upload file type or size restriction explicitly bypassed or disabled",
    regex: /\b(skipUploadValidation|allowAnyFileType)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep file type and size checks enforced on upload endpoints to prevent malicious or oversized file uploads.",
  },
];

export async function runMediaUploadAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, MEDIA_UPLOAD_RULES);
}
