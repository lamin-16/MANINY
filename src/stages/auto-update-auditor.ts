import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const AUTO_UPDATE_RULES: LineAuditRule[] = [
  {
    id: "MANINY-UPD-001",
    severity: "high",
    category: "code-pattern",
    title: "Update manifest or package installer lacks visible signature, checksum, or trusted host check",
    regex: /\b(installUpdatePackage|verifyUpdateSignature|fetchUpdateManifest)\s*\([^\r\n)]*(\b(manifestUrl|updatePackage|downloadUrl)\b|\$\{)[^\r\n)]*(?![^\r\n]*(verifySignature|verifyChecksum|trustedUpdateHost|sha256))/i,
    description: "Verify cryptographic signatures and checksums over HTTPS from trusted update sources before applying updates.",
  },
  {
    id: "MANINY-UPD-002",
    severity: "medium",
    category: "code-pattern",
    title: "Update signature or integrity check explicitly bypassed",
    regex: /\b(skipUpdateSignature|allowUnsignedUpdate)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep update package signature and integrity verification enabled.",
  },
];

export async function runAutoUpdateAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, AUTO_UPDATE_RULES);
}
