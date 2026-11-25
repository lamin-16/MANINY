import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const BACKUP_RESTORE_RULES: LineAuditRule[] = [
  {
    id: "MANINY-BKP-001",
    severity: "high",
    category: "code-pattern",
    title: "Backup or restore routine lacks visible encryption, integrity check, or safe path guard",
    regex: /\b(createBackup|restoreSnapshot|exportBackupArchive)\s*\([^\r\n)]*(\b(req\.body|backupPath|snapshotId)\b|\$\{)[^\r\n)]*(?![^\r\n]*(encrypt|verifyChecksum|sanitizePath|authorize))/i,
    description: "Encrypt backup archives, verify snapshot integrity, and validate target paths before backup or restore operations.",
  },
  {
    id: "MANINY-BKP-002",
    severity: "medium",
    category: "code-pattern",
    title: "Backup encryption or checksum verification explicitly disabled",
    regex: /\b(skipBackupEncryption|disableSnapshotChecksum)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep backup encryption and integrity verification enabled to protect stored recovery artifacts.",
  },
];

export async function runBackupRestoreAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, BACKUP_RESTORE_RULES);
}
