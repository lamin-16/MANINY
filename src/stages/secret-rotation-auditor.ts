import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const SECRET_ROTATION_RULES: LineAuditRule[] = [
  {
    id: "MANINY-SRT-001",
    severity: "high",
    category: "code-pattern",
    title: "Secret rotation lacks visible grace period, dual-key verification, or audit trail",
    regex: /\b(rotateManagedSecret|scheduleSecretRotation|retireSecretVersion)\s*\([^\r\n)]*(\b(secretId|version|grace|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(gracePeriod|dualKeyVerify|auditSecretRotation|enforceRotationWindow))/i,
    description: "Enforce rotation grace periods, support dual-key verification during cutover, and log secret rotations.",
  },
  {
    id: "MANINY-SRT-002",
    severity: "medium",
    category: "code-pattern",
    title: "Automatic secret rotation explicitly disabled",
    regex: /\b(disableSecretRotation|skipRotationCheck)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep secret rotation policies active to minimize long-lived credential exposure.",
  },
];

export async function runSecretRotationAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, SECRET_ROTATION_RULES);
}
