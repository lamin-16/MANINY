import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const ANOMALY_GUARD_RULES: LineAuditRule[] = [
  {
    id: "MANINY-ANO-001",
    severity: "medium",
    category: "code-pattern",
    title: "Anomaly detector or risk scorer lacks visible threshold, actor context check, or audit log",
    regex: /\b(detectAnomalyBurst|evaluateRiskScore|flagSuspiciousActor)\s*\([^\r\n)]*(\b(actorId|eventRate|riskPayload|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(anomalyThreshold|verifyActorContext|auditAnomalyEvent|cooldownWindow))/i,
    description: "Calibrate anomaly thresholds and cooldown windows, verify actor context, and log security alerts deterministically.",
  },
  {
    id: "MANINY-ANO-002",
    severity: "low",
    category: "code-pattern",
    title: "Anomaly detection or risk scoring explicitly bypassed",
    regex: /\b(skipAnomalyDetection|disableRiskScoring)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep anomaly and risk evaluation active for sensitive operations.",
  },
];

export async function runAnomalyGuardAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, ANOMALY_GUARD_RULES);
}
