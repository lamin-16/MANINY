import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const STEP_UP_AUTH_RULES: LineAuditRule[] = [
  {
    id: "MANINY-STP-001",
    severity: "high",
    category: "code-pattern",
    title: "Step-up authentication lacks visible max auth age, MFA challenge, reauth, or audit guard",
    regex: /\b(enforceStepUpAuth|requireFreshMfa|verifyElevatedChallenge)\s*\([^\r\n)]*(\b(action|session|challenge|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(maxAuthAge|verifyMfaChallenge|auditStepUpEvent|requireReauth))/i,
    description: "Enforce fresh authentication age limits, require MFA re-verification for privileged actions, and log step-up events.",
  },
  {
    id: "MANINY-STP-002",
    severity: "medium",
    category: "code-pattern",
    title: "Step-up authentication or fresh MFA explicitly bypassed",
    regex: /\b(skipStepUpAuth|bypassFreshMfa)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep step-up authentication enabled for high-impact operations.",
  },
];

export async function runStepUpAuthAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, STEP_UP_AUTH_RULES);
}
