import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const CRON_SCHEDULER_RULES: LineAuditRule[] = [
  {
    id: "MANINY-CRN-001",
    severity: "medium",
    category: "code-pattern",
    title: "Scheduled or cron job handler uses dynamic expression or input without visible validation or lock guard",
    regex: /\b(scheduleCron|registerCronJob|runScheduledTask)\s*\([^\r\n)]*(\b(req\.body|cronExpr|taskCommand)\b|\$\{)[^\r\n)]*(?![^\r\n]*(validateSchedule|lockAcquired|overlapGuard|sanitize))/i,
    description: "Validate schedule expressions and guard scheduled jobs against overlapping runs or untrusted command inputs.",
  },
  {
    id: "MANINY-CRN-002",
    severity: "low",
    category: "code-pattern",
    title: "Scheduled job overlap or concurrency protection explicitly disabled",
    regex: /\b(allowOverlappingCron|skipJobLock)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep overlap guards enabled on scheduled tasks to avoid race conditions and resource exhaustion.",
  },
];

export async function runCronSchedulerAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, CRON_SCHEDULER_RULES);
}
