import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const JOB_QUEUE_POISON_RULES: LineAuditRule[] = [
  {
    id: "MANINY-JQP-001",
    severity: "medium",
    category: "code-pattern",
    title: "Queue worker lacks visible max retry cap, dead-letter routing, or poison-pill guard",
    regex: /\b(consumeQueueJob|processBackgroundTask|handleFailedJob)\s*\([^\r\n)]*(\b(job|payload|attempts|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(maxRetries|deadLetterQueue|quarantinePoisonJob|validateJobSchema))/i,
    description: "Cap retry attempts, route failing jobs to a dead-letter queue, validate payloads, and quarantine poison messages.",
  },
  {
    id: "MANINY-JQP-002",
    severity: "low",
    category: "code-pattern",
    title: "Queue retry limit or dead-letter routing explicitly disabled",
    regex: /\b(unlimitedJobRetries|disableDeadLetterQueue)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep retry caps and dead-letter queues active to prevent infinite retry loops.",
  },
];

export async function runJobQueuePoisonAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, JOB_QUEUE_POISON_RULES);
}
