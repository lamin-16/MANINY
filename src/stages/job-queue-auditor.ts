import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const JOB_QUEUE_RULES: LineAuditRule[] = [
  {
    id: "MANINY-JOB-001",
    severity: "medium",
    category: "code-pattern",
    title: "Background job or queue worker handles dynamic payload without visible schema or auth check",
    regex: /\b(enqueueJob|processQueue|runBackgroundJob)\s*\([^\r\n)]*(\b(req\.body|rawJob|payload)\b|\$\{)[^\r\n)]*(?![^\r\n]*(schema|validate|authorize|tenantId|safeParse))/i,
    description: "Validate job payloads and enforce authorization or tenant context before enqueueing or executing background tasks.",
  },
  {
    id: "MANINY-JOB-002",
    severity: "low",
    category: "code-pattern",
    title: "Queue job concurrency or retry limit guard explicitly disabled",
    regex: /\b(disableJobRetry|unlimitedQueueConcurrency)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Maintain bounded concurrency and controlled retry policies on background job queues.",
  },
];

export async function runJobQueueAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, JOB_QUEUE_RULES);
}
