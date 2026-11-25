import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const DEPLOY_PIPELINE_RULES: LineAuditRule[] = [
  {
    id: "MANINY-DPL-001",
    severity: "high",
    category: "code-pattern",
    title: "Deployment or container configuration enables privileged or root execution without visible guard",
    regex: /\b(privileged|runAsRoot|allowRootUser)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Avoid running containers or deployment workers with privileged or root access unless strictly justified and isolated.",
  },
  {
    id: "MANINY-DPL-002",
    severity: "medium",
    category: "code-pattern",
    title: "Deployment pipeline security scan or signature check explicitly skipped",
    regex: /\b(skipSecurityScan|allowInsecureDeploy|bypassDeployCheck)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep security verification and artifact checks active in deployment pipelines.",
  },
];

export async function runDeployPipelineAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, DEPLOY_PIPELINE_RULES);
}
