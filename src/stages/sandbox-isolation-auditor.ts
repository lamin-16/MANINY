import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const SANDBOX_ISOLATION_RULES: LineAuditRule[] = [
  {
    id: "MANINY-SBX-001",
    severity: "high",
    category: "code-pattern",
    title: "Sandbox or container isolation lacks visible seccomp, capability drop, namespace, or mount guard",
    regex: /\b(launchSandboxedProcess|configureSeccompProfile|isolateContainerNamespace)\s*\([^\r\n)]*(\b(sandbox|seccomp|namespace|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(enforceSeccompFilter|dropCapabilities|isolateUserNamespace|restrictHostMounts))/i,
    description: "Enforce seccomp syscall filters, drop Linux capabilities, isolate namespaces, and restrict host mounts.",
  },
  {
    id: "MANINY-SBX-002",
    severity: "high",
    category: "code-pattern",
    title: "Privileged mode or sandbox isolation explicitly disabled",
    regex: /\b(privilegedSandbox|disableNamespaceIsolation)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Avoid privileged sandbox execution and keep namespace isolation enabled.",
  },
];

export async function runSandboxIsolationAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, SANDBOX_ISOLATION_RULES);
}
