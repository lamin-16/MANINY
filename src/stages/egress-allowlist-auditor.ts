import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const EGRESS_ALLOWLIST_RULES: LineAuditRule[] = [
  {
    id: "MANINY-EAL-001",
    severity: "high",
    category: "code-pattern",
    title: "Outbound egress call lacks visible host allowlist, private-IP block, or DNS pinning guard",
    regex: /\b(dispatchEgressRequest|openOutboundTunnel|resolveEgressHost)\s*\([^\r\n)]*(\b(url|host|endpoint|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(allowedEgressHosts|blockPrivateRanges|pinResolvedIp|validateEgressUrl))/i,
    description: "Enforce explicit outbound host allowlists, block private/link-local IP ranges, and validate destination URLs.",
  },
  {
    id: "MANINY-EAL-002",
    severity: "medium",
    category: "code-pattern",
    title: "Outbound egress allowlist or private IP check explicitly bypassed",
    regex: /\b(allowAllEgress|skipPrivateIpCheck)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep outbound allowlists and private-range restrictions active.",
  },
];

export async function runEgressAllowlistAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, EGRESS_ALLOWLIST_RULES);
}
