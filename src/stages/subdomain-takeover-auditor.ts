import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const SUBDOMAIN_TAKEOVER_RULES: LineAuditRule[] = [
  {
    id: "MANINY-SUB-001",
    severity: "high",
    category: "code-pattern",
    title: "Subdomain or custom domain binding lacks visible ownership proof, endpoint claim, or host guard",
    regex: /\b(provisionSubdomainRecord|bindCustomDomain|verifyDnsOwnership)\s*\([^\r\n)]*(\b(cnameTarget|customDomain|subdomain)\b|\$\{)[^\r\n)]*(?![^\r\n]*(verifyDomainOwnership|claimCloudEndpoint|validateSubdomainHost|txtRecord))/i,
    description: "Verify domain ownership via TXT/challenge records and claim target cloud endpoints before publishing DNS records.",
  },
  {
    id: "MANINY-SUB-002",
    severity: "medium",
    category: "code-pattern",
    title: "Dangling CNAME or unverified subdomain binding explicitly permitted",
    regex: /\b(allowDanglingCname|skipDomainOwnershipCheck)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Remove dangling DNS records and keep domain ownership verification enabled.",
  },
];

export async function runSubdomainTakeoverAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, SUBDOMAIN_TAKEOVER_RULES);
}
