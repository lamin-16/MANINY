import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const SUPPLY_CHAIN_INTEGRITY_RULES: LineAuditRule[] = [
  {
    id: "MANINY-SCI-001",
    severity: "high",
    category: "code-pattern",
    title: "Dependency or artifact check lacks visible checksum, provenance, version pin, or audit guard",
    regex: /\b(verifyPackageChecksum|pinDependencyVersion|validateRegistrySignature)\s*\([^\r\n)]*(\b(packageName|artifact|checksum|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(checkSha256Integrity|verifyProvenanceAttestation|enforceExactVersion|auditDependencyChange))/i,
    description: "Verify artifact checksums and provenance attestations, pin exact versions, and log supply-chain updates.",
  },
  {
    id: "MANINY-SCI-002",
    severity: "medium",
    category: "code-pattern",
    title: "Dependency integrity or signature check explicitly bypassed",
    regex: /\b(skipChecksumVerification|allowUnpinnedDependency)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep checksum, signature, and version-pinning guards enabled.",
  },
];

export async function runSupplyChainIntegrityAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, SUPPLY_CHAIN_INTEGRITY_RULES);
}
