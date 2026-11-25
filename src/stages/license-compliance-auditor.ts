import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const LICENSE_COMPLIANCE_RULES: LineAuditRule[] = [
  {
    id: "MANINY-LIC-001",
    severity: "medium",
    category: "code-pattern",
    title: "Copyleft or restrictive license referenced in policy or package manifest",
    regex: /\b(license|spdx)\b[^\r\n;,)]*[:=]\s*['"`]?(GPL-3\.0|AGPL-3\.0|SSPL|Commons-Clause)['"`]?/i,
    description: "Review copyleft or restrictive licenses against organizational distribution and compliance policies.",
  },
  {
    id: "MANINY-LIC-002",
    severity: "low",
    category: "code-pattern",
    title: "License compliance enforcement explicitly disabled or skipped",
    regex: /\b(skipLicenseCheck|disableLicenseAudit|allowUnlicensed)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep dependency license compliance checks enabled to catch unapproved or restricted licenses.",
  },
];

export async function runLicenseComplianceAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, LICENSE_COMPLIANCE_RULES);
}
