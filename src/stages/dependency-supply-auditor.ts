import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const DEPENDENCY_SUPPLY_RULES: LineAuditRule[] = [
  {
    id: "MANINY-SUP-001",
    severity: "medium",
    category: "dependency",
    title: "Unpinned wildcard or latest dependency version specified in manifest",
    regex: /"[^"]+"\s*:\s*"(\*|latest)"/,
    description: "Pin dependency versions or ranges explicitly to prevent unexpected supply-chain updates.",
    extensions: new Set([".json"]),
  },
  {
    id: "MANINY-SUP-002",
    severity: "medium",
    category: "code-pattern",
    title: "Package installation or execution skips audit or lifecycle script safeguards",
    regex: /\b(npm\s+install|yarn\s+add|pnpm\s+add)\b[^\r\n]*(--no-audit|--ignore-scripts)/i,
    description: "Avoid bypassing security audits or lifecycle script controls during dependency installation.",
  },
];

export async function runDependencySupplyAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, DEPENDENCY_SUPPLY_RULES);
}
