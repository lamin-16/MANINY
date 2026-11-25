import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const INJECTION_GUARD_RULES: LineAuditRule[] = [
  {
    id: "MANINY-INJ-001",
    severity: "high",
    category: "code-pattern",
    title: "SQL or query execution interpolates dynamic values without parameterized binding",
    regex: /\b(executeQuery|runSql|rawQuery)\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`\s*(?![^\r\n)]*(params|bindings|values))/i,
    description: "Use parameterized queries or bound placeholders instead of interpolating dynamic values into query strings.",
  },
  {
    id: "MANINY-INJ-002",
    severity: "high",
    category: "code-pattern",
    title: "Shell or command runner interpolates dynamic input without argument array isolation",
    regex: /\b(execCommand|runShell)\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`/i,
    description: "Avoid shell string interpolation with dynamic inputs; pass fixed commands and validated argument arrays.",
  },
];

export async function runInjectionGuardAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, INJECTION_GUARD_RULES);
}
