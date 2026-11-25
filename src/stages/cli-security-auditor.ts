import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const CLI_SECURITY_RULES: LineAuditRule[] = [
  {
    id: "MANINY-CLI-001",
    severity: "medium",
    category: "code-pattern",
    title: "CLI argument parser or command runner lacks visible validation or safe argument handling",
    regex: /\b(parseCliArgs|executeCliCommand|spawnCliProcess)\s*\([^\r\n)]*(\b(process\.argv|rawArgs|cliInput)\b|\$\{)[^\r\n)]*(?![^\r\n]*(validateArgs|sanitizeArg|execFile|allowedFlags))/i,
    description: "Validate CLI flags and arguments and avoid passing untrusted command strings into shell execution.",
  },
  {
    id: "MANINY-CLI-002",
    severity: "low",
    category: "code-pattern",
    title: "CLI input validation or shell safety check explicitly bypassed",
    regex: /\b(skipCliValidation|allowRawCliArgs)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep CLI argument validation enabled to prevent unintended command behavior or injection.",
  },
];

export async function runCliSecurityAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, CLI_SECURITY_RULES);
}
