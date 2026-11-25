import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy, Severity } from "../core/types.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";
import { isRuleDefinitionLine } from "./stage-utils.js";

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
const SCAN_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

interface CommandExecutionRule {
  id: string;
  severity: Severity;
  category: Finding["category"];
  title: string;
  regex: RegExp;
  description: string;
}

const COMMAND_EXECUTION_RULES: CommandExecutionRule[] = [
  {
    id: "MANINY-CMD-001",
    severity: "high",
    category: "code-pattern",
    title: "Shell or process execution uses request input or dynamic template without visible allowlist guard",
    regex: /\b(exec|execSync|spawn|spawnSync)\s*\([^\r\n)]*(\b(req\.query|req\.body|req\.params)\b|`[^`\n]*\$\{)[^\r\n)]*(?![^\r\n]*(allowlist|allowedCommands|validate))/i,
    description: "Avoid passing untrusted or interpolated strings into shell commands; use parameterized arguments and strict command allowlists.",
  },
  {
    id: "MANINY-CMD-002",
    severity: "medium",
    category: "code-pattern",
    title: "Subprocess spawned with shell enabled alongside dynamic or request input",
    regex: /\bshell\s*:\s*true\b[^\r\n;,}]*(\b(req\.query|req\.body|req\.params)\b|\$\{)/i,
    description: "Disable shell execution when spawning child processes to reduce command injection surface.",
  },
];

function makeCmdFindingId(ruleId: string, relFile: string, line: number): string {
  const hash = crypto.createHash("sha256").update(`${ruleId}:${relFile}:${line}`).digest("hex").slice(0, 10);
  return `F-${hash}`;
}

async function collectFiles(dir: string, root: string): Promise<string[]> {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const results: string[] = [];
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) results.push(...(await collectFiles(path.join(dir, entry.name), root)));
    } else if (entry.isFile() && SCAN_EXTS.has(path.extname(entry.name).toLowerCase())) {
      const rel = path.relative(root, path.join(dir, entry.name));
      if (rel) results.push(rel);
    }
  }
  return results;
}

export async function runCommandExecutionAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await collectFiles(policy.workspaceRoot, policy.workspaceRoot);
  for (const relFile of files) {
    const safePath = resolveSafeWorkspacePath(policy.workspaceRoot, relFile);
    if (!safePath) continue;
    let content: string;
    try { content = await fs.readFile(safePath, "utf8"); } catch { continue; }
    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const lineText = lines[i] ?? "";
      const trimmed = lineText.trim();
      if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("*")) continue;
      for (const rule of COMMAND_EXECUTION_RULES) {
        if (!isRuleDefinitionLine(lineText) && rule.regex.test(lineText)) {
          const lineNum = i + 1;
          findings.push({
            id: makeCmdFindingId(rule.id, relFile, lineNum),
            ruleId: rule.id,
            title: rule.title,
            category: rule.category,
            severity: rule.severity,
            filePath: relFile,
            line: lineNum,
            description: rule.description,
            status: "detected",
            evidence: [],
          });
        }
      }
    }
  }
  return findings;
}
