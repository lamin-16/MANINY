import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy, Severity } from "../core/types.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";
import { isRuleDefinitionLine } from "./stage-utils.js";

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
const SCAN_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

interface LogInjectionRule {
  id: string;
  severity: Severity;
  category: Finding["category"];
  title: string;
  regex: RegExp;
  description: string;
}

const LOG_INJECTION_RULES: LogInjectionRule[] = [
  {
    id: "MANINY-LOG-001",
    severity: "medium",
    category: "code-pattern",
    title: "Raw request input passed directly to logging call",
    regex: /\b(console\.(log|info|warn|error|debug)|logger\.(log|info|warn|error|debug))\s*\([^\r\n)]*\b(req\.body|req\.query|req\.params|req\.headers)\b/i,
    description: "Sanitize or structure request data before writing to application logs to prevent log injection and excessive payload exposure.",
  },
  {
    id: "MANINY-LOG-002",
    severity: "low",
    category: "code-pattern",
    title: "Interpolated request metadata inside log template string",
    regex: /\b(console\.(log|info|warn|error|debug)|logger\.(log|info|warn|error|debug))\s*\([^\r\n)]*`[^`]*\$\{[^}\r\n]*\b(req\.|ip|userAgent|x-forwarded-for)\b[^}\r\n]*\}[^`]*`/i,
    description: "Normalize or strip control characters and untrusted client headers before interpolating request metadata into logs.",
  },
];

function makeLogFindingId(ruleId: string, relFile: string, line: number): string {
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

export async function runLogInjectionAuditor(policy: ManinyPolicy): Promise<Finding[]> {
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
      for (const rule of LOG_INJECTION_RULES) {
        if (!isRuleDefinitionLine(lineText) && rule.regex.test(lineText)) {
          const lineNum = i + 1;
          findings.push({
            id: makeLogFindingId(rule.id, relFile, lineNum),
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
