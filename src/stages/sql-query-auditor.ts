import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy, Severity } from "../core/types.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";
import { isRuleDefinitionLine } from "./stage-utils.js";

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
const SCAN_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

interface SqlQueryRule {
  id: string;
  severity: Severity;
  category: Finding["category"];
  title: string;
  regex: RegExp;
  description: string;
}

const SQL_QUERY_RULES: SqlQueryRule[] = [
  {
    id: "MANINY-SQL-001",
    severity: "high",
    category: "code-pattern",
    title: "Interpolated template expression inside SQL statement template literal",
    regex: /`[^`]*\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP\s+TABLE)\b[^`]*\$\{[^}]+\}[^`]*`/i,
    description: "Use parameterized queries or prepared statements instead of interpolating dynamic values into SQL command strings.",
  },
  {
    id: "MANINY-SQL-002",
    severity: "medium",
    category: "code-pattern",
    title: "Raw SQL execution helper called with interpolated template or string concatenation",
    regex: /\b(queryRaw|executeRaw|rawQuery|db\.query)\s*\([^\r\n)]*(`[^`]*\$\{[^}]+\}[^`]*`|\+\s*[A-Za-z_$])/i,
    description: "Avoid string concatenation or template interpolation in raw SQL execution helpers; bind untrusted values as parameters.",
  },
];

function makeSqlFindingId(ruleId: string, relFile: string, line: number): string {
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

export async function runSqlQueryAuditor(policy: ManinyPolicy): Promise<Finding[]> {
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
      for (const rule of SQL_QUERY_RULES) {
        if (!isRuleDefinitionLine(lineText) && rule.regex.test(lineText)) {
          const lineNum = i + 1;
          findings.push({
            id: makeSqlFindingId(rule.id, relFile, lineNum),
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
