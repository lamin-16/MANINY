import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy, Severity } from "../core/types.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
const SCAN_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

interface ResourceExhaustionRule {
  id: string;
  severity: Severity;
  category: Finding["category"];
  title: string;
  regex: RegExp;
  description: string;
}

const RESOURCE_EXHAUSTION_RULES: ResourceExhaustionRule[] = [
  {
    id: "MANINY-RSH-001",
    severity: "medium",
    category: "code-pattern",
    title: "Unbounded or request-driven allocation passed to Array or Buffer constructor",
    regex: /\b(new Array|Buffer\.alloc|Buffer\.allocUnsafe)\s*\(\s*([^\r\n)]*\b(req\.query|req\.body|req\.params)\b|[A-Za-z_$][A-Za-z0-9_$.]*)[^\r\n)]*(?![^\r\n]*(Math\.min|MAX_|limit|clamp))/i,
    description: "Bound buffer and array allocations with explicit maximum limits and validate untrusted size parameters.",
  },
  {
    id: "MANINY-RSH-002",
    severity: "low",
    category: "code-pattern",
    title: "Recurring setInterval scheduled without visible cleanup or bound on line",
    regex: /\bsetInterval\s*\([^\r\n)]*(?![^\r\n]*(clearInterval|unref|maxRuns))/i,
    description: "Ensure recurring intervals have clear lifecycle cleanup, bounded execution, or unref() semantics to prevent resource leaks.",
  },
];

function makeRshFindingId(ruleId: string, relFile: string, line: number): string {
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

export async function runResourceExhaustionAuditor(policy: ManinyPolicy): Promise<Finding[]> {
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
      for (const rule of RESOURCE_EXHAUSTION_RULES) {
        if (rule.regex.test(lineText)) {
          const lineNum = i + 1;
          findings.push({
            id: makeRshFindingId(rule.id, relFile, lineNum),
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
