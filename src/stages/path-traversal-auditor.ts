import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy, Severity } from "../core/types.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
const SCAN_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

interface PathTraversalRule {
  id: string;
  severity: Severity;
  category: Finding["category"];
  title: string;
  regex: RegExp;
  description: string;
}

const PATH_TRAVERSAL_RULES: PathTraversalRule[] = [
  {
    id: "MANINY-PTH-001",
    severity: "high",
    category: "code-pattern",
    title: "Interpolated or dynamic path passed to file system operation without safe resolver",
    regex: /\b(readFile|writeFile|appendFile|unlink|createReadStream|createWriteStream)\s*\(\s*(`[^`]*\$\{[^}]+\}[^`]*`|[A-Za-z_$][A-Za-z0-9_$.]*)[^\r\n)]*(?![^\r\n]*(resolveSafeWorkspacePath|basename|startsWith))/i,
    description: "Resolve and confine file paths within an allowed base directory before performing file read, write, or deletion operations.",
  },
  {
    id: "MANINY-PTH-002",
    severity: "medium",
    category: "code-pattern",
    title: "Request input passed directly into path.join or path.resolve",
    regex: /\bpath\.(join|resolve)\s*\([^\r\n)]*\b(req\.params|req\.query|req\.body)\b/i,
    description: "Validate and canonicalize request path segments to block '../' traversal sequences before joining paths.",
  },
];

function makePthFindingId(ruleId: string, relFile: string, line: number): string {
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

export async function runPathTraversalAuditor(policy: ManinyPolicy): Promise<Finding[]> {
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
      for (const rule of PATH_TRAVERSAL_RULES) {
        if (rule.regex.test(lineText)) {
          const lineNum = i + 1;
          findings.push({
            id: makePthFindingId(rule.id, relFile, lineNum),
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
