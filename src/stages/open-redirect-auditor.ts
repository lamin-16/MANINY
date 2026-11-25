import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy, Severity } from "../core/types.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
const SCAN_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

interface OpenRedirectRule {
  id: string;
  severity: Severity;
  category: Finding["category"];
  title: string;
  regex: RegExp;
  description: string;
}

const OPEN_REDIRECT_RULES: OpenRedirectRule[] = [
  {
    id: "MANINY-RDR-001",
    severity: "high",
    category: "code-pattern",
    title: "Request input or interpolated template passed to redirect call without visible path/host check",
    regex: /\b(res\.redirect|redirect|router\.push|router\.replace)\s*\(\s*([^\r\n)]*\b(req\.query|req\.body|req\.params)\b|`[^`]*\$\{[^}]+\}[^`]*`)[^\r\n)]*(?![^\r\n]*(startsWith|allowedHosts|safeUrl|allowlist))/i,
    description: "Validate redirect targets to ensure they resolve to safe relative paths or explicitly allowlisted origins before redirecting.",
  },
  {
    id: "MANINY-RDR-002",
    severity: "medium",
    category: "code-pattern",
    title: "Dynamic or interpolated value assigned or passed to browser location navigation",
    regex: /\b(window\.location|location\.href|location\.assign|location\.replace)\b[^\r\n;,)]*(=|\()\s*(`[^`]*\$\{[^}]+\}[^`]*`|[A-Za-z_$][A-Za-z0-9_$.]*)/i,
    description: "Avoid assigning unvalidated variables or template literals directly to location navigation sinks.",
  },
];

function makeRdrFindingId(ruleId: string, relFile: string, line: number): string {
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

export async function runOpenRedirectAuditor(policy: ManinyPolicy): Promise<Finding[]> {
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
      for (const rule of OPEN_REDIRECT_RULES) {
        if (rule.regex.test(lineText)) {
          const lineNum = i + 1;
          findings.push({
            id: makeRdrFindingId(rule.id, relFile, lineNum),
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
