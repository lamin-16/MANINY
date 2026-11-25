import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy, Severity } from "../core/types.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
const SCAN_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

interface XssSinkRule {
  id: string;
  severity: Severity;
  category: Finding["category"];
  title: string;
  regex: RegExp;
  description: string;
}

const XSS_SINK_RULES: XssSinkRule[] = [
  {
    id: "MANINY-XSS-001",
    severity: "high",
    category: "code-pattern",
    title: "Dynamic or interpolated markup passed to DOM HTML sink",
    regex: /\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write)\b[^\r\n;]*(`[^`]*\$\{[^}]+\}[^`]*`|=\s*[A-Za-z_$][A-Za-z0-9_$.]*)/,
    description: "Avoid assigning interpolated or untrusted strings to innerHTML, outerHTML, insertAdjacentHTML, or document.write; use safe text rendering or vetted sanitizers.",
  },
  {
    id: "MANINY-XSS-002",
    severity: "medium",
    category: "code-pattern",
    title: "dangerouslySetInnerHTML used with dynamic or template expression",
    regex: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(`[^`]*\$\{[^}]+\}[^`]*`|[A-Za-z_$][A-Za-z0-9_$.]*)/,
    description: "Sanitize HTML content with a trusted sanitizer before passing to dangerouslySetInnerHTML or render structured JSX elements instead.",
  },
];

function makeXssFindingId(ruleId: string, relFile: string, line: number): string {
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

export async function runXssSinkAuditor(policy: ManinyPolicy): Promise<Finding[]> {
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
      for (const rule of XSS_SINK_RULES) {
        if (rule.regex.test(lineText)) {
          const lineNum = i + 1;
          findings.push({
            id: makeXssFindingId(rule.id, relFile, lineNum),
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
