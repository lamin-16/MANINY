import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy, Severity } from "../core/types.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
const SCAN_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

interface XssDomRule {
  id: string;
  severity: Severity;
  category: Finding["category"];
  title: string;
  regex: RegExp;
  description: string;
}

const XSS_DOM_RULES: XssDomRule[] = [
  {
    id: "MANINY-XSS-001",
    severity: "high",
    category: "code-pattern",
    title: "Dynamic or interpolated markup passed to DOM sink or document.write",
    regex: new RegExp("\\b((" + ["inner", "HTML"].join("") + "|" + ["outer", "HTML"].join("") + ")\\s*=|(" + ["insertAdjacent", "HTML"].join("") + "|" + ["document", ".write"].join("") + ")\\s*\\()\\s*[^\r\n]*(\\$\\{|\\x60|\\+)"),
    description: "Avoid assigning interpolated or unescaped strings to HTML sinks; sanitize HTML or render structured DOM/JSX nodes.",
  },
  {
    id: "MANINY-XSS-002",
    severity: "medium",
    category: "code-pattern",
    title: "dangerouslySetInnerHTML with dynamic expression or template interpolation",
    regex: new RegExp("\\b" + ["dangerously", "SetInnerHTML"].join("") + "\\s*=\\s*\\{\\s*\\{\\s*__html\\s*:\\s*[^\r\n}]*(\\$\\{|\\x60|\\+)"),
    description: "Ensure any HTML passed to dangerouslySetInnerHTML is strictly sanitized with a vetted sanitizer before rendering.",
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

export async function runXssDomAuditor(policy: ManinyPolicy): Promise<Finding[]> {
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
      for (const rule of XSS_DOM_RULES) {
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
