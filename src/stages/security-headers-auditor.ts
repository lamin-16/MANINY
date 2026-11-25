import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy, Severity } from "../core/types.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
const SCAN_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

interface SecurityHeaderRule {
  id: string;
  severity: Severity;
  category: Finding["category"];
  title: string;
  regex: RegExp;
  description: string;
}

const SECURITY_HEADER_RULES: SecurityHeaderRule[] = [
  {
    id: "MANINY-HDR-001",
    severity: "medium",
    category: "code-pattern",
    title: "Permissive unsafe-inline or wildcard directive in Content-Security-Policy configuration",
    regex: /Content-Security-Policy[^\r\n;]*('unsafe-inline'|'unsafe-eval'|\*)/i,
    description: "Avoid unsafe-inline, unsafe-eval, or wildcard script/style sources in Content-Security-Policy headers.",
  },
  {
    id: "MANINY-HDR-002",
    severity: "low",
    category: "code-pattern",
    title: "Frame protection or transport security header explicitly disabled",
    regex: /\b(contentSecurityPolicy|frameguard|hsts)\s*[:=]\s*false\b/i,
    description: "Keep frame protection, CSP, and HSTS enabled on web responses.",
  },
];

function makeHdrFindingId(ruleId: string, relFile: string, line: number): string {
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

function isSecHdrRuleLine(lineText: string): boolean {
  return /^\s*(title|description|regex)\s*:/.test(lineText) || lineText.includes("new RegExp(");
}

export async function runSecurityHeadersAuditor(policy: ManinyPolicy): Promise<Finding[]> {
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
      for (const rule of SECURITY_HEADER_RULES) {
        if (!isSecHdrRuleLine(lineText) && rule.regex.test(lineText)) {
          const lineNum = i + 1;
          findings.push({
            id: makeHdrFindingId(rule.id, relFile, lineNum),
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
