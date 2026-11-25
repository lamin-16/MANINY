import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy, Severity } from "../core/types.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
const SCAN_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

interface CorsOriginRule {
  id: string;
  severity: Severity;
  category: Finding["category"];
  title: string;
  regex: RegExp;
  description: string;
}

const CORS_ORIGIN_RULES: CorsOriginRule[] = [
  {
    id: "MANINY-CRS-001",
    severity: "medium",
    category: "code-pattern",
    title: "Wildcard or unrestricted CORS origin configured without visible allowlist check",
    regex: /(Access-Control-Allow-Origin['"]?\s*[:=]\s*['"]?\*['"]?|origin\s*[:=]\s*['"]?\*['"]?)[^\r\n;,}]*(?![^\r\n]*(allowlist|allowedOrigins|isAllowedOrigin))/i,
    description: "Restrict cross-origin access to explicit trusted origins rather than wildcard origins on authenticated or sensitive endpoints.",
  },
  {
    id: "MANINY-CRS-002",
    severity: "medium",
    category: "code-pattern",
    title: "Incoming request origin used without visible allowlist or membership check on line",
    regex: /\b(req\.headers\.origin|req\.header\(['"]origin['"]\))\b[^\r\n;,)]*(?![^\r\n]*(allowlist|allowedOrigins|includes|validateOrigin))/i,
    description: "Validate incoming Origin headers against an explicit allowlist before reflecting or granting cross-origin access.",
  },
];

function makeCrsFindingId(ruleId: string, relFile: string, line: number): string {
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

export async function runCorsOriginAuditor(policy: ManinyPolicy): Promise<Finding[]> {
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
      for (const rule of CORS_ORIGIN_RULES) {
        if (rule.regex.test(lineText)) {
          const lineNum = i + 1;
          findings.push({
            id: makeCrsFindingId(rule.id, relFile, lineNum),
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
