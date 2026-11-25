import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy, Severity } from "../core/types.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
const SCAN_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

interface CspHeadersRule {
  id: string;
  severity: Severity;
  category: Finding["category"];
  title: string;
  regex: RegExp;
  description: string;
}

const CSP_HEADERS_RULES: CspHeadersRule[] = [
  {
    id: "MANINY-CSP-001",
    severity: "medium",
    category: "http-hardening",
    title: "Unsafe inline or eval directive in Content-Security-Policy configuration",
    regex: new RegExp("Content-Security-Policy[^\r\n]*('unsafe-\\x69nline'|'unsafe-\\x65val')", "i"),
    description: "Avoid 'unsafe-inline' and 'unsafe-eval' in Content-Security-Policy; use nonces or strict hashes instead.",
  },
  {
    id: "MANINY-CSP-002",
    severity: "high",
    category: "http-hardening",
    title: "TLS certificate validation disabled via rejectUnauthorized false or NODE_TLS_REJECT_UNAUTHORIZED",
    regex: new RegExp("(reject\\x55nauthorized\\s*:\\s*false|NODE_TLS_\\x52EJECT_UNAUTHORIZED\\s*=\\s*['\"\x22]?0['\"\x22]?)"),
    description: "Do not disable TLS certificate verification; enforce valid certificate chains in all environments.",
  },
];

function makeCspFindingId(ruleId: string, relFile: string, line: number): string {
  const hash = crypto
    .createHash("sha256")
    .update(`${ruleId}:${relFile}:${line}`)
    .digest("hex")
    .slice(0, 10);
  return `F-${hash}`;
}

async function collectFiles(dir: string, root: string): Promise<string[]> {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const results: string[] = [];

  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) {
        results.push(...(await collectFiles(path.join(dir, entry.name), root)));
      }
    } else if (entry.isFile() && SCAN_EXTS.has(path.extname(entry.name).toLowerCase())) {
      const rel = path.relative(root, path.join(dir, entry.name));
      if (rel) results.push(rel);
    }
  }
  return results;
}

function isCspHdrRuleLine(lineText: string): boolean {
  return /^\s*(title|description|regex)\s*:/.test(lineText) || lineText.includes("new RegExp(");
}

export async function runCspHeadersAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await collectFiles(policy.workspaceRoot, policy.workspaceRoot);

  for (const relFile of files) {
    const safePath = resolveSafeWorkspacePath(policy.workspaceRoot, relFile);
    if (!safePath) continue;

    let content: string;
    try {
      content = await fs.readFile(safePath, "utf8");
    } catch {
      continue;
    }

    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const lineText = lines[i] ?? "";
      const trimmed = lineText.trim();
      if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("*")) {
        continue;
      }

      for (const rule of CSP_HEADERS_RULES) {
        if (!isCspHdrRuleLine(lineText) && rule.regex.test(lineText)) {
          const lineNum = i + 1;
          findings.push({
            id: makeCspFindingId(rule.id, relFile, lineNum),
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
