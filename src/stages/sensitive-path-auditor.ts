import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy, Severity } from "../core/types.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
const SCAN_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

interface SensitivePathRule {
  id: string;
  severity: Severity;
  category: Finding["category"];
  title: string;
  regex: RegExp;
  description: string;
}

const SENSITIVE_PATH_RULES: SensitivePathRule[] = [
  {
    id: "MANINY-PTH-001",
    severity: "medium",
    category: "code-pattern",
    title: "Reference to sensitive credential or environment path in code",
      regex: /['"`][^\r\n`]*(\.env(\.(?!example\b|sample\b|template\b)[a-zA-Z0-9_-]+)?|id_rsa|\.htpasswd|\.git\/config)['"`]/,
    description: "Avoid embedding references to sensitive secret or credential files in application code.",
  },
  {
    id: "MANINY-PTH-002",
    severity: "low",
    category: "code-pattern",
    title: "Reference to backup or database dump path in code",
    regex: /['"`][^'"`\r\n]*(\.bak\b|\.old\b|dump\.sql\b)['"`]/i,
    description: "Ensure backup or database dump paths are not exposed or accessed from application routes.",
  },
];

function makePthFindingId(ruleId: string, relFile: string, line: number): string {
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

export async function runSensitivePathAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await collectFiles(policy.workspaceRoot, policy.workspaceRoot);

  for (const relFile of files) {
    if (/(^|\/)(smoke-test|\.test\.|\.spec\.)/i.test(relFile)) continue;
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

      for (const rule of SENSITIVE_PATH_RULES) {
        if (!/(blockedPathSubstrings|TRAVERSAL_PATHS|SENSITIVE_PROBE_PATHS|startsWith\(["']\.env)/.test(lineText) && rule.regex.test(lineText)) {
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
