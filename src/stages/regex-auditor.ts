import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy, Severity } from "../core/types.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
const SCAN_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

interface RegexRule {
  id: string;
  severity: Severity;
  category: Finding["category"];
  title: string;
  regex: RegExp;
  description: string;
}

const REGEX_RULES: RegexRule[] = [
  {
    id: "MANINY-RGX-001",
    severity: "medium",
    category: "code-pattern",
    title: "Potential nested quantifier pattern in regular expression literal",
    regex: /\/(\([^)]*[+*][^)]*\))[+*]\//,
    description: "Nested quantifiers in regular expressions can cause catastrophic backtracking on crafted inputs.",
  },
  {
    id: "MANINY-RGX-002",
    severity: "high",
    category: "code-pattern",
    title: "Legacy 'with' statement or direct eval() call",
    regex: /\b(with\s*\(|eval\s*\()/,
    description: "Avoid 'with' statements and direct eval() calls due to unpredictable scoping and code injection risks.",
  },
];

function makeRgxFindingId(ruleId: string, relFile: string, line: number): string {
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

export async function runRegexAuditor(policy: ManinyPolicy): Promise<Finding[]> {
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

      for (const rule of REGEX_RULES) {
        if (rule.regex.test(lineText)) {
          const lineNum = i + 1;
          findings.push({
            id: makeRgxFindingId(rule.id, relFile, lineNum),
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
