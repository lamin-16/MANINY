import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy, Severity } from "../core/types.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
const CODE_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

interface BehavioralRule {
  id: string;
  severity: Severity;
  category: Finding["category"];
  title: string;
  regex: RegExp;
  description: string;
}

const BEHAVIORAL_RULES: BehavioralRule[] = [
  {
    id: "MANINY-BEH-001",
    severity: "medium",
    category: "code-pattern",
    title: "String-based timer execution (setTimeout/setInterval)",
    regex: /\b(setTimeout|setInterval)\s*\(\s*(['"`])/,
    description: "Passing a string literal to setTimeout or setInterval acts like implicit eval().",
  },
  {
    id: "MANINY-SEC-003",
    severity: "high",
    category: "secret-exposure",
    title: "Potential hardcoded provider token prefix",
    regex: /\b(ghp_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z\-_]{25,}|sk-[A-Za-z0-9\-_]{20,})\b/,
    description: "Detected token-like literal prefix; move secrets to environment variables or secret managers.",
  },
];

function makeBehFindingId(ruleId: string, relFile: string, line: number): string {
  const hash = crypto
    .createHash("sha256")
    .update(`${ruleId}:${relFile}:${line}`)
    .digest("hex")
    .slice(0, 10);
  return `F-${hash}`;
}

async function collectCodeFiles(dir: string, root: string): Promise<string[]> {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const results: string[] = [];

  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) {
        results.push(...(await collectCodeFiles(path.join(dir, entry.name), root)));
      }
    } else if (entry.isFile() && CODE_EXTS.has(path.extname(entry.name).toLowerCase())) {
      const rel = path.relative(root, path.join(dir, entry.name));
      if (rel) results.push(rel);
    }
  }
  return results;
}

function isBehavioralRuleDefLine(lineText: string): boolean {
  return /^\s*(title|description|regex)\s*:/.test(lineText) || lineText.includes("new RegExp(");
}

export async function runBehavioralAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await collectCodeFiles(policy.workspaceRoot, policy.workspaceRoot);

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

      for (const rule of BEHAVIORAL_RULES) {
        if (!isBehavioralRuleDefLine(lineText) && (rule.regex.test(lineText))) {
          const lineNum = i + 1;
          findings.push({
            id: makeBehFindingId(rule.id, relFile, lineNum),
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
