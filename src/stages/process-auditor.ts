import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy, Severity } from "../core/types.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
const CODE_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

interface ProcessRule {
  id: string;
  severity: Severity;
  category: Finding["category"];
  title: string;
  regex: RegExp;
  description: string;
}

const PROCESS_RULES: ProcessRule[] = [
  {
    id: "MANINY-PRC-001",
    severity: "high",
    category: "code-pattern",
    title: "Shell execution via exec/execSync with dynamic or template input",
    regex: /\b(exec|execSync)\s*\(\s*`[^`]*\$\{/,
    description: "Interpolating variables into shell commands passed to exec/execSync risks command injection.",
  },
  {
    id: "MANINY-PRC-002",
    severity: "low",
    category: "code-pattern",
    title: "Allocation using Buffer.allocUnsafe",
    regex: /\bBuffer\.allocUnsafe\s*\(/,
    description: "Buffer.allocUnsafe may contain uninitialized memory bytes; prefer Buffer.alloc when zeroed memory is desired.",
  },
];

function makePrcFindingId(ruleId: string, relFile: string, line: number): string {
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
    } else if (entry.isFile() && CODE_EXTS.has(path.extname(entry.name).toLowerCase())) {
      const rel = path.relative(root, path.join(dir, entry.name));
      if (rel) results.push(rel);
    }
  }
  return results;
}

export async function runProcessAuditor(policy: ManinyPolicy): Promise<Finding[]> {
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

      for (const rule of PROCESS_RULES) {
        if (rule.regex.test(lineText)) {
          const lineNum = i + 1;
          findings.push({
            id: makePrcFindingId(rule.id, relFile, lineNum),
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
