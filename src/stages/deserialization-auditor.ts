import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy, Severity } from "../core/types.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
const SCAN_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

interface DeserializationRule {
  id: string;
  severity: Severity;
  category: Finding["category"];
  title: string;
  regex: RegExp;
  description: string;
}

const DESERIALIZATION_RULES: DeserializationRule[] = [
  {
    id: "MANINY-DSR-001",
    severity: "high",
    category: "code-pattern",
    title: "Untrusted request input or template expression passed directly to deserializer",
    regex: /\b(JSON\.parse|deserialize|unserialize)\s*\(\s*([^\r\n)]*\b(req\.body|req\.query|req\.params)\b|`[^`]*\$\{[^}]+\}[^`]*`)/i,
    description: "Validate raw payloads and enforce strict schemas before parsing or deserializing untrusted input data.",
  },
  {
    id: "MANINY-DSR-002",
    severity: "medium",
    category: "code-pattern",
    title: "YAML loader invoked without visible safe schema restriction on line",
    regex: /\b(yaml\.load|loadYaml)\s*\([^\r\n)]*(?![^\r\n]*(FAILSAFE_SCHEMA|CORE_SCHEMA|JSON_SCHEMA|safeLoad))/i,
    description: "Restrict YAML parsing to safe schemas (such as FAILSAFE_SCHEMA or CORE_SCHEMA) to prevent unsafe tag execution.",
  },
];

function makeDsrFindingId(ruleId: string, relFile: string, line: number): string {
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

export async function runDeserializationAuditor(policy: ManinyPolicy): Promise<Finding[]> {
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
      for (const rule of DESERIALIZATION_RULES) {
        if (rule.regex.test(lineText)) {
          const lineNum = i + 1;
          findings.push({
            id: makeDsrFindingId(rule.id, relFile, lineNum),
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
