import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy, Severity } from "../core/types.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";
import { isRuleDefinitionLine } from "./stage-utils.js";

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
const SCAN_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".sh", ".yml", ".yaml", ".dockerfile"]);

interface ContainerSecurityRule {
  id: string;
  severity: Severity;
  category: Finding["category"];
  title: string;
  regex: RegExp;
  description: string;
}

const CONTAINER_SECURITY_RULES: ContainerSecurityRule[] = [
  {
    id: "MANINY-CNT-001",
    severity: "high",
    category: "code-pattern",
    title: "Privileged container mode enabled in container runtime or compose configuration",
    regex: /(--privileged\b|privileged\s*:\s*true)/i,
    description: "Avoid running containers in privileged mode; drop unnecessary Linux capabilities and apply least-privilege security options instead.",
  },
  {
    id: "MANINY-CNT-002",
    severity: "medium",
    category: "code-pattern",
    title: "Container explicitly configured to run as root user",
    regex: /(\bUSER\s+root\b|\buser\s*:\s*['"]?(root|0:0)['"]?)/i,
    description: "Run container processes under a non-root user ID to limit blast radius if a container breakout occurs.",
  },
];

function makeCntFindingId(ruleId: string, relFile: string, line: number): string {
  const hash = crypto.createHash("sha256").update(`${ruleId}:${relFile}:${line}`).digest("hex").slice(0, 10);
  return `F-${hash}`;
}

async function collectFiles(dir: string, root: string): Promise<string[]> {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const results: string[] = [];
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) results.push(...(await collectFiles(path.join(dir, entry.name), root)));
    } else if (entry.isFile()) {
      const lowerName = entry.name.toLowerCase();
      const ext = path.extname(lowerName);
      if (SCAN_EXTS.has(ext) || lowerName.startsWith("dockerfile")) {
        const rel = path.relative(root, path.join(dir, entry.name));
        if (rel) results.push(rel);
      }
    }
  }
  return results;
}

export async function runContainerSecurityAuditor(policy: ManinyPolicy): Promise<Finding[]> {
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
      if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("#")) continue;
      for (const rule of CONTAINER_SECURITY_RULES) {
        if (!isRuleDefinitionLine(lineText) && rule.regex.test(lineText)) {
          const lineNum = i + 1;
          findings.push({
            id: makeCntFindingId(rule.id, relFile, lineNum),
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
