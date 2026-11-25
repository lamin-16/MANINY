import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy, Severity } from "../core/types.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
const SCAN_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

interface TimingSidechannelRule {
  id: string;
  severity: Severity;
  category: Finding["category"];
  title: string;
  regex: RegExp;
  description: string;
}

const TIMING_SIDECHANNEL_RULES: TimingSidechannelRule[] = [
  {
    id: "MANINY-TSC-001",
    severity: "medium",
    category: "code-pattern",
    title: "Direct equality comparison on secret/token/signature without visible timingSafeEqual",
    regex: /\b(token|secret|signature|hmac|apiKey|passwordHash)\b[^\r\n;)]*(===|!==|==|!=)[^\r\n;)]*(?![^\r\n]*timingSafeEqual)/i,
    description: "Use constant-time comparison such as crypto.timingSafeEqual when comparing authentication tokens, signatures, or secrets.",
  },
  {
    id: "MANINY-TSC-002",
    severity: "low",
    category: "code-pattern",
    title: "High-resolution or wall-clock timing measurement used inside auth/token check",
    regex: /\b(auth|token|verify|hmac|signature)[^\r\n{;]*\b(Date\.now|performance\.now|hrtime)\s*\(/i,
    description: "Avoid exposing timing differences during credential or token verification that could leak state via timing side channels.",
  },
];

function makeTscFindingId(ruleId: string, relFile: string, line: number): string {
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

export async function runTimingSidechannelAuditor(policy: ManinyPolicy): Promise<Finding[]> {
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
      for (const rule of TIMING_SIDECHANNEL_RULES) {
        if (rule.regex.test(lineText)) {
          const lineNum = i + 1;
          findings.push({
            id: makeTscFindingId(rule.id, relFile, lineNum),
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
