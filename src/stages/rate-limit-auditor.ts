import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy, Severity } from "../core/types.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
const SCAN_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

interface RateLimitRule {
  id: string;
  severity: Severity;
  category: Finding["category"];
  title: string;
  regex: RegExp;
  description: string;
}

const RATE_LIMIT_RULES: RateLimitRule[] = [
  {
    id: "MANINY-RLM-001",
    severity: "medium",
    category: "code-pattern",
    title: "Authentication or credential POST route lacks visible rate-limiting middleware on line",
    regex: /\b(router|app)\.post\s*\(\s*['"][^'"]*(login|signin|register|reset-password|forgot-password|otp|verify-code)[^'"]*['"][^\r\n)]*(?![^\r\n]*(rateLimit|limiter|throttle|slowDown))/i,
    description: "Apply rate limiting and brute-force protection middleware to authentication, registration, OTP, and password-reset endpoints.",
  },
  {
    id: "MANINY-RLM-002",
    severity: "low",
    category: "code-pattern",
    title: "Sub-250ms fixed timeout used inside authentication or brute-force handler",
    regex: /\b(login|signin|auth|verifyOtp|bruteForce)[^\r\n{;]*\bsetTimeout\s*\([^\r\n,)]+,\s*([0-9]{1,2}|1[0-9]{2}|2[0-4][0-9])\s*\)/i,
    description: "Avoid near-zero or sub-250ms artificial delays for auth throttling; rely on proper rate limiters, lockouts, or progressive backoff.",
  },
];

function makeRlmFindingId(ruleId: string, relFile: string, line: number): string {
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

export async function runRateLimitAuditor(policy: ManinyPolicy): Promise<Finding[]> {
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
      for (const rule of RATE_LIMIT_RULES) {
        if (rule.regex.test(lineText)) {
          const lineNum = i + 1;
          findings.push({
            id: makeRlmFindingId(rule.id, relFile, lineNum),
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
