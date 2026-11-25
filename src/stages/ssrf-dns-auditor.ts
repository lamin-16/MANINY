import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy, Severity } from "../core/types.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
const SCAN_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

interface SsrfDnsRule {
  id: string;
  severity: Severity;
  category: Finding["category"];
  title: string;
  regex: RegExp;
  description: string;
}

const SSRF_DNS_RULES: SsrfDnsRule[] = [
  {
    id: "MANINY-SSR-001",
    severity: "high",
    category: "http-hardening",
    title: "Reference to cloud instance metadata endpoint in source code",
    regex: /\b(169\.254\.169\.254|metadata\.google\.internal|metadata\.goog)\b/i,
    description: "Avoid embedding cloud metadata IP addresses or internal hostnames in application code.",
  },
  {
    id: "MANINY-SSR-002",
    severity: "medium",
    category: "code-pattern",
    title: "Dynamic URL/host variable interpolated into template literal",
    regex: /\b(targetUrl|redirectUrl|callbackUrl|webhookUrl|endpointUrl)\b[^\r\n]*`[^`]*\$\{/,
    description: "Validate scheme, host allowlist, and private/loopback ranges before requesting dynamic URLs.",
  },
];

function makeSsrFindingId(ruleId: string, relFile: string, line: number): string {
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

export async function runSsrfDnsAuditor(policy: ManinyPolicy): Promise<Finding[]> {
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

      for (const rule of SSRF_DNS_RULES) {
        if (rule.regex.test(lineText)) {
          const lineNum = i + 1;
          findings.push({
            id: makeSsrFindingId(rule.id, relFile, lineNum),
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
