import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy, Severity } from "../core/types.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
const SCAN_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

interface NotificationInjectionRule {
  id: string;
  severity: Severity;
  category: Finding["category"];
  title: string;
  regex: RegExp;
  description: string;
}

const NOTIFICATION_INJECTION_RULES: NotificationInjectionRule[] = [
  {
    id: "MANINY-NTF-001",
    severity: "medium",
    category: "code-pattern",
    title: "Untrusted request input passed into mail or notification sender without visible sanitization",
    regex: /\b(sendMail|sendEmail|sendNotification|dispatchAlert)\s*\([^\r\n)]*\b(req\.query|req\.body|req\.params)\b[^\r\n)]*(?![^\r\n]*(sanitize|escape|encode|validate))/i,
    description: "Validate and sanitize user inputs before passing recipients, subjects, or content to email or notification dispatchers.",
  },
  {
    id: "MANINY-NTF-002",
    severity: "medium",
    category: "code-pattern",
    title: "Unescaped CRLF or header newline sequence in mail/notification context",
    regex: /\b(subject|header|recipient|to|from)\b[^\r\n;,)]*(\\r\\n|%0d%0a|crlf)/i,
    description: "Strip carriage-return and line-feed sequences from email headers and notification fields to prevent header injection.",
  },
];

function makeNtfFindingId(ruleId: string, relFile: string, line: number): string {
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

export async function runNotificationInjectionAuditor(policy: ManinyPolicy): Promise<Finding[]> {
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
      for (const rule of NOTIFICATION_INJECTION_RULES) {
        if (rule.regex.test(lineText)) {
          const lineNum = i + 1;
          findings.push({
            id: makeNtfFindingId(rule.id, relFile, lineNum),
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
