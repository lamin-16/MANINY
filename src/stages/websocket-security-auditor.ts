import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy, Severity } from "../core/types.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
const SCAN_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);

interface WebsocketSecurityRule {
  id: string;
  severity: Severity;
  category: Finding["category"];
  title: string;
  regex: RegExp;
  description: string;
}

const WEBSOCKET_SECURITY_RULES: WebsocketSecurityRule[] = [
  {
    id: "MANINY-WSC-001",
    severity: "high",
    category: "code-pattern",
    title: "WebSocket connection handler lacks visible origin or authentication guard on line",
    regex: /\b(wss|io|socket)\.on\s*\(\s*['"]connection['"][^\r\n)]*(?![^\r\n]*(origin|token|authenticate|verifyClient|session))/i,
    description: "Verify client authentication tokens and check allowed origins on WebSocket handshake/connection handlers.",
  },
  {
    id: "MANINY-WSC-002",
    severity: "medium",
    category: "code-pattern",
    title: "Incoming WebSocket message or data passed directly to parser or DOM sink without visible check",
    regex: /\b(message|data)\b[^\r\n;,)]*\b(JSON\.parse|innerHTML|eval)\b[^\r\n;,)]*(?![^\r\n]*(schema|safeParse|sanitize|validate))/i,
    description: "Validate and sanitize incoming WebSocket frames with a strict schema before parsing or rendering them.",
  },
];

function makeWscFindingId(ruleId: string, relFile: string, line: number): string {
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

export async function runWebsocketSecurityAuditor(policy: ManinyPolicy): Promise<Finding[]> {
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
      for (const rule of WEBSOCKET_SECURITY_RULES) {
        if (rule.regex.test(lineText)) {
          const lineNum = i + 1;
          findings.push({
            id: makeWscFindingId(rule.id, relFile, lineNum),
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
