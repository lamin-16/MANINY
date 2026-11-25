import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy, Severity } from "../core/types.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";

interface EnvPatternRule {
  id: string;
  severity: Severity;
  title: string;
  regex: RegExp;
  description: string;
}

const ENV_RULES: EnvPatternRule[] = [
  {
    id: "MANINY-ENV-001",
    severity: "high",
    title: "TLS verification disabled via NODE_TLS_REJECT_UNAUTHORIZED=0",
    regex: /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?/i,
    description: "Disables Node.js TLS certificate checks globally, exposing network traffic to MitM.",
  },
  {
    id: "MANINY-ENV-002",
    severity: "medium",
    title: "Wildcard interface binding (0.0.0.0)",
    regex: /\b0\.0\.0\.0\b/,
    description: "Binds service to all network interfaces; restrict to loopback or private interface when appropriate.",
  },
  {
    id: "MANINY-ENV-003",
    severity: "medium",
    title: "Verbose debug flag enabled in configuration",
    regex: /\b(DEBUG\s*=\s*['"]?(true|\*|1|app:\*)['"]?|APP_DEBUG\s*=\s*['"]?true['"]?)/i,
    description: "Verbose debug logging can leak internal stack traces or sensitive metadata.",
  },
];

const CANDIDATE_FILES = [
  ".env.example",
  ".env.sample",
  "docker-compose.yml",
  "docker-compose.yaml",
  "config.json",
  "config.yaml",
  "config.yml",
];

function makeEnvFindingId(ruleId: string, fileRel: string, line: number): string {
  const hash = crypto
    .createHash("sha256")
    .update(`${ruleId}:${fileRel}:${line}`)
    .digest("hex")
    .slice(0, 10);
  return `F-${hash}`;
}

export async function runEnvAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const relFile of CANDIDATE_FILES) {
    const safePath = resolveSafeWorkspacePath(policy.workspaceRoot, relFile);
    if (!safePath) {
      continue;
    }

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
      if (!trimmed || trimmed.startsWith("#")) {
        continue;
      }

      for (const rule of ENV_RULES) {
        if (rule.regex.test(lineText)) {
          const lineNum = i + 1;
          findings.push({
            id: makeEnvFindingId(rule.id, relFile, lineNum),
            ruleId: rule.id,
            title: rule.title,
            category: "http-hardening",
            severity: rule.severity,
            filePath: path.relative(policy.workspaceRoot, safePath) || relFile,
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
