import { SecurityRuleDefinition } from "./types.js";

const RULE_MAP = new Map<string, SecurityRuleDefinition>();

export function registerRule(rule: SecurityRuleDefinition): void {
  RULE_MAP.set(rule.ruleId, rule);
}

export function registerRules(rules: SecurityRuleDefinition[]): void {
  for (const rule of rules) {
    registerRule(rule);
  }
}

export function getRule(ruleId: string): SecurityRuleDefinition | undefined {
  return RULE_MAP.get(ruleId);
}

export function listRules(): SecurityRuleDefinition[] {
  return Array.from(RULE_MAP.values());
}

registerRules([
  {
    ruleId: "MANINY-CODE-001",
    title: "Dynamic code execution via eval()",
    category: "code-pattern",
    severity: "high",
    description: "Detected dynamic eval() call that can execute untrusted input.",
    detectLine: (line) => /\beval\s*\(/.test(line),
    verifyLine: (line) => /\beval\s*\(/.test(line),
    fixLine: (line) => {
      const nextLine = line.replace(
        /\beval\s*\(/g,
        "/* MANINY-REMOVED-EVAL */ ((_v: unknown) => _v)("
      );
      return { changed: nextLine !== line, nextLine };
    },
  },
  {
    ruleId: "MANINY-CODE-002",
    title: "Dynamic function construction via new Function()",
    category: "code-pattern",
    severity: "high",
    description: "Detected dynamic Function constructor usage.",
    detectLine: (line) => /\bnew\s+Function\s*\(/.test(line),
    verifyLine: (line) => /\bnew\s+Function\s*\(/.test(line),
    fixLine: (line) => {
      const nextLine = line.replace(
        /\bnew\s+Function\s*\(/g,
        "/* MANINY-REMOVED-NEW-FUNCTION */ ((..._args: unknown[]) => undefined)("
      );
      return { changed: nextLine !== line, nextLine };
    },
  },
  {
    ruleId: "MANINY-CODE-003",
    title: "Dynamic command execution via child_process",
    category: "code-pattern",
    severity: "high",
    description: "Detects shell command execution calls that require strict input validation.",
    detectLine: (line) => /\b(exec|execSync)\s*\(/.test(line),
    verifyLine: (line) => /\b(exec|execSync)\s*\(/.test(line),
  },
  {
    ruleId: "MANINY-HTTP-001",
    title: "TLS certificate verification disabled (rejectUnauthorized: false)",
    category: "http-hardening",
    severity: "medium",
    description: "Disabling TLS certificate validation exposes connections to MitM.",
    detectLine: (line) => /rejectUnauthorized\s*:\s*false/.test(line),
    verifyLine: (line) => /rejectUnauthorized\s*:\s*false/.test(line),
    fixLine: (line) => {
      const nextLine = line.replace(
        /rejectUnauthorized\s*:\s*false/g,
        "rejectUnauthorized: true"
      );
      return { changed: nextLine !== line, nextLine };
    },
  },
  {
    ruleId: "MANINY-HTTP-002",
    title: "Plain HTTP endpoint in non-local configuration",
    category: "http-hardening",
    severity: "medium",
    description: "Detects unencrypted http:// URLs outside localhost for transport hardening.",
    detectLine: (line) =>
      /http:\/\/(?!localhost|127\.0\.0\.1|\[::1\])[A-Za-z0-9.-]+/.test(line),
    verifyLine: (line) =>
      /http:\/\/(?!localhost|127\.0\.0\.1|\[::1\])[A-Za-z0-9.-]+/.test(line),
    fixLine: (line) => {
      const nextLine = line.replace(
        /http:\/\/(?!localhost|127\.0\.0\.1|\[::1\])/g,
        "https://"
      );
      return { changed: nextLine !== line, nextLine };
    },
  },
  {
    ruleId: "MANINY-SEC-001",
    title: "Potential hardcoded secret or API token assignment",
    category: "secret-exposure",
    severity: "critical",
    description: "Detected potential hardcoded credential or token literal.",
    detectLine: (line) =>
      /(?:api[_-]?key|secret[_-]?key|auth[_-]?token|private[_-]?key)\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']/i.test(
        line
      ),
    verifyLine: (line) =>
      /(?:api[_-]?key|secret[_-]?key|auth[_-]?token|private[_-]?key)\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']/i.test(
        line
      ),
  },
]);
