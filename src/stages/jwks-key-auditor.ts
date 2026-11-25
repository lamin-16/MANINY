import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const JWKS_KEY_RULES: LineAuditRule[] = [
  {
    id: "MANINY-JWK-001",
    severity: "high",
    category: "code-pattern",
    title: "JWKS or signing key handler lacks visible rotation authorization, key allowlist, or signature check",
    regex: /\b(rotateSigningKey|verifyJwksKey|publishJwksSet)\s*\([^\r\n)]*(\b(keyId|jwksUrl|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(authorizeKeyRotation|verifyKeySignature|allowedKeyIds|minKeyBits))/i,
    description: "Restrict signing key rotation and validate key identifiers and JWKS sources against an explicit allowlist.",
  },
  {
    id: "MANINY-JWK-002",
    severity: "medium",
    category: "code-pattern",
    title: "Key verification or key strength guard explicitly bypassed",
    regex: /\b(skipKeyVerification|allowWeakSigningKey)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep cryptographic key verification and minimum key strength checks enabled.",
  },
];

export async function runJwksKeyAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, JWKS_KEY_RULES);
}
