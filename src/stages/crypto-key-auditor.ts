import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const CRYPTO_KEY_RULES: LineAuditRule[] = [
  {
    id: "MANINY-CRY-001",
    severity: "high",
    category: "code-pattern",
    title: "Weak or legacy cipher algorithm used in cryptographic operation",
    regex: /\b(createCipheriv|createDecipheriv|createHash)\s*\(\s*['"`](des|rc4|md5|sha1)['"`]/i,
    description: "Use modern authenticated encryption and strong hash functions such as AES-GCM and SHA-256 or SHA-512.",
  },
  {
    id: "MANINY-CRY-002",
    severity: "high",
    category: "code-pattern",
    title: "Cryptographic key or signing secret derived from static literal on line",
    regex: /\b(signToken|deriveKey|encryptPayload)\s*\([^\r\n)]*(['"`][A-Za-z0-9_\-@!#$%^&*]{6,}['"`])/,
    description: "Load signing keys and encryption secrets from secure runtime key management rather than literals.",
  },
];

export async function runCryptoKeyAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, CRYPTO_KEY_RULES);
}
