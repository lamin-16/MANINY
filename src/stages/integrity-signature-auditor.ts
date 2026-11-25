import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const INTEGRITY_SIGNATURE_RULES: LineAuditRule[] = [
  {
    id: "MANINY-INT-001",
    severity: "high",
    category: "code-pattern",
    title: "Signature or payload integrity verification explicitly bypassed or skipped",
    regex: /\b(skipSignatureCheck|bypassChecksum|ignoreIntegrity)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Enforce cryptographic signature and integrity verification on incoming payloads, webhooks, and artifacts.",
  },
  {
    id: "MANINY-INT-002",
    severity: "medium",
    category: "code-pattern",
    title: "Signature or digest verification lacks timing-safe or verified check reference",
    regex: /\b(verifyWebhookSignature|verifyDigest)\s*\([^\r\n)]*\b(req\.headers|signature)\b[^\r\n)]*(?![^\r\n]*(timingSafeEqual|verifyHmac|isValidSignature))/i,
    description: "Use constant-time comparison and verified HMAC or signature checks when validating external payloads.",
  },
];

export async function runIntegritySignatureAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, INTEGRITY_SIGNATURE_RULES);
}
