import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const WEBAUTHN_PASSKEY_RULES: LineAuditRule[] = [
  {
    id: "MANINY-WBA-001",
    severity: "high",
    category: "code-pattern",
    title: "WebAuthn or passkey verification lacks visible origin, counter, or user verification guard",
    regex: /\b(registerPasskeyCredential|verifyPasskeyAssertion|challengeWebAuthnOrigin)\s*\([^\r\n)]*(\b(credential|assertion|origin|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(expectedOrigin|verifySignCount|requireUserVerification|validateChallenge))/i,
    description: "Verify relying-party origin, validate cryptographic sign counts, and enforce user verification for passkey flows.",
  },
  {
    id: "MANINY-WBA-002",
    severity: "medium",
    category: "code-pattern",
    title: "WebAuthn origin or sign-count check explicitly bypassed",
    regex: /\b(skipOriginCheck|ignoreSignCount)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep WebAuthn origin validation and signature counter checks enabled.",
  },
];

export async function runWebAuthnPasskeyAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, WEBAUTHN_PASSKEY_RULES);
}
