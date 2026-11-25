import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const OAUTH_SSO_RULES: LineAuditRule[] = [
  {
    id: "MANINY-OAU-001",
    severity: "high",
    category: "code-pattern",
    title: "OAuth or SSO callback or token exchange lacks visible state, PKCE, or redirect allowlist check",
    regex: /\b(handleOAuthCallback|exchangeOAuthCode|verifySsoAssertion)\s*\([^\r\n)]*(\b(req\.query|redirectUri|oauthCode)\b|\$\{)[^\r\n)]*(?![^\r\n]*(verifyState|codeVerifier|allowedRedirectUris|validateAudience))/i,
    description: "Verify OAuth state/nonce parameters, enforce PKCE and token audience checks, and validate redirect URIs against an allowlist.",
  },
  {
    id: "MANINY-OAU-002",
    severity: "medium",
    category: "code-pattern",
    title: "OAuth state verification or SSO signature check explicitly bypassed",
    regex: /\b(skipOAuthState|disableSsoSignatureCheck)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep OAuth CSRF state checks and SSO assertion signature verification enabled.",
  },
];

export async function runOauthSsoAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, OAUTH_SSO_RULES);
}
