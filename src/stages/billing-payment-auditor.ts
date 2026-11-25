import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const BILLING_PAYMENT_RULES: LineAuditRule[] = [
  {
    id: "MANINY-BIL-001",
    severity: "high",
    category: "code-pattern",
    title: "Payment or checkout handler trusts client amount or discount without visible server verification",
    regex: /\b(processPayment|createInvoice|handleSubscriptionCheckout)\s*\([^\r\n)]*(\b(req\.body|amount|discountCode|price)\b|\$\{)[^\r\n)]*(?![^\r\n]*(verifyPaymentIntent|calculateServerTotal|validateSubscription|verifyWebhookSignature))/i,
    description: "Compute totals and discounts server-side and verify payment intents or billing signatures before finalizing charges.",
  },
  {
    id: "MANINY-BIL-002",
    severity: "medium",
    category: "code-pattern",
    title: "Billing verification or amount integrity check explicitly bypassed",
    regex: /\b(skipPaymentVerification|allowClientAmount)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep payment verification and server-side price calculation enabled.",
  },
];

export async function runBillingPaymentAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, BILLING_PAYMENT_RULES);
}
