import { Finding, FindingStatus } from "./types.js";

const ALLOWED_TRANSITIONS: Record<FindingStatus, FindingStatus[]> = {
  detected: ["verified_exploitable", "needs_review", "patched"],
  verified_exploitable: ["patched", "needs_review", "verified_fixed"],
  needs_review: ["verified_exploitable", "patched", "rolled_back"],
  patched: ["verified_fixed", "rolled_back", "needs_review"],
  verified_fixed: ["needs_review"],
  rolled_back: ["needs_review", "patched"],
};

export function canTransition(current: FindingStatus, next: FindingStatus): boolean {
  return ALLOWED_TRANSITIONS[current].includes(next);
}

export function transitionStatus(
  finding: Finding,
  nextStatus: FindingStatus,
  reason: string
): Finding {
  if (!canTransition(finding.status, nextStatus)) {
    throw new Error(
      `Invalid state transition for ${finding.id}: ${finding.status} -> ${nextStatus} (${reason})`
    );
  }

  return {
    ...finding,
    status: nextStatus,
  };
}
