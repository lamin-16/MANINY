import { EvidenceRecord, Finding } from "./types.js";

export interface LiveProbeOptions {
  targetUrls: string[];
  allowHosts: string[];
  timeoutMs?: number;
}

const SENSITIVE_PROBE_PATHS = ["/.env", "/.git/HEAD", "/config.json", "/api/health"];

function makeEvidence(detail: string, filePath?: string): EvidenceRecord[] {
  return [{ detail, filePath } as unknown as EvidenceRecord];
}

export async function runSafeLiveHttpProbes(options: LiveProbeOptions): Promise<Finding[]> {
  const findings: Finding[] = [];
  const allowedSet = new Set(
    (options.allowHosts ?? []).map((h) => h.trim().toLowerCase()).filter(Boolean)
  );
  const timeoutMs = options.timeoutMs ?? 5000;
  let seq = 1;

  for (const rawUrl of options.targetUrls ?? []) {
    let parsed: URL;
    try {
      parsed = new URL(rawUrl);
    } catch {
      continue;
    }

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      continue;
    }

    const hostLower = parsed.hostname.toLowerCase();
    if (!allowedSet.has(hostLower)) {
      findings.push({
        id: `MANINY-LIVE-000-${seq++}`,
        ruleId: "MANINY-LIVE-000",
        severity: "info",
        category: "http-hardening",
        status: "needs_review",
        filePath: rawUrl,
        evidence: makeEvidence(`allowHosts=[${[...allowedSet].join(", ")}]`, rawUrl),
        title: "Target host skipped because it is not listed in allowed target hosts",
        description: `Host "${parsed.hostname}" was not explicitly permitted in allowHosts; live probe skipped safely.`,
      });
      continue;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const baseRes = await fetch(parsed.toString(), {
        method: "GET",
        signal: controller.signal,
        redirect: "manual",
      });

      const hsts = baseRes.headers.get("strict-transport-security");
      const xcto = baseRes.headers.get("x-content-type-options");
      if (!hsts || !xcto) {
        const missing = [!hsts ? "Strict-Transport-Security" : "", !xcto ? "X-Content-Type-Options" : ""].filter(Boolean);
        findings.push({
          id: `MANINY-LIVE-001-${seq++}`,
          ruleId: "MANINY-LIVE-001",
          severity: "medium",
          category: "http-hardening",
          status: "verified_exploitable",
          filePath: parsed.toString(),
          evidence: makeEvidence(`HTTP ${baseRes.status}; missing headers: ${missing.join(", ")}`, parsed.toString()),
          title: "Live HTTP response missing baseline security headers",
          description: `HTTP ${baseRes.status} from ${parsed.hostname} missing: ${missing.join(", ")}.`,
        });
      }

      for (const p of SENSITIVE_PROBE_PATHS) {
        const probeUrl = new URL(p, parsed.origin).toString();
        const pController = new AbortController();
        const pTimer = setTimeout(() => pController.abort(), timeoutMs);
        try {
          const pRes = await fetch(probeUrl, {
            method: "GET",
            signal: pController.signal,
            redirect: "manual",
          });
          if (pRes.status === 200 && p !== "/api/health") {
            findings.push({
              id: `MANINY-LIVE-002-${seq++}`,
              ruleId: "MANINY-LIVE-002",
              severity: "high",
              category: "http-hardening",
              status: "verified_exploitable",
              filePath: probeUrl,
              evidence: makeEvidence(`GET ${probeUrl} -> HTTP ${pRes.status}`, probeUrl),
              title: "Live probe observed HTTP 200 on sensitive path",
              description: `Endpoint ${probeUrl} returned HTTP 200 during non-destructive GET verification.`,
            });
          }
        } finally {
          clearTimeout(pTimer);
        }
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      findings.push({
        id: `MANINY-LIVE-003-${seq++}`,
        ruleId: "MANINY-LIVE-003",
        severity: "low",
        category: "http-hardening",
        status: "needs_review",
        filePath: parsed.toString(),
        evidence: makeEvidence(msg, parsed.toString()),
        title: "Live HTTP probe timed out or failed to connect",
        description: msg,
      });
    } finally {
      clearTimeout(timer);
    }
  }

  return findings;
}
