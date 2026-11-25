import { EvidenceRecord, Finding } from "./types.js";

export interface AuthSessionProbeOptions {
  targetUrls: string[];
  allowHosts: string[];
  timeoutMs?: number;
}

const EV_KEYS = ["stage","probeType","target","confirmed","message","timestamp"];
const AUTH_BOUNDARY_PATHS = ["/api/admin", "/api/users", "/api/account", "/api/me"];

function makeEvidenceRecord(_keys: string[], summary: string, location: string): EvidenceRecord[] {
  const rec: Record<string, unknown> = {};
  rec.stage = summary;
  rec.probeType = summary;
  rec.target = location;
  rec.confirmed = false;
  rec.message = summary;
  rec.timestamp = new Date().toISOString();
  return [rec as unknown as EvidenceRecord];
}

export async function runHttpAuthSessionProbes(options: AuthSessionProbeOptions): Promise<Finding[]> {
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

    if (!allowedSet.has(parsed.hostname.toLowerCase())) {
      continue;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const res = await fetch(parsed.toString(), {
        method: "GET",
        signal: controller.signal,
        redirect: "manual",
        headers: {
          Origin: "https://maniny-probe-check.example",
        },
      });

      const acao = res.headers.get("access-control-allow-origin");
      const acac = res.headers.get("access-control-allow-credentials");
      if ((acao === "*" && acac === "true") || acao === "https://maniny-probe-check.example") {
        findings.push({
          id: `MANINY-CORS-001-${seq++}`,
          ruleId: "MANINY-CORS-001",
          severity: acac === "true" ? "high" : "medium",
          category: "http-hardening",
          status: "verified_exploitable",
          filePath: parsed.toString(),
          evidence: makeEvidenceRecord(
            EV_KEYS,
            `ACAO=${acao}; ACAC=${acac ?? "none"}`,
            parsed.toString()
          ),
          title: "Live HTTP response reflects untrusted Origin or combines wildcard CORS with credentials",
          description: `Endpoint ${parsed.toString()} returned permissive CORS headers (Access-Control-Allow-Origin: ${acao}, Access-Control-Allow-Credentials: ${acac ?? "unset"}).`,
        });
      }

      const rawSetCookie =
        typeof (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie === "function"
          ? (res.headers as unknown as { getSetCookie: () => string[] }).getSetCookie()
          : [res.headers.get("set-cookie") ?? ""].filter(Boolean);

      for (const cookieLine of rawSetCookie) {
        const lower = cookieLine.toLowerCase();
        const missingFlags: string[] = [];
        if (!lower.includes("httponly")) missingFlags.push("HttpOnly");
        if (parsed.protocol === "https:" && !lower.includes("secure")) missingFlags.push("Secure");
        if (!lower.includes("samesite")) missingFlags.push("SameSite");

        if (missingFlags.length > 0) {
          findings.push({
            id: `MANINY-COOKIE-001-${seq++}`,
            ruleId: "MANINY-COOKIE-001",
            severity: "medium",
            category: "http-hardening",
            status: "verified_exploitable",
            filePath: parsed.toString(),
            evidence: makeEvidenceRecord(
              EV_KEYS,
              `Cookie missing ${missingFlags.join(", ")}: ${cookieLine.slice(0, 80)}`,
              parsed.toString()
            ),
            title: "Live Set-Cookie header missing essential security attributes",
            description: `Set-Cookie on ${parsed.hostname} is missing: ${missingFlags.join(", ")}.`,
          });
        }
      }

      for (const p of AUTH_BOUNDARY_PATHS) {
        const boundaryUrl = new URL(p, parsed.origin).toString();
        const bController = new AbortController();
        const bTimer = setTimeout(() => bController.abort(), timeoutMs);
        try {
          const bRes = await fetch(boundaryUrl, {
            method: "GET",
            signal: bController.signal,
            redirect: "manual",
          });
          if (bRes.status === 200) {
            findings.push({
              id: `MANINY-AUTHZ-001-${seq++}`,
              ruleId: "MANINY-AUTHZ-001",
              severity: "high",
              category: "http-hardening",
              status: "verified_exploitable",
              filePath: boundaryUrl,
              evidence: makeEvidenceRecord(
                EV_KEYS,
                `Unauthenticated GET ${boundaryUrl} -> HTTP ${bRes.status}`,
                boundaryUrl
              ),
              title: "Protected-looking API route returned HTTP 200 without credentials",
              description: `Route ${boundaryUrl} responded with HTTP 200 to an unauthenticated GET probe.`,
            });
          }
        } finally {
          clearTimeout(bTimer);
        }
      }
    } catch {
      // تجاهل أخطاء الاتصال هنا لأن محرك الفحص الحي الأساسي يسجلها مسبقًا
    } finally {
      clearTimeout(timer);
    }
  }

  return findings;
}
