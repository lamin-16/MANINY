<div align="center">

![MANINY Digital Dragon Banner](./assets/dragon-banner.svg)

<br />

[![TypeScript](https://img.shields.io/badge/TYPESCRIPT-STRICT-FFD000?style=for-the-badge&labelColor=05070B&color=B45309)](./tsconfig.json)
[![Verify](https://img.shields.io/badge/VERIFY-SAFE%20PROBES-00F5D4?style=for-the-badge&labelColor=05070B&color=0E7490)](./src/stages/verifier.ts)
[![Simulate](https://img.shields.io/badge/SIMULATE-ADVERSARIAL-FF8C42?style=for-the-badge&labelColor=05070B&color=9A3412)](./src/stages/adversarial-sim.ts)
[![Fix](https://img.shields.io/badge/FIX-CONTROLLED%20PATCH-D8B4FE?style=for-the-badge&labelColor=05070B&color=6B21A8)](./src/stages/fixer.ts)
[![Rollback](https://img.shields.io/badge/DEFEND-AUTO%20ROLLBACK-4ADE80?style=for-the-badge&labelColor=05070B&color=166534)](./src/stages/reviewer.ts)

</div>

---

## What Is MANINY?

**MANINY** is an autonomous multi-stage security verification, controlled remediation, and defensive rollback engine written in strict TypeScript. Instead of blindly modifying source files or running unsafe probes, MANINY enforces a deterministic state machine with workspace sandboxing, backup snapshots, SHA-256 audit trails, and optional multi-agent AI advisory.

---

## How The Pipeline Works (Step-by-Step)

1. **Stage 1 — Detection (`src/stages/detector.ts`):**
   - Recursively scans files inside `--workspace` while automatically skipping `.git`, `node_modules`, `dist`, and `maniny-report*` artifacts.
   - Matches line-level rules and collects target URLs into the inspection queue.
2. **Stage 2 — Safe Verification & Exposure (`src/stages/verifier.ts`, `src/stages/exposure-checker.ts`):**
   - Confirms static code vulnerabilities (`verified_exploitable`).
   - When `--allow-probes` and `--allow-host <host>` are explicitly provided, inspects baseline HTTP security headers (`Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Strict-Transport-Security`, and wildcard `CORS`).
3. **Stage 3 — Adversarial Simulation (`src/stages/adversarial-sim.ts`):**
   - Executes strictly benign reflection probes on authorized `--allow-host` targets and checks whether HTML angle brackets are properly encoded before flagging `MANINY-ADV-REFLECT-001`.
4. **Stage 4 — Controlled Remediation (`src/stages/fixer.ts`):**
   - Runs **only** when `--allow-fix` is passed.
   - Blocks sensitive paths (`.env`, `.git`, `node_modules`, `id_rsa`, `credentials`, and report files), saves `backupContent` + `unifiedDiff`, and applies targeted patches.
5. **Stage 5 — Defender Review & Auto-Rollback (`src/stages/reviewer.ts`):**
   - Re-verifies every patched file to confirm the vulnerable pattern is gone and the file remains intact.
   - Marks successful patches as `verified_fixed` or automatically restores `backupContent` (`rolled_back`) if verification fails.
6. **Stage 6 — Integrity Audit & Multi-Agent Advisory (`src/core/audit-trail.ts`, `src/core/agents.ts`):**
   - Generates a canonical `SHA-256` execution digest (`--integrity`).
   - Optionally queries configured AI agents (`OpenAI`, `Claude`, `DeepSeek`, `Gemini`, or custom OpenAI-compatible endpoints) for defensive remediation guidance (`--agents`).

---

## Rules & Rollback Matrix

<div align="center">

![MANINY Rule and State Matrix](./assets/rules-matrix.svg)

</div>

| Rule ID | Category | Severity | Target Pattern | Auto-Fix |
| :--- | :--- | :--- | :--- | :--- |
| `MANINY-CODE-001` | `code-pattern` | `high` | `eval(...)` | Yes |
| `MANINY-CODE-002` | `code-pattern` | `high` | `new Function(...)` | Yes |
| `MANINY-CODE-003` | `code-pattern` | `high` | `exec()` / `execSync()` | Manual review |
| `MANINY-CODE-004` | `code-pattern` | `medium` | `innerHTML =` / `outerHTML =` | Yes (`textContent =`) |
| `MANINY-CODE-005` | `code-pattern` | `high` | `document.write(...)` | Manual review |
| `MANINY-CODE-006` | `code-pattern` | `high` | `dangerouslySetInnerHTML` | Manual review |
| `MANINY-HTTP-001` | `http-hardening` | `medium` | `rejectUnauthorized: false` | Yes (`true`) |
| `MANINY-HTTP-002` | `http-hardening` | `medium` | Non-local `http://` URLs | Yes (`https://`) |
| `MANINY-SEC-001` | `secret-exposure` | `critical` | Hardcoded API keys / tokens | Manual review |
| `MANINY-SEC-002` | `secret-exposure` | `medium` | `Math.random()` in token/secret context | Manual review |

---

## Installation & Build

```bash
git clone https://github.com/lamin-16/MANINY.git
cd MANINY
npm install
npm run build

