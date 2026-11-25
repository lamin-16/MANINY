<div align="center">

![MANINY Digital Dragon Banner](./assets/dragon-banner.svg)

<br />

[![TypeScript](https://img.shields.io/badge/Language-TypeScript%20Strict-FFD700?style=for-the-badge&labelColor=06080B&color=B0811B)](./tsconfig.json)
[![Pipeline](https://img.shields.io/badge/Engine-Detect%20%E2%86%92%20Verify%20%E2%86%92%20Sim%20%E2%86%92%20Fix%20%E2%86%92%20Defend-FF5A1F?style=for-the-badge&labelColor=06080B&color=2A1610)](./src/runner.ts)
[![Reports](https://img.shields.io/badge/Reports-JSON%20%7C%20SARIF%202.1.0-FFF5B8?style=for-the-badge&labelColor=06080B&color=1E2430)](./src/core/reporter.ts)
[![Safety](https://img.shields.io/badge/Guardrails-Scope%20Locked%20%7C%20Auto%20Rollback-E5E7EB?style=for-the-badge&labelColor=06080B&color=111622)](./src/stages/reviewer.ts)

</div>

---

## Architecture Overview

MANINY coordinates local static analysis, authorized HTTP checks, controlled remediation, and post-patch defensive review under a strict state machine:

- **Detection (`src/stages/detector.ts`):** Scans project files and queues allowed URLs while ignoring `node_modules`, `.git`, build outputs, and MANINY report files.
- **Verification & Simulation (`src/stages/verifier.ts`, `src/stages/exposure-checker.ts`, `src/stages/adversarial-sim.ts`):** Verifies code patterns statically and checks headers, `HSTS`, and benign reflection on hosts explicitly permitted by `--allow-host` and `--allow-probes`.
- **Remediation & Rollback (`src/stages/fixer.ts`, `src/stages/reviewer.ts`):** Enforces workspace containment and policy rules, saves backup snapshots and `unifiedDiff`, and automatically restores the backup (`rolled_back`) if review fails.

---

## Built-In Rules

| Rule ID | Category | Severity | Target | Auto-Fix |
| :--- | :--- | :--- | :--- | :--- |
| `MANINY-CODE-001` | `code-pattern` | `high` | `eval()` | Yes |
| `MANINY-CODE-002` | `code-pattern` | `high` | `new Function()` | Yes |
| `MANINY-CODE-003` | `code-pattern` | `high` | `exec()` / `execSync()` | Manual review |
| `MANINY-HTTP-001` | `http-hardening` | `medium` | `rejectUnauthorized: false` | Yes |
| `MANINY-HTTP-002` | `http-hardening` | `medium` | Non-local `http://` | Yes (`https://`) |
| `MANINY-SEC-001` | `secret-exposure` | `critical` | Hardcoded secret literals | Manual review |

---

## Build & Execution

Install dependencies and build with `npm install && npm run build`, then run the pipeline via `node ./dist/cli.js --mode pipeline --workspace ./sample-target --allow-fix --format both --report ./maniny-report`.
