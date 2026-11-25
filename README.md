<div align="center">

<img src="./assets/dragon-banner.svg" alt="MANINY Dragon Banner" width="100%" />

<br />

[![Runtime](https://img.shields.io/badge/Runtime-TypeScript%20%7C%20Node.js-D4AF37?style=for-the-badge&labelColor=090B0E&color=D4AF37)](./tsconfig.json)
[![Pipeline](https://img.shields.io/badge/Stages-Detect%20%7C%20Verify%20%7C%20Fix%20%7C%20Review-F5F7FA?style=for-the-badge&labelColor=090B0E&color=273043)](./src/runner.ts)
[![Reports](https://img.shields.io/badge/Output-JSON%20%7C%20SARIF%202.1.0-FFD700?style=for-the-badge&labelColor=090B0E&color=8C6512)](./src/core/reporter.ts)
[![Guardrails](https://img.shields.io/badge/Safety-Scope%20Guard%20%7C%20Auto%20Rollback-E5E7EB?style=for-the-badge&labelColor=090B0E&color=1B2230)](./src/stages/reviewer.ts)

> **Dragon Guardrail Principle:** Every automated patch is backed up first, verified after change, and automatically rolled back if incomplete or unsafe.

</div>

---

## Execution Pipeline

| Stage | Module | Role |
| :--- | :--- | :--- |
| **1. Detector** | `src/stages/detector.ts` | Scans workspace files and queues target URLs while ignoring report artifacts |
| **2. Safe Verifier** | `src/stages/verifier.ts` | Performs static verification and baseline HTTP header checks |
| **3. Exposure Checker** | `src/stages/exposure-checker.ts` | Audits `Strict-Transport-Security` (`HSTS`) on authorized targets |
| **4. Adversarial Sim** | `src/stages/adversarial-sim.ts` | Runs non-destructive reflection probes when `--allow-probes` and `--allow-host` match |
| **5. Fixer** | `src/stages/fixer.ts` | Enforces policy and workspace path rules, saves backup + `unifiedDiff`, and patches |
| **6. Defender Reviewer** | `src/stages/reviewer.ts` | Confirms `verified_fixed` or restores backup with status `rolled_back` |

---

## Rules & Policy Boundaries

- **Authorized Scope Only:** Network probes run only when `--allow-probes` is enabled and the host matches `--allow-host`.
- **Workspace Containment:** File edits stay inside `workspaceRoot` and block sensitive paths (`.env`, `.git`, `node_modules`, `id_rsa`, `credentials`).
- **Built-In Rules:** `MANINY-CODE-001` (`eval`), `MANINY-CODE-002` (`new Function`), `MANINY-CODE-003` (`exec`/`execSync`), `MANINY-HTTP-001` (`rejectUnauthorized: false`), `MANINY-HTTP-002` (non-local `http://`), and `MANINY-SEC-001` (hardcoded secrets).

---

## Build & Run

1. Install dependencies and build: `npm install && npm run build`
2. Run full pipeline with `JSON` + `SARIF` reports:
   `node ./dist/cli.js --mode pipeline --workspace ./sample-target --allow-fix --format both --report ./maniny-report`
