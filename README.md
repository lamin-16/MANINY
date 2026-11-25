# MANINY — ARTEX Security CLI Platform

**MANINY** is a TypeScript/Node.js defensive security CLI engineered with an **ARTEX**-grade verification, remediation, rollback, and audit pipeline.

## Key Capabilities
- **Static & Behavioral Detection:** Scans code patterns, package dependencies (`MANINY-DEP-001`), environment/deployment configs (`MANINY-ENV-001..003`), string timers (`MANINY-BEH-001`), and token prefixes (`MANINY-SEC-003`).
- **Safe Verification & Adversarial Simulation:** Verifies static/HTTP baselines and runs safe non-destructive reflection/header probes (`--allow-host`, `--allow-probes`).
- **Guarded Remediation & Auto-Rollback:** Applies targeted fixes under `--allow-fix` with workspace path containment, backup snapshots, and automatic rollback on failure.
- **Cryptographic Execution Audit (`--integrity`):** Generates a canonical SHA-256 digest and `ARTEX-AUD-*` identifier for every run.
- **Multi-Agent Advisory (`--agents`, `--agents-status`):** Supports OpenAI, Claude, DeepSeek, Gemini, and custom OpenAI-compatible endpoints.
- **CI/CD & Telemetry Flags:** `--url-only`, `--json-compact`, `--compliance`, `--fail-on <severity>`, and `--stats`.

## Quick Commands
```bash
npm test

node ./dist/cli.js \
  --mode verify \
  --url-only \
  --url [https://example.com/](https://example.com/) \
  --allow-host example.com \
  --allow-probes \
  --compliance \
  --integrity \
  --json-compact

node ./dist/cli.js --stats --workspace .

