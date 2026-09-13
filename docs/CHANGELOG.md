# Changelog

## Unreleased (console rebuild + GCP path)

### Frontend — minimalist rebuild (`frontend/src`)
- Landing + 5-section console shell: narrative landing (`Prune.`), then a
  fixed left rail (Run · Evidence · Policy · Exports · Audit, icon-only on
  mobile) sharing one run object, with past-run preview + back-to-live.
- Simulation: role/scenario pickers, FLOW + LIVE LOG twin boxes with timed
  event playback, conditional Security Kernel console with a real command
  interpreter (`help/status/invariants/diff/allow/deny/escalate/ack`),
  verdicts gated behind kernel entry, scenario explainer cards, shared
  dotted-galaxy backdrop. No new dependencies; CSS-only motion.
- Evidence per change: REMOVED/KEPT chips expand to recorded justifications.
- Take-home artifacts: `policy.json`, `audit-bundle.json`, `policy.tf`
  downloads wired to live endpoints on every completed run.
- Evidence/Policy/Exports views read the shared run (or preview); Audit lists
  run history lazily and previews read-only.
- Autonomy tiers: verdicts carry Standard/Sensitive badges with the triggering
  rule; verdicts auto-release on playback end while the kernel console stays a
  labeled what-if sandbox (never gating). See `PRODUCT_OVERVIEW.md` §7.
- Removed: header nav, onboarding modals/tours, dashboard/learn/capabilities
  pages (left unrouted on disk; AuditPage rewritten for the rail),
  marketing-style landing sections.

### Backend — GCP local evaluation
- New GCP seed (`BillingExportSA`, CMEK coupling, protected resources).
- `supports_local_evaluation` capability + `evaluate_local_policy` tool;
  native simulation stays honestly unsupported (existing tests untouched).
- Controller recognizes the local-eval tool in all simulation branches;
  diffs render provider-aware (GCP etag-style block).
- Kernel: local-eval handling for versioning/rollback codes; restoration of
  previously held permissions is not expansion (other gates unchanged).
- Regression suites scoped per provider (AWS tests can't fire on GCP and
  vice versa); GCP CMEK positive + dangerous-permission negatives added.
- New scenarios `gcp` (closed loop, verified) and `gcp_recovery` (honest
  re-bind recovery, v1 → flawed v2 → corrected v3), wired to API + CLI.
- 10 new tests (`tests/test_gcp_path.py`); full suite 131 passing.

### Docs
- Added `PRODUCT_OVERVIEW.md`, `RUNBOOK.md`, `FRONTEND.md`,
  `GCP_LOCAL_EVALUATION.md`, and this changelog.

## Prior state

See `TEAM_BRIEF.md` (pitch brief), `ARCHITECTURE.md` (system design),
`PHASE1_CONTRACT.md` (original contracts), `CONTRIBUTING.md` (workflow).
