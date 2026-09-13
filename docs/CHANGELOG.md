# Changelog

## Unreleased (console rebuild + GCP path)

### Frontend — minimalist rebuild (`frontend/src`)
- Replaced the 6-page SOC console with 2 views: narrative landing (`Prune.`,
  problem → solution → stages on scroll) and a focused simulation console.
- Simulation: role/scenario pickers, FLOW + LIVE LOG twin boxes with timed
  event playback, conditional Security Kernel console with a real command
  interpreter (`help/status/invariants/diff/allow/deny/escalate/ack`),
  verdicts gated behind kernel entry, scenario explainer cards, shared
  dotted-galaxy backdrop. No new dependencies; CSS-only motion.
- Evidence per change: REMOVED/KEPT chips expand to recorded justifications.
- Take-home artifacts: `policy.json`, `audit-bundle.json`, `policy.tf`
  downloads wired to live endpoints on every completed run.
- Removed: header nav, onboarding modals/tours, dashboard/learn/audit/
  capabilities pages (left unrouted on disk), marketing-style landing sections.

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
