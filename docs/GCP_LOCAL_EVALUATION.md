# GCP Local Evaluation — design and honesty boundaries

## Why GCP "failed" before

Three deliberate gates blocked it: `GCP_CAPABILITIES.supports_policy_simulation = False`,
`SimulatePolicyTool` returning `UNSUPPORTED_CAPABILITY` for GCP, and zero GCP seed data.
The deterministic simulator itself is provider-agnostic string matching, so the gap was
adapter coverage — not impossibility.

## The fix (Tier 1 + honest recovery)

GCP's real analog of the AWS story is **CMEK**: reading a CMEK-encrypted GCS object
silently requires `cloudkms.cryptoKeyDecrypter`, which never appears in audit logs —
the same `NOT OBSERVED ≠ PROVEN UNNEEDED` thesis on a second cloud.

- **Seed** (`data/environment.json`, additive): `BillingExportSA` service account
  (6 bindings), audit logs (decrypter unlogged), `gcp_export_flow` workflow,
  `CheckoutService → CloudStorage → CloudKMS` dependency, protected resources
  (`resourcemanager.projects.setIamPolicy`, `compute.instances.delete`).
- **Local evaluation, labeled**: new `supports_local_evaluation` capability (GCP only)
  + `evaluate_local_policy` tool running the same deterministic engine, tagged
  `local_evaluation: true` in every output. Native `simulate_*` stays blocked —
  the truthful-escalation tests still pass untouched.
- **Kernel**: skips the native-versioning/rollback capability codes for local-eval
  providers (recorded in audit details, not hidden); restoration of previously held
  permissions is not privilege expansion (other gates still apply).
- **Regression suites are provider-scoped**: AWS-specific tests fire only for
  `PaymentServiceRole`; GCP gets its own CMEK positive + dangerous-permission
  negatives (verified to fail on the broad set, pass on the pruned set).
- **Recovery without fake rollback**: GCP has no atomic rollback, so the
  `gcp_recovery` scenario re-binds the correct least-privilege set through the
  standard apply path (v1 → flawed v2 → corrected v3), verified end to end.
- **Reasoners**: `GCPDeterministicReasoner` (9-step mirror of the AWS arc),
  `GCPRecoveryReasoner` (counts only *executed* applies, so kernel stale-denies
  can't desync its plan). Wired into `POST /api/agent/run` (`gcp`, `gcp_recovery`),
  CLI (`--demo gcp|gcp-recovery`), and 10 tests in `tests/test_gcp_path.py`.

## Boundaries (what we do NOT claim)

No native GCP simulation, no version history, no atomic rollback — the UI labels
the path `GCP · local eval`, and `RealGCPProvider` (live credentials) remains a
disabled-by-default stub. The `unsupported_gcp` escalation demo is kept as proof
we don't hallucinate where capability is genuinely absent.
