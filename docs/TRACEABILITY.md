# PS10 Traceability — every requirement → code → test → demo moment

Problem statement: autonomous cloud-IAM agent that reduces excessive permissions
without breaking simulated service dependencies.

## Required agent capabilities

| # | PS requirement | Implementation | Tests | Demo moment |
|---|---|---|---|---|
| 1 | Inspect IAM assignments and access history | `get_role`, `get_access_history`, `list_permissions` (`backend/tools/iam_tools.py`); seed `data/environment.json` | `test_tools.py`, `test_contracts.py` | Flow: Observe; log lines "Observed N permissions", "Audited M log lines" |
| 2 | Identify candidate permissions for removal | `find_unused_permissions` + `SecurityAnalyzer` evidence bundles (`backend/security/analyzer.py`) | `test_tools.py`, `test_gcp_path.py::seed` | Log line "Flagged N unlogged candidates" |
| 3 | Propose a least-privilege policy | Structured `ApplyPolicyChangeArgs` via `policy_candidate_generated` (`backend/agent/controller.py`); agent can never edit raw JSON | `test_agent.py`, `test_phase2_agent.py` | Replan line naming kept vs cut sets |
| 4 | Simulate impact, inspect impact | `PolicySimulator.simulate` returns failing workflow + missing permission + broken dependency (`backend/environment/simulator.py`) | `test_simulator.py`, GCP sim-fail test | Log line "SIM FAILED — checkout needs kms:Decrypt" |
| 5 | On failure: identify dependency, revise | `get_service_dependencies` + `replan_started` (`backend/scenarios.py` reasoners) | `test_agent.py` (replans == 1), GCP closed-loop test | Dependency chain + "Replanned" log lines |
| 6 | Re-simulate until constraints pass | Second simulation gates every apply; loop guards bound retries (`backend/agent/budgets.py`, controller) | `test_phase2_agent.py`, `test_phase4_safety.py` | "Re-simulation passed" before Kernel lines |
| 7 | Verify revised policy preserves access | Independent `PolicyVerifier` + `ExtendedPolicyVerifier` + regression suites (`backend/environment/verifier.py`, `backend/security/verification.py`, `backend/security/regression.py`); proposer never self-grades | `test_verifier.py`, `test_startup_backend.py`, GCP regression scoping test | "Independent verification passed" + verdict banner |
| 8 | Final policy + evidence per change | `PolicyDiff` with `why_removed`/`why_kept` (`backend/security/diff.py`); evidence ledger; `GET /api/audit/bundle/{id}`; UI chips expand to per-change evidence + `policy.json` / `audit-bundle.json` / `policy.tf` downloads | `test_phase3_*`, `test_gcp_path.py::api`, `test_startup_backend.py` | REMOVED/KEPT chips, evidence box, download row |

## Required workflow (end-to-end proof)

AWS: `test_agent.py` + `main.py --demo aws` + picker `Least-privilege fix`
→ 7→4, `verified_success`. GCP mirror: `tests/test_gcp_path.py::test_gcp_closed_loop_verified`
+ `--demo gcp` + picker `GCP · local eval` → 6→4, `verified_success`.

## Safety properties (why autonomy is trustworthy)

| Property | Mechanism | Test |
|---|---|---|
| AI proposes, code decides | Reasoner emits decisions only; Kernel gate intercepts every mutation | `test_phase4_safety.py` |
| No privilege expansion | `NO_PRIVILEGE_EXPANSION` + restoration rule | `test_phase3_security.py`, GCP tests |
| Protected capabilities untouchable | `NO_PROTECTED_PERMISSION_MUTATION` (`safety_block` → `security_block`) | `test_api_scenario_safety_block` |
| No silent completion | `NO_COMPLETION_WITHOUT_VERIFICATION` | `test_phase4_safety.py` |
| Failed applies roll back / re-bind | AWS atomic rollback; GCP honest re-bind (`gcp_recovery`) | rollback + `test_gcp_recovery_rebinds_and_verifies` |
| Truthful multi-cloud limits | Native GCP sim stays `unsupported_capability`; local eval labeled | `test_cross_provider_scenario_gcp_safe_unsupported_escalation` |
